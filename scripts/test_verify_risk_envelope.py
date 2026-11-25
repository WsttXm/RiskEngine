#!/usr/bin/env python3
"""Standalone unit & golden-vector tests for scripts/verify_risk_envelope.py.

Uses pure Python standard library only (zero third-party dependencies).
Covers all 6 RFC §4.8.3 offline verification steps, strict DER parsing, root-first OID .17
extension defense, monotonic Google CRL floor parsing, CLI invocation, and targeted rejection codes.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import verify_risk_envelope as vre  # noqa: E402

# ---------------------------------------------------------------------------
# Minimal Pure-Python DER / X.509 / ECDSA P-256 Generator for Deterministic Tests
# ---------------------------------------------------------------------------

P256 = vre.CURVE_PARAMS[vre.OID_CURVE_P256]


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_tlv(tag: bytes, content: bytes) -> bytes:
    return tag + der_len(len(content)) + content


def der_seq(*items: bytes) -> bytes:
    return der_tlv(b"\x30", b"".join(items))


def der_set(*items: bytes) -> bytes:
    return der_tlv(b"\x31", b"".join(items))


def der_int(val: int) -> bytes:
    if val == 0:
        raw = b"\x00"
    elif val > 0:
        raw = val.to_bytes((val.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    else:
        nbytes = (val.bit_length() + 8) // 8
        raw = val.to_bytes(nbytes, "big", signed=True)
    return der_tlv(b"\x02", raw)


def der_enum(val: int) -> bytes:
    return der_tlv(b"\x0a", der_int(val)[2:])


def der_bool(flag: bool) -> bytes:
    return b"\x01\x01" + (b"\xff" if flag else b"\x00")


def der_octets(data: bytes) -> bytes:
    return der_tlv(b"\x04", data)


def der_bit_string(data: bytes, unused: int = 0) -> bytes:
    return der_tlv(b"\x03", bytes([unused]) + data)


def der_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        if arc == 0:
            out.append(0)
        else:
            chunks: List[int] = []
            while arc > 0:
                chunks.append(arc & 0x7F)
                arc >>= 7
            chunks.reverse()
            for idx, c in enumerate(chunks):
                out.append(c | (0x80 if idx < len(chunks) - 1 else 0))
    return der_tlv(b"\x06", bytes(out))


def der_ctx(tag_num: int, content: bytes) -> bytes:
    if tag_num < 31:
        tag = bytes([0xA0 | tag_num])
    else:
        chunks: List[int] = []
        v = tag_num
        while v > 0:
            chunks.append(v & 0x7F)
            v >>= 7
        chunks.reverse()
        tag = bytearray([0xBF])
        for idx, c in enumerate(chunks):
            tag.append(c | (0x80 if idx < len(chunks) - 1 else 0))
        tag = bytes(tag)
    return der_tlv(tag, content)


def der_utf8(s: str) -> bytes:
    return der_tlv(b"\x0c", s.encode("utf-8"))


def der_utc_time(dt: datetime.datetime) -> bytes:
    u = dt.astimezone(datetime.timezone.utc)
    return der_tlv(b"\x17", u.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def der_dn(cn: str) -> bytes:
    atv = der_seq(der_oid("2.5.4.3"), der_utf8(cn))
    return der_seq(der_set(atv))


def p256_keygen(priv_scalar: int) -> Tuple[int, Tuple[int, int]]:
    pub_jac = vre._ec_scalar_mul(priv_scalar, (P256["gx"], P256["gy"]), P256["p"], P256["a"])
    pub_aff = vre._ec_to_affine(pub_jac, P256["p"])
    assert pub_aff is not None
    return priv_scalar, pub_aff


def p256_sign_der(priv_scalar: int, message: bytes) -> bytes:
    n = P256["n"]
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    # Deterministic RFC 6979-like nonce for repeatable tests (test-only!)
    k = (int.from_bytes(hashlib.sha256(priv_scalar.to_bytes(32, "big") + digest).digest(), "big") % (n - 1)) + 1
    pt = vre._ec_to_affine(
        vre._ec_scalar_mul(k, (P256["gx"], P256["gy"]), P256["p"], P256["a"]), P256["p"]
    )
    assert pt is not None
    r = pt[0] % n
    s = (pow(k, -1, n) * (z + r * priv_scalar)) % n
    assert r != 0 and s != 0
    return der_seq(der_int(r), der_int(s))


def p256_spki(pub_xy: Tuple[int, int]) -> bytes:
    pub_bytes = b"\x04" + pub_xy[0].to_bytes(32, "big") + pub_xy[1].to_bytes(32, "big")
    alg = der_seq(der_oid(vre.OID_EC_PUBLIC_KEY), der_oid(vre.OID_CURVE_P256))
    return der_seq(alg, der_bit_string(pub_bytes))


def build_attestation_ext_value(
    challenge: bytes,
    att_level: int = 1,
    km_level: int = 1,
    device_locked: bool = True,
    verified_boot_state: int = 0,
    pkg_name: str = "com.host.app",
    app_sig_sha256_hex: str = "aa" * 32,
    rot_in_hw: bool = True,
) -> bytes:
    rot = der_seq(
        der_octets(b"\x11" * 32),
        der_bool(device_locked),
        der_enum(verified_boot_state),
        der_octets(b"\x22" * 32),
    )
    app_id = der_seq(
        der_set(der_seq(der_octets(pkg_name.encode("utf-8")), der_int(100))),
        der_set(der_octets(bytes.fromhex(app_sig_sha256_hex))),
    )
    sw_items = [der_ctx(709, der_octets(app_id))]
    hw_items: List[bytes] = []
    if rot_in_hw:
        hw_items.append(der_ctx(704, rot))
    else:
        sw_items.append(der_ctx(704, rot))

    key_desc = der_seq(
        der_int(300),
        der_enum(att_level),
        der_int(300),
        der_enum(km_level),
        der_octets(challenge),
        der_octets(b""),
        der_seq(*sw_items),
        der_seq(*hw_items),
    )
    return key_desc


def build_x509_cert(
    serial: int,
    issuer_cn: str,
    subject_cn: str,
    subject_pub: Tuple[int, int],
    issuer_priv: int,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    is_ca: bool = False,
    path_len: Optional[int] = None,
    key_cert_sign: bool = False,
    attestation_inner: Optional[bytes] = None,
) -> bytes:
    exts: List[bytes] = []
    bc_fields = [der_bool(True)] if is_ca else []
    if is_ca and path_len is not None:
        bc_fields.append(der_int(path_len))
    exts.append(der_seq(der_oid(vre.BASIC_CONSTRAINTS_OID), der_bool(True), der_octets(der_seq(*bc_fields))))
    if key_cert_sign:
        # Bit 5 = keyCertSign -> 0x04 in byte 0, unused bits = 2
        exts.append(der_seq(der_oid(vre.KEY_USAGE_OID), der_bool(True), der_octets(der_bit_string(b"\x04", 2))))
    if attestation_inner is not None:
        exts.append(der_seq(der_oid(vre.KEY_ATTESTATION_OID), der_octets(attestation_inner)))

    sig_alg = der_seq(der_oid(vre.OID_ECDSA_SHA256))
    tbs = der_seq(
        der_ctx(0, der_int(2)),  # v3
        der_int(serial),
        sig_alg,
        der_dn(issuer_cn),
        der_seq(der_utc_time(not_before), der_utc_time(not_after)),
        der_dn(subject_cn),
        p256_spki(subject_pub),
        der_ctx(3, der_seq(*exts)),
    )
    sig = p256_sign_der(issuer_priv, tbs)
    return der_seq(tbs, sig_alg, der_bit_string(sig))


def der_to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"


class OfflineEnvelopeVerifierUnitTest(unittest.TestCase):
    FIXED_NOW = datetime.datetime(2026, 11, 24, 12, 0, 0, tzinfo=datetime.timezone.utc)
    FIXED_NOW_MS = int(FIXED_NOW.timestamp() * 1000)
    APP_PKG = "com.host.app"
    APP_SIG = "aa" * 32
    CHALLENGE = bytes(range(1, 33))

    def _build_fixture(
        self,
        *,
        mode: str = "FRESH_ATTESTATION",
        att_level: int = 1,
        km_level: int = 1,
        device_locked: bool = True,
        verified_boot_state: int = 0,
        leaf_serial: int = 1001,
        att_challenge: Optional[bytes] = None,
        payload_overrides: Optional[Dict[str, object]] = None,
        cert_expired: bool = False,
        leaf_shadow_fake_rot: bool = False,
        rot_in_hw: bool = True,
    ) -> Tuple[Dict[str, object], vre.VerificationPolicy]:
        root_priv, root_pub = p256_keygen(0x11111111111111112222222222222222)
        inter_priv, inter_pub = p256_keygen(0x33333333333333334444444444444444)
        leaf_priv, leaf_pub = p256_keygen(0x55555555555555556666666666666666)

        nb = self.FIXED_NOW - datetime.timedelta(days=30)
        na = (
            self.FIXED_NOW - datetime.timedelta(minutes=1)
            if cert_expired
            else self.FIXED_NOW + datetime.timedelta(days=365)
        )

        root_der = build_x509_cert(
            serial=1,
            issuer_cn="Test Google Root",
            subject_cn="Test Google Root",
            subject_pub=root_pub,
            issuer_priv=root_priv,
            not_before=nb,
            not_after=self.FIXED_NOW + datetime.timedelta(days=365),
            is_ca=True,
            path_len=1,
            key_cert_sign=True,
        )
        effective_att_challenge = self.CHALLENGE if att_challenge is None else att_challenge
        inter_att = (
            build_attestation_ext_value(
                challenge=effective_att_challenge,
                att_level=att_level,
                km_level=km_level,
                device_locked=False,
                verified_boot_state=2,
                pkg_name=self.APP_PKG,
                app_sig_sha256_hex=self.APP_SIG,
                rot_in_hw=rot_in_hw,
            )
            if leaf_shadow_fake_rot
            else None
        )
        inter_der = build_x509_cert(
            serial=2,
            issuer_cn="Test Google Root",
            subject_cn="Test KeyMint Intermediate",
            subject_pub=inter_pub,
            issuer_priv=root_priv,
            not_before=nb,
            not_after=self.FIXED_NOW + datetime.timedelta(days=365),
            is_ca=True,
            path_len=0,
            key_cert_sign=True,
            attestation_inner=inter_att,
        )
        leaf_att = build_attestation_ext_value(
            challenge=effective_att_challenge,
            att_level=att_level,
            km_level=km_level,
            device_locked=device_locked,
            verified_boot_state=verified_boot_state,
            pkg_name=self.APP_PKG,
            app_sig_sha256_hex=self.APP_SIG,
            rot_in_hw=rot_in_hw,
        )
        leaf_der = build_x509_cert(
            serial=leaf_serial,
            issuer_cn="Test KeyMint Intermediate",
            subject_cn="Android Keystore Key",
            subject_pub=leaf_pub,
            issuer_priv=inter_priv,
            not_before=nb,
            not_after=na,
            is_ca=False,
            attestation_inner=leaf_att,
        )

        payload: Dict[str, object] = {
            "v": 2,
            "pkg": self.APP_PKG,
            "sdk": "2.0.0-SNAPSHOT",
            "scene": "PAYMENT",
            "ts": self.FIXED_NOW_MS,
            "monoMs": 8429103,
            "challenge": vre.base64url_no_pad(self.CHALLENGE),
            "riskLevel": "SAFE",
            "score": 0,
            "action": "ALLOW",
            "confidence": 100,
            "dimensions": {
                "TAMPERING": 0,
                "PRIVILEGE": 0,
                "ENVIRONMENT": 0,
                "FRAUD_CONTEXT": 0,
            },
            "hardTriggers": [],
            "coverage": 100,
            "fpComposite": "11" * 32,
            "fpHardware": "22" * 32,
            "reportSha256": "33" * 32,
        }
        if payload_overrides:
            payload.update(payload_overrides)

        sig_bytes = p256_sign_der(leaf_priv, vre.canonical_json_bytes(payload))
        envelope: Dict[str, object] = {
            "payload": payload,
            "signatureBase64": base64.b64encode(sig_bytes).decode("ascii"),
            "certChainPem": [der_to_pem(leaf_der), der_to_pem(inter_der), der_to_pem(root_der)],
            "attestationMode": mode,
            "keySecurityLevel": "STRONGBOX" if att_level == 2 else "TRUSTED_ENVIRONMENT",
        }
        root_spki_sha = hashlib.sha256(p256_spki(root_pub)).hexdigest()
        policy = vre.VerificationPolicy(
            trusted_root_spki_sha256={root_spki_sha},
            revoked_serials=set(),
            expected_package=self.APP_PKG,
            expected_app_sig_sha256={self.APP_SIG},
        )
        return envelope, policy

    def test_valid_fresh_and_persistent_envelopes_allow(self) -> None:
        for mode in ("FRESH_ATTESTATION", "PERSISTENT_KEY"):
            env, policy = self._build_fixture(
                mode=mode,
                att_challenge=self.CHALLENGE if mode == "FRESH_ATTESTATION" else b"init-challenge-bytes",
            )
            nonce_store = vre.InMemoryNonceStore()
            res = vre.verify_signed_envelope(
                env, self.CHALLENGE, policy=policy, nonce_store=nonce_store, eval_time_utc=self.FIXED_NOW
            )
            self.assertTrue(res.ok, res.message)
            self.assertEqual(vre.DECISION_ALLOW, res.decision)
            self.assertEqual(vre.CODE_OK, res.reason_code)
            self.assertEqual(2, res.details.get("protocolVersion"))
            self.assertEqual("ALLOW", res.details.get("action"))
            self.assertEqual(100, res.details.get("confidence"))
            self.assertEqual(
                {"TAMPERING": 0, "PRIVILEGE": 0, "ENVIRONMENT": 0, "FRAUD_CONTEXT": 0},
                res.details.get("dimensions"),
            )

    def test_tampered_payload_rejected_step5(self) -> None:
        env, policy = self._build_fixture()
        env["payload"]["score"] = 45  # type: ignore[index]
        res = vre.verify_signed_envelope(env, self.CHALLENGE, policy=policy, eval_time_utc=self.FIXED_NOW)
        self.assertFalse(res.ok)
        self.assertEqual(vre.DECISION_REJECT, res.decision)
        self.assertEqual(vre.CODE_SIGNATURE_INVALID, res.reason_code)
        self.assertEqual(5, res.step_failed)

    def test_legacy_v1_and_malformed_v2_payloads_rejected_step0(self) -> None:
        env_v1, pol_v1 = self._build_fixture(payload_overrides={"v": 1})
        res_v1 = vre.verify_signed_envelope(env_v1, self.CHALLENGE, policy=pol_v1, eval_time_utc=self.FIXED_NOW)
        self.assertFalse(res_v1.ok)
        self.assertEqual(vre.DECISION_REJECT, res_v1.decision)
        self.assertEqual(vre.CODE_UNSUPPORTED_PROTOCOL_VERSION, res_v1.reason_code)
        self.assertEqual(0, res_v1.step_failed)

        env_bad_action, pol_bad_action = self._build_fixture(payload_overrides={"action": "UNKNOWN_ACTION"})
        res_bad_action = vre.verify_signed_envelope(
            env_bad_action, self.CHALLENGE, policy=pol_bad_action, eval_time_utc=self.FIXED_NOW
        )
        self.assertEqual(vre.CODE_ENVELOPE_MALFORMED, res_bad_action.reason_code)
        self.assertEqual(0, res_bad_action.step_failed)

        env_bad_dims, pol_bad_dims = self._build_fixture(
            payload_overrides={"dimensions": {"TAMPERING": 0}}
        )
        res_bad_dims = vre.verify_signed_envelope(
            env_bad_dims, self.CHALLENGE, policy=pol_bad_dims, eval_time_utc=self.FIXED_NOW
        )
        self.assertEqual(vre.CODE_ENVELOPE_MALFORMED, res_bad_dims.reason_code)
        self.assertEqual(0, res_bad_dims.step_failed)

        env_bad_score, pol_bad_score = self._build_fixture(payload_overrides={"score": 101})
        res_bad_score = vre.verify_signed_envelope(
            env_bad_score, self.CHALLENGE, policy=pol_bad_score, eval_time_utc=self.FIXED_NOW
        )
        self.assertEqual(vre.CODE_ENVELOPE_MALFORMED, res_bad_score.reason_code)
        self.assertEqual(0, res_bad_score.step_failed)

    def test_revoked_serial_rejected_step2(self) -> None:
        env, policy = self._build_fixture(leaf_serial=0xDEADBEEF1234)
        policy.revoked_serials = {"deadbeef1234"}
        res = vre.verify_signed_envelope(env, self.CHALLENGE, policy=policy, eval_time_utc=self.FIXED_NOW)
        self.assertFalse(res.ok)
        self.assertEqual(vre.CODE_CERT_SERIAL_REVOKED, res.reason_code)
        self.assertEqual(2, res.step_failed)

    def test_unlocked_root_of_trust_rejected_step3(self) -> None:
        env, policy = self._build_fixture(device_locked=False, verified_boot_state=2)
        res = vre.verify_signed_envelope(env, self.CHALLENGE, policy=policy, eval_time_utc=self.FIXED_NOW)
        self.assertFalse(res.ok)
        self.assertEqual(vre.CODE_ROOT_OF_TRUST_UNLOCKED, res.reason_code)
        self.assertEqual(3, res.step_failed)

    def test_root_first_defeats_leaf_extension_shadowing(self) -> None:
        # Intermediate carries unlocked RootOfTrust while spoofed leaf claims locked+VERIFIED
        env, policy = self._build_fixture(device_locked=True, verified_boot_state=0, leaf_shadow_fake_rot=True)
        res = vre.verify_signed_envelope(env, self.CHALLENGE, policy=policy, eval_time_utc=self.FIXED_NOW)
        self.assertFalse(res.ok)
        self.assertEqual(vre.CODE_ROOT_OF_TRUST_UNLOCKED, res.reason_code)
        self.assertEqual(3, res.step_failed)

    def test_wrong_challenge_and_replayed_nonce_rejected_step4(self) -> None:
        env, policy = self._build_fixture()
        wrong = bytes([0xAA] * 32)
        res_wrong = vre.verify_signed_envelope(env, wrong, policy=policy, eval_time_utc=self.FIXED_NOW)
        self.assertEqual(vre.CODE_CHALLENGE_MISMATCH, res_wrong.reason_code)
        self.assertEqual(4, res_wrong.step_failed)

        nonce_store = vre.InMemoryNonceStore()
        res_first = vre.verify_signed_envelope(
            env, self.CHALLENGE, policy=policy, nonce_store=nonce_store, eval_time_utc=self.FIXED_NOW
        )
        self.assertEqual(vre.DECISION_ALLOW, res_first.decision)
        res_replay = vre.verify_signed_envelope(
            env, self.CHALLENGE, policy=policy, nonce_store=nonce_store, eval_time_utc=self.FIXED_NOW
        )
        self.assertEqual(vre.CODE_NONCE_REPLAYED, res_replay.reason_code)
        self.assertEqual(4, res_replay.step_failed)

    def test_fresh_attestation_cert_challenge_mismatch_rejected_step4(self) -> None:
        env, policy = self._build_fixture(mode="FRESH_ATTESTATION", att_challenge=bytes([0x99] * 32))
        res = vre.verify_signed_envelope(env, self.CHALLENGE, policy=policy, eval_time_utc=self.FIXED_NOW)
        self.assertEqual(vre.CODE_ATTESTATION_CHALLENGE_MISMATCH, res.reason_code)
        self.assertEqual(4, res.step_failed)

    def test_software_fallback_rejected_step0(self) -> None:
        env, policy = self._build_fixture(mode="SOFTWARE_FALLBACK")
        env["keySecurityLevel"] = "SOFTWARE"
        res = vre.verify_signed_envelope(env, self.CHALLENGE, policy=policy, eval_time_utc=self.FIXED_NOW)
        self.assertEqual(vre.CODE_SOFTWARE_FALLBACK_REJECTED, res.reason_code)
        self.assertEqual(0, res.step_failed)

    def test_expired_cert_and_untrusted_root_rejected_step1(self) -> None:
        env_exp, pol_exp = self._build_fixture(cert_expired=True)
        res_exp = vre.verify_signed_envelope(env_exp, self.CHALLENGE, policy=pol_exp, eval_time_utc=self.FIXED_NOW)
        self.assertEqual(vre.CODE_CERT_VALIDITY_EXPIRED, res_exp.reason_code)
        self.assertEqual(1, res_exp.step_failed)

        env_root, pol_root = self._build_fixture()
        pol_root.trusted_root_spki_sha256 = set(vre.BUILTIN_GOOGLE_ROOT_SPKI_SHA256)
        res_root = vre.verify_signed_envelope(env_root, self.CHALLENGE, policy=pol_root, eval_time_utc=self.FIXED_NOW)
        self.assertEqual(vre.CODE_ROOT_ANCHOR_UNTRUSTED, res_root.reason_code)
        self.assertEqual(1, res_root.step_failed)

    def test_policy_step_up_and_hard_trigger_reject(self) -> None:
        # Normalized LOW (0-100 scale, score=18, ALLOW) must ALLOW under default threshold=60
        env_low, pol_low = self._build_fixture(
            payload_overrides={
                "riskLevel": "LOW",
                "score": 18,
                "action": "ALLOW",
                "dimensions": {"TAMPERING": 0, "PRIVILEGE": 18, "ENVIRONMENT": 0, "FRAUD_CONTEXT": 0},
            }
        )
        res_low = vre.verify_signed_envelope(env_low, self.CHALLENGE, policy=pol_low, eval_time_utc=self.FIXED_NOW)
        self.assertTrue(res_low.ok)
        self.assertEqual(vre.DECISION_ALLOW, res_low.decision)
        self.assertEqual(vre.CODE_OK, res_low.reason_code)

        # Normalized MEDIUM (score=42, CHALLENGE) -> STEP_UP
        env_med, pol_med = self._build_fixture(
            payload_overrides={
                "riskLevel": "MEDIUM",
                "score": 42,
                "action": "CHALLENGE",
                "dimensions": {"TAMPERING": 0, "PRIVILEGE": 42, "ENVIRONMENT": 0, "FRAUD_CONTEXT": 0},
            }
        )
        res_med = vre.verify_signed_envelope(env_med, self.CHALLENGE, policy=pol_med, eval_time_utc=self.FIXED_NOW)
        self.assertTrue(res_med.ok)
        self.assertEqual(vre.DECISION_STEP_UP, res_med.decision)
        self.assertEqual(vre.CODE_POLICY_STEP_UP, res_med.reason_code)

        # Low Assessment Confidence (< 70) / REVIEW -> STEP_UP even when score=0
        env_conf, pol_conf = self._build_fixture(
            payload_overrides={"riskLevel": "UNKNOWN", "score": 0, "action": "REVIEW", "confidence": 60}
        )
        res_conf = vre.verify_signed_envelope(env_conf, self.CHALLENGE, policy=pol_conf, eval_time_utc=self.FIXED_NOW)
        self.assertTrue(res_conf.ok)
        self.assertEqual(vre.DECISION_STEP_UP, res_conf.decision)
        self.assertEqual(vre.CODE_POLICY_STEP_UP, res_conf.reason_code)

        # Normalized HIGH (score=65 >= 60, RESTRICT) -> REJECT / POLICY_HIGH_RISK
        env_high, pol_high = self._build_fixture(
            payload_overrides={
                "riskLevel": "HIGH",
                "score": 65,
                "action": "RESTRICT",
                "dimensions": {"TAMPERING": 0, "PRIVILEGE": 65, "ENVIRONMENT": 0, "FRAUD_CONTEXT": 0},
            }
        )
        res_high = vre.verify_signed_envelope(env_high, self.CHALLENGE, policy=pol_high, eval_time_utc=self.FIXED_NOW)
        self.assertFalse(res_high.ok)
        self.assertEqual(vre.DECISION_REJECT, res_high.decision)
        self.assertEqual(vre.CODE_POLICY_HIGH_RISK, res_high.reason_code)
        self.assertEqual(6, res_high.step_failed)

        # Hard trigger (normalized floor 95, DEADLY, BLOCK) -> REJECT / POLICY_HARD_TRIGGER
        env_ht, pol_ht = self._build_fixture(
            payload_overrides={
                "riskLevel": "DEADLY",
                "score": 95,
                "action": "BLOCK",
                "dimensions": {"TAMPERING": 78, "PRIVILEGE": 0, "ENVIRONMENT": 0, "FRAUD_CONTEXT": 0},
                "hardTriggers": ["tee_grant_chain_split"],
            }
        )
        res_ht = vre.verify_signed_envelope(env_ht, self.CHALLENGE, policy=pol_ht, eval_time_utc=self.FIXED_NOW)
        self.assertFalse(res_ht.ok)
        self.assertEqual(vre.DECISION_REJECT, res_ht.decision)
        self.assertEqual(vre.CODE_POLICY_HARD_TRIGGER, res_ht.reason_code)
        self.assertEqual(6, res_ht.step_failed)

    def test_builtin_crl_floor_loads_all_revoked_serials(self) -> None:
        revoked = vre.load_builtin_revoked_serials_from_java()
        self.assertGreaterEqual(len(revoked), 1600)
        self.assertIn("10023936558530442420", revoked)

    def test_cli_invocation_roundtrip(self) -> None:
        env, policy = self._build_fixture()
        root_spki = next(iter(policy.trusted_root_spki_sha256))
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as tf:
            json.dump(env, tf)
            tf.flush()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "verify_risk_envelope.py"),
                    "--envelope",
                    tf.name,
                    "--challenge",
                    vre.base64url_no_pad(self.CHALLENGE),
                    "--expected-package",
                    self.APP_PKG,
                    "--expected-app-sig",
                    self.APP_SIG,
                    "--trusted-root-spki",
                    root_spki,
                    "--eval-epoch-ms",
                    str(self.FIXED_NOW_MS),
                    "--min-confidence",
                    "70",
                    "--reject-score-threshold",
                    "60",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, proc.returncode, proc.stderr + proc.stdout)
            parsed = json.loads(proc.stdout)
            self.assertEqual(vre.DECISION_ALLOW, parsed["decision"])
            self.assertEqual(vre.CODE_OK, parsed["reasonCode"])
            self.assertEqual(2, parsed["details"]["protocolVersion"])
            self.assertEqual("ALLOW", parsed["details"]["action"])
            self.assertEqual(100, parsed["details"]["confidence"])
            self.assertEqual(
                {"TAMPERING": 0, "PRIVILEGE": 0, "ENVIRONMENT": 0, "FRAUD_CONTEXT": 0},
                parsed["details"]["dimensions"],
            )


if __name__ == "__main__":
    unittest.main()
