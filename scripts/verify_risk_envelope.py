#!/usr/bin/env python3
"""Independent offline 6-step server verifier for RiskEngine SignedRiskEnvelope (RFC §4.8.3).

Zero third-party dependencies & zero runtime network I/O (Python 3.8+ standard library only).

Implements all 6 RFC §4.8.3 offline verification steps:
  1. Certificate chain integrity: X.509 cryptographic signatures (ECDSA P-256/P-384 & RSA),
     Issuer/Subject DN continuity, CA BasicConstraints + RFC 5280 pathLenConstraint,
     KeyUsage.keyCertSign, validity windows, and Google Hardware Attestation Root SPKI match.
  2. Revocation check: every certificate serial in the chain is checked against the monotonic
     offline revoked-keybox CRL floor + optional server CRL snapshot.
  3. Root-first OID 1.3.6.1.4.1.11129.2.1.17 hardware extension check: strict minimal DER parsing,
     hwTags overriding swTags, TEE/STRONG_BOX security level, hardware-enforced RootOfTrust
     (deviceLocked == True, verifiedBootState == VERIFIED), and attestationApplicationId
     package name & signing certificate SHA-256 verification.
  4. Challenge, freshness & replay-nonce binding: payload.challenge equality, FRESH_ATTESTATION
     certificate attestationChallenge byte equality, timestamp window, and one-time nonce store.
  5. ECDSA signature verification: SHA256withECDSA over canonical UTF-8 payload JSON bytes
     using the leaf certificate public key.
  6. Business risk policy decision (protocol v=2, 0-100 scale): ALLOW / STEP_UP / REJECT based on
     hardTriggers, riskLevel, action, normalized score, confidence, dimensions, and coverage.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
BASIC_CONSTRAINTS_OID = "2.5.29.19"
KEY_USAGE_OID = "2.5.29.15"

# Verified Google Hardware Attestation Root SPKI SHA-256 anchors
# (kept in sync with GoogleAttestationRootStore.java)
BUILTIN_GOOGLE_ROOT_SPKI_SHA256: Tuple[str, ...] = (
    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
)

# Signature & public key algorithm OIDs
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_RSA_SHA384 = "1.2.840.113549.1.1.12"
OID_RSA_SHA512 = "1.2.840.113549.1.1.13"

OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"

OID_CURVE_P256 = "1.2.840.10045.3.1.7"
OID_CURVE_P384 = "1.3.132.0.34"

# DigestInfo prefixes for PKCS#1 v1.5 RSA verification
PKCS1_DIGEST_INFO_PREFIXES: Dict[str, bytes] = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

# NIST curve parameters (short Weierstrass y^2 = x^3 + ax + b mod p)
CURVE_PARAMS: Dict[str, Dict[str, int]] = {
    OID_CURVE_P256: {
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        "coord_bytes": 32,
    },
    OID_CURVE_P384: {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        "b": 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        "gx": 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        "gy": 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        "coord_bytes": 48,
    },
}

# Protocol v=2 payload contract constants (1:1 parity with SignedRiskEnvelope / RiskScoringEngine)
PROTOCOL_VERSION = 2
VALID_RISK_ACTIONS: Tuple[str, ...] = ("ALLOW", "CHALLENGE", "RESTRICT", "BLOCK", "REVIEW")
REQUIRED_DIMENSIONS: Tuple[str, ...] = ("TAMPERING", "PRIVILEGE", "ENVIRONMENT", "FRAUD_CONTEXT")

# Standardized decisions
DECISION_ALLOW = "ALLOW"
DECISION_STEP_UP = "STEP_UP"
DECISION_REJECT = "REJECT"

# Standardized reason codes (1:1 parity with Java reference verifier)
CODE_OK = "OK"
CODE_ENVELOPE_MALFORMED = "ENVELOPE_MALFORMED"
CODE_UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
CODE_SOFTWARE_FALLBACK_REJECTED = "SOFTWARE_FALLBACK_REJECTED"
CODE_REPORT_SHA256_MISMATCH = "REPORT_SHA256_MISMATCH"
CODE_CERT_CHAIN_TOO_SHORT = "CERT_CHAIN_TOO_SHORT"
CODE_CERT_PARSE_ERROR = "CERT_PARSE_ERROR"
CODE_CERT_SIGNATURE_INVALID = "CERT_SIGNATURE_INVALID"
CODE_CERT_ISSUER_MISMATCH = "CERT_ISSUER_MISMATCH"
CODE_CERT_CA_CONSTRAINT_INVALID = "CERT_CA_CONSTRAINT_INVALID"
CODE_CERT_VALIDITY_EXPIRED = "CERT_VALIDITY_EXPIRED"
CODE_ROOT_ANCHOR_UNTRUSTED = "ROOT_ANCHOR_UNTRUSTED"
CODE_CERT_SERIAL_REVOKED = "CERT_SERIAL_REVOKED"
CODE_ATTESTATION_EXTENSION_MISSING = "ATTESTATION_EXTENSION_MISSING"
CODE_ATTESTATION_EXTENSION_INVALID = "ATTESTATION_EXTENSION_INVALID"
CODE_ATTESTATION_SECURITY_LEVEL_INVALID = "ATTESTATION_SECURITY_LEVEL_INVALID"
CODE_ROOT_OF_TRUST_MISSING = "ROOT_OF_TRUST_MISSING"
CODE_ROOT_OF_TRUST_UNLOCKED = "ROOT_OF_TRUST_UNLOCKED"
CODE_ROOT_OF_TRUST_BOOT_UNVERIFIED = "ROOT_OF_TRUST_BOOT_UNVERIFIED"
CODE_APP_ID_PACKAGE_MISMATCH = "APP_ID_PACKAGE_MISMATCH"
CODE_APP_ID_SIGNATURE_MISMATCH = "APP_ID_SIGNATURE_MISMATCH"
CODE_CHALLENGE_MISMATCH = "CHALLENGE_MISMATCH"
CODE_ATTESTATION_CHALLENGE_MISMATCH = "ATTESTATION_CHALLENGE_MISMATCH"
CODE_NONCE_REPLAYED = "NONCE_REPLAYED"
CODE_ENVELOPE_EXPIRED = "ENVELOPE_EXPIRED"
CODE_SIGNATURE_INVALID = "SIGNATURE_INVALID"
CODE_POLICY_HARD_TRIGGER = "POLICY_HARD_TRIGGER"
CODE_POLICY_HIGH_RISK = "POLICY_HIGH_RISK"
CODE_POLICY_STEP_UP = "POLICY_STEP_UP"


class DerError(ValueError):
    """Strict minimal ASN.1 DER parsing error."""


@dataclass(frozen=True)
class DerElement:
    tag_class: int  # 0=UNIVERSAL, 1=APPLICATION, 2=CONTEXT_SPECIFIC, 3=PRIVATE
    constructed: bool
    tag_number: int
    raw: bytes
    value: bytes

    def is_universal(self, tag: int) -> bool:
        return self.tag_class == 0 and self.tag_number == tag

    def is_context(self, tag: Optional[int] = None) -> bool:
        return self.tag_class == 2 and (tag is None or self.tag_number == tag)

    def children(self) -> List["DerElement"]:
        if not self.constructed:
            raise DerError("Expected constructed DER element")
        return parse_der_sequence_contents(self.value)

    def single_child(self) -> "DerElement":
        kids = self.children()
        if len(kids) != 1:
            raise DerError(f"Expected single DER child, got {len(kids)}")
        return kids[0]

    def as_int(self) -> int:
        if self.tag_class != 0 or self.tag_number not in (2, 10) or self.constructed:
            raise DerError("Expected primitive DER INTEGER/ENUMERATED")
        if not self.value:
            raise DerError("Empty DER INTEGER")
        if len(self.value) > 1:
            b0, b1 = self.value[0], self.value[1]
            if (b0 == 0x00 and (b1 & 0x80) == 0) or (b0 == 0xFF and (b1 & 0x80) != 0):
                raise DerError("Non-minimal DER INTEGER encoding")
        return int.from_bytes(self.value, "big", signed=True)

    def as_bool(self) -> bool:
        if not self.is_universal(1) or self.constructed or len(self.value) != 1:
            raise DerError("Expected primitive 1-byte DER BOOLEAN")
        if self.value[0] == 0x00:
            return False
        if self.value[0] == 0xFF:
            return True
        raise DerError(f"Non-canonical DER BOOLEAN byte: 0x{self.value[0]:02x}")

    def as_octets(self) -> bytes:
        if not self.is_universal(4) or self.constructed:
            raise DerError("Expected primitive DER OCTET STRING")
        return self.value

    def as_bit_string(self) -> Tuple[int, bytes]:
        if not self.is_universal(3) or self.constructed or not self.value:
            raise DerError("Expected primitive DER BIT STRING")
        unused = self.value[0]
        if unused > 7 or (len(self.value) == 1 and unused != 0):
            raise DerError("Invalid DER BIT STRING unused bits")
        payload = self.value[1:]
        if unused > 0 and (payload[-1] & ((1 << unused) - 1)) != 0:
            raise DerError("Non-canonical DER BIT STRING trailing bits")
        return unused, payload

    def as_oid(self) -> str:
        if not self.is_universal(6) or self.constructed or not self.value:
            raise DerError("Expected primitive DER OBJECT IDENTIFIER")
        first = self.value[0]
        arcs = [first // 40, first % 40]
        idx = 1
        while idx < len(self.value):
            if self.value[idx] == 0x80:
                raise DerError("Non-minimal DER OID subidentifier")
            val = 0
            while True:
                if idx >= len(self.value):
                    raise DerError("Truncated DER OID subidentifier")
                b = self.value[idx]
                idx += 1
                val = (val << 7) | (b & 0x7F)
                if (b & 0x80) == 0:
                    break
            arcs.append(val)
        return ".".join(str(a) for a in arcs)


def _read_der_element(data: bytes, offset: int) -> Tuple[DerElement, int]:
    n = len(data)
    if offset >= n:
        raise DerError("Unexpected end of DER input")
    start = offset
    first = data[offset]
    offset += 1
    tag_class = (first >> 6) & 0x03
    constructed = bool(first & 0x20)
    tag_number = first & 0x1F
    if tag_number == 0x1F:
        tag_number = 0
        if offset >= n or data[offset] == 0x80:
            raise DerError("Invalid or non-minimal DER high-tag-number")
        while True:
            if offset >= n:
                raise DerError("Truncated DER high-tag-number")
            b = data[offset]
            offset += 1
            tag_number = (tag_number << 7) | (b & 0x7F)
            if tag_number > 0x3FFFFFFF:
                raise DerError("DER tag number overflow")
            if (b & 0x80) == 0:
                break
        if tag_number < 31:
            raise DerError("Non-minimal DER high-tag-number (<31)")

    if offset >= n:
        raise DerError("Truncated DER length")
    len_byte = data[offset]
    offset += 1
    if len_byte == 0x80:
        raise DerError("Indefinite BER length forbidden in DER")
    if (len_byte & 0x80) == 0:
        length = len_byte
    else:
        num_octets = len_byte & 0x7F
        if num_octets == 0 or num_octets > 4 or offset + num_octets > n:
            raise DerError("Invalid DER long-form length")
        if data[offset] == 0x00:
            raise DerError("Non-minimal DER long-form length (leading zero)")
        length = 0
        for _ in range(num_octets):
            length = (length << 8) | data[offset]
            offset += 1
        if length < 128:
            raise DerError("Non-minimal DER long-form length (<128)")

    end = offset + length
    if end > n:
        raise DerError("DER element length exceeds buffer")
    elem = DerElement(
        tag_class=tag_class,
        constructed=constructed,
        tag_number=tag_number,
        raw=data[start:end],
        value=data[offset:end],
    )
    return elem, end


def parse_der_single(data: bytes) -> DerElement:
    elem, end = _read_der_element(data, 0)
    if end != len(data):
        raise DerError(f"Trailing bytes after DER element ({len(data) - end} bytes)")
    return elem


def parse_der_sequence_contents(data: bytes) -> List[DerElement]:
    out: List[DerElement] = []
    offset = 0
    n = len(data)
    while offset < n:
        elem, offset = _read_der_element(data, offset)
        out.append(elem)
    return out


# ---------------------------------------------------------------------------
# Pure-Python stdlib Elliptic Curve (P-256 / P-384) & RSA Signature Verifier
# ---------------------------------------------------------------------------


def _ec_point_double(pt: Optional[Tuple[int, int, int]], p: int, a: int) -> Optional[Tuple[int, int, int]]:
    if pt is None:
        return None
    x1, y1, z1 = pt
    if y1 == 0 or z1 == 0:
        return None
    y1_sq = (y1 * y1) % p
    s = (4 * x1 * y1_sq) % p
    z1_sq = (z1 * z1) % p
    # For a = p - 3: m = 3 * (x1 - z1^2) * (x1 + z1^2)
    m = (3 * (x1 - z1_sq) * (x1 + z1_sq)) % p if a == p - 3 else (3 * x1 * x1 + a * z1_sq * z1_sq) % p
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * y1_sq * y1_sq) % p
    z3 = (2 * y1 * z1) % p
    return (x3, y3, z3)


def _ec_point_add(
    pt1: Optional[Tuple[int, int, int]],
    pt2: Optional[Tuple[int, int, int]],
    p: int,
    a: int,
) -> Optional[Tuple[int, int, int]]:
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    x1, y1, z1 = pt1
    x2, y2, z2 = pt2
    z1_sq = (z1 * z1) % p
    z2_sq = (z2 * z2) % p
    u1 = (x1 * z2_sq) % p
    u2 = (x2 * z1_sq) % p
    s1 = (y1 * z2 * z2_sq) % p
    s2 = (y2 * z1 * z1_sq) % p
    if u1 == u2:
        if s1 != s2:
            return None
        return _ec_point_double(pt1, p, a)
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    h_sq = (h * h) % p
    h_cu = (h * h_sq) % p
    u1_h_sq = (u1 * h_sq) % p
    x3 = (r * r - h_cu - 2 * u1_h_sq) % p
    y3 = (r * (u1_h_sq - x3) - s1 * h_cu) % p
    z3 = (h * z1 * z2) % p
    return (x3, y3, z3)


def _ec_scalar_mul(k: int, affine_pt: Tuple[int, int], p: int, a: int) -> Optional[Tuple[int, int, int]]:
    if k == 0:
        return None
    result: Optional[Tuple[int, int, int]] = None
    addend: Optional[Tuple[int, int, int]] = (affine_pt[0], affine_pt[1], 1)
    while k > 0:
        if k & 1:
            result = _ec_point_add(result, addend, p, a)
        addend = _ec_point_double(addend, p, a)
        k >>= 1
    return result


def _ec_to_affine(pt: Optional[Tuple[int, int, int]], p: int) -> Optional[Tuple[int, int]]:
    if pt is None or pt[2] == 0:
        return None
    x, y, z = pt
    z_inv = pow(z, -1, p)
    z_inv2 = (z_inv * z_inv) % p
    z_inv3 = (z_inv2 * z_inv) % p
    return ((x * z_inv2) % p, (y * z_inv3) % p)


def _ec_point_on_curve(x: int, y: int, params: Dict[str, int]) -> bool:
    p = params["p"]
    if not (0 <= x < p and 0 <= y < p):
        return False
    lhs = (y * y) % p
    rhs = (pow(x, 3, p) + params["a"] * x + params["b"]) % p
    return lhs == rhs


def verify_ecdsa_der_signature(
    curve_oid: str,
    pub_xy: Tuple[int, int],
    message: bytes,
    sig_der: bytes,
    hash_name: str,
) -> bool:
    params = CURVE_PARAMS.get(curve_oid)
    if params is None:
        return False
    p = params["p"]
    a = params["a"]
    n = params["n"]
    qx, qy = pub_xy
    if not _ec_point_on_curve(qx, qy, params):
        return False
    try:
        seq = parse_der_single(sig_der)
        if not seq.is_universal(16) or not seq.constructed:
            return False
        parts = seq.children()
        if len(parts) != 2:
            return False
        r = parts[0].as_int()
        s = parts[1].as_int()
    except DerError:
        return False
    if not (1 <= r < n and 1 <= s < n):
        return False
    digest = hashlib.new(hash_name, message).digest()
    n_bits = n.bit_length()
    z = int.from_bytes(digest, "big")
    if len(digest) * 8 > n_bits:
        z >>= len(digest) * 8 - n_bits
    w = pow(s, -1, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    p1 = _ec_scalar_mul(u1, (params["gx"], params["gy"]), p, a)
    p2 = _ec_scalar_mul(u2, (qx, qy), p, a)
    sum_pt = _ec_to_affine(_ec_point_add(p1, p2, p, a), p)
    if sum_pt is None:
        return False
    return (sum_pt[0] % n) == r


def verify_rsa_pkcs1_v15_signature(
    modulus_n: int,
    exponent_e: int,
    message: bytes,
    signature: bytes,
    hash_name: str,
) -> bool:
    prefix = PKCS1_DIGEST_INFO_PREFIXES.get(hash_name)
    if prefix is None or modulus_n <= 0 or exponent_e < 3:
        return False
    k = (modulus_n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s_int = int.from_bytes(signature, "big")
    if s_int >= modulus_n:
        return False
    em = pow(s_int, exponent_e, modulus_n).to_bytes(k, "big")
    t = prefix + hashlib.new(hash_name, message).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + (b"\xff" * (k - len(t) - 3)) + b"\x00" + t
    return em == expected


# ---------------------------------------------------------------------------
# X.509 Certificate Parsing & Chain Validation (Steps 1 & 2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicKeyInfo:
    algorithm: str  # "EC" or "RSA"
    spki_der: bytes
    spki_sha256: str
    curve_oid: Optional[str] = None
    ec_point: Optional[Tuple[int, int]] = None
    rsa_n: Optional[int] = None
    rsa_e: Optional[int] = None


@dataclass(frozen=True)
class ParsedX509Certificate:
    der: bytes
    tbs_der: bytes
    serial_number: int
    signature_oid: str
    signature_bytes: bytes
    issuer_der: bytes
    subject_der: bytes
    not_before: datetime.datetime
    not_after: datetime.datetime
    public_key: PublicKeyInfo
    is_ca: bool
    path_len_constraint: Optional[int]  # None if unlimited or not CA
    key_usage_present: bool
    key_cert_sign: bool
    extensions: Dict[str, bytes]  # oid -> extnValue raw DER OCTET STRING (outer wrapping)


def pem_to_der(pem: str) -> bytes:
    if not isinstance(pem, str):
        raise DerError("Certificate PEM must be string")
    lines = [
        line.strip()
        for line in pem.strip().splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    if not lines:
        raise DerError("Empty PEM certificate")
    try:
        return base64.b64decode("".join(lines), validate=True)
    except Exception as exc:
        raise DerError(f"Invalid PEM base64: {exc}") from exc


def _parse_asn1_time(elem: DerElement) -> datetime.datetime:
    text = elem.value.decode("ascii")
    if elem.is_universal(23):  # UTCTime YYMMDDHHMMSSZ
        if not text.endswith("Z") or len(text) != 13:
            raise DerError(f"Unsupported UTCTime: {text}")
        yy = int(text[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        return datetime.datetime(
            year,
            int(text[2:4]),
            int(text[4:6]),
            int(text[6:8]),
            int(text[8:10]),
            int(text[10:12]),
            tzinfo=datetime.timezone.utc,
        )
    if elem.is_universal(24):  # GeneralizedTime YYYYMMDDHHMMSSZ
        if not text.endswith("Z") or len(text) != 15:
            raise DerError(f"Unsupported GeneralizedTime: {text}")
        return datetime.datetime(
            int(text[0:4]),
            int(text[4:6]),
            int(text[6:8]),
            int(text[8:10]),
            int(text[10:12]),
            int(text[12:14]),
            tzinfo=datetime.timezone.utc,
        )
    raise DerError("Invalid X.509 Time tag")


def _parse_spki(spki_elem: DerElement) -> PublicKeyInfo:
    if not spki_elem.is_universal(16) or not spki_elem.constructed:
        raise DerError("SPKI is not SEQUENCE")
    parts = spki_elem.children()
    if len(parts) != 2:
        raise DerError("SPKI must have 2 fields")
    alg_parts = parts[0].children()
    if not alg_parts:
        raise DerError("Empty SPKI AlgorithmIdentifier")
    alg_oid = alg_parts[0].as_oid()
    unused, pub_bits = parts[1].as_bit_string()
    if unused != 0:
        raise DerError("Non-zero unused bits in public key BIT STRING")
    spki_sha256 = hashlib.sha256(spki_elem.raw).hexdigest()

    if alg_oid == OID_EC_PUBLIC_KEY:
        if len(alg_parts) < 2:
            raise DerError("Missing EC curve parameter OID")
        curve_oid = alg_parts[1].as_oid()
        params = CURVE_PARAMS.get(curve_oid)
        if params is None:
            raise DerError(f"Unsupported EC curve OID: {curve_oid}")
        coord_len = params["coord_bytes"]
        if len(pub_bits) != 1 + 2 * coord_len or pub_bits[0] != 0x04:
            raise DerError("Expected uncompressed EC public key point")
        x = int.from_bytes(pub_bits[1 : 1 + coord_len], "big")
        y = int.from_bytes(pub_bits[1 + coord_len :], "big")
        return PublicKeyInfo(
            algorithm="EC",
            spki_der=spki_elem.raw,
            spki_sha256=spki_sha256,
            curve_oid=curve_oid,
            ec_point=(x, y),
        )

    if alg_oid == OID_RSA_ENCRYPTION:
        rsa_seq = parse_der_single(pub_bits)
        rsa_parts = rsa_seq.children()
        if len(rsa_parts) != 2:
            raise DerError("Invalid RSAPublicKey structure")
        return PublicKeyInfo(
            algorithm="RSA",
            spki_der=spki_elem.raw,
            spki_sha256=spki_sha256,
            rsa_n=rsa_parts[0].as_int(),
            rsa_e=rsa_parts[1].as_int(),
        )

    raise DerError(f"Unsupported public key algorithm OID: {alg_oid}")


def parse_x509_der(der: bytes) -> ParsedX509Certificate:
    cert_seq = parse_der_single(der)
    if not cert_seq.is_universal(16) or not cert_seq.constructed:
        raise DerError("Certificate is not SEQUENCE")
    cert_parts = cert_seq.children()
    if len(cert_parts) != 3:
        raise DerError("Certificate must contain tbsCertificate, signatureAlgorithm, signatureValue")
    tbs_elem, sig_alg_elem, sig_val_elem = cert_parts
    sig_alg_parts = sig_alg_elem.children()
    if not sig_alg_parts:
        raise DerError("Empty signatureAlgorithm")
    sig_oid = sig_alg_parts[0].as_oid()
    unused, sig_bytes = sig_val_elem.as_bit_string()
    if unused != 0:
        raise DerError("Non-zero unused bits in signatureValue")

    tbs_parts = tbs_elem.children()
    idx = 0
    if tbs_parts and tbs_parts[0].is_context(0):
        idx = 1  # optional v1/v2/v3 version
    if len(tbs_parts) < idx + 6:
        raise DerError("Truncated TBSCertificate")

    serial_number = tbs_parts[idx].as_int()
    # tbs_parts[idx + 1] is inner signature AlgorithmIdentifier
    issuer_elem = tbs_parts[idx + 2]
    validity_parts = tbs_parts[idx + 3].children()
    if len(validity_parts) != 2:
        raise DerError("Invalid Validity SEQUENCE")
    not_before = _parse_asn1_time(validity_parts[0])
    not_after = _parse_asn1_time(validity_parts[1])
    subject_elem = tbs_parts[idx + 4]
    pub_key = _parse_spki(tbs_parts[idx + 5])

    extensions: Dict[str, bytes] = {}
    is_ca = False
    path_len_constraint: Optional[int] = None
    key_usage_present = False
    key_cert_sign = False

    for extra in tbs_parts[idx + 6 :]:
        if extra.is_context(3):
            ext_seq = extra.single_child()
            for ext_item in ext_seq.children():
                ext_fields = ext_item.children()
                if len(ext_fields) not in (2, 3):
                    raise DerError("Invalid X.509 Extension structure")
                oid = ext_fields[0].as_oid()
                extn_val_elem = ext_fields[-1]
                # Store the raw DER OCTET STRING element (same semantics as Java getExtensionValue)
                extensions[oid] = extn_val_elem.raw
                inner_octets = extn_val_elem.as_octets()
                if oid == BASIC_CONSTRAINTS_OID:
                    bc_seq = parse_der_single(inner_octets)
                    bc_fields = bc_seq.children()
                    if bc_fields and bc_fields[0].is_universal(1):
                        is_ca = bc_fields[0].as_bool()
                        if len(bc_fields) >= 2 and bc_fields[1].is_universal(2):
                            path_len_constraint = bc_fields[1].as_int()
                    elif bc_fields and bc_fields[0].is_universal(2):
                        path_len_constraint = bc_fields[0].as_int()
                elif oid == KEY_USAGE_OID:
                    key_usage_present = True
                    ku_elem = parse_der_single(inner_octets)
                    _, ku_bytes = ku_elem.as_bit_string()
                    # Bit 5 (0-indexed from MSB of byte 0) is keyCertSign -> mask 0x04
                    key_cert_sign = bool(ku_bytes) and bool(ku_bytes[0] & 0x04)

    return ParsedX509Certificate(
        der=der,
        tbs_der=tbs_elem.raw,
        serial_number=serial_number,
        signature_oid=sig_oid,
        signature_bytes=sig_bytes,
        issuer_der=issuer_elem.raw,
        subject_der=subject_elem.raw,
        not_before=not_before,
        not_after=not_after,
        public_key=pub_key,
        is_ca=is_ca,
        path_len_constraint=path_len_constraint,
        key_usage_present=key_usage_present,
        key_cert_sign=key_cert_sign,
        extensions=extensions,
    )


def verify_x509_signature(child: ParsedX509Certificate, issuer: ParsedX509Certificate) -> bool:
    pub = issuer.public_key
    oid = child.signature_oid
    if pub.algorithm == "EC" and pub.curve_oid and pub.ec_point:
        hash_map = {
            OID_ECDSA_SHA256: "sha256",
            OID_ECDSA_SHA384: "sha384",
            OID_ECDSA_SHA512: "sha512",
        }
        hash_name = hash_map.get(oid)
        if not hash_name:
            return False
        return verify_ecdsa_der_signature(
            pub.curve_oid, pub.ec_point, child.tbs_der, child.signature_bytes, hash_name
        )
    if pub.algorithm == "RSA" and pub.rsa_n is not None and pub.rsa_e is not None:
        hash_map = {
            OID_RSA_SHA256: "sha256",
            OID_RSA_SHA384: "sha384",
            OID_RSA_SHA512: "sha512",
        }
        hash_name = hash_map.get(oid)
        if not hash_name:
            return False
        return verify_rsa_pkcs1_v15_signature(
            pub.rsa_n, pub.rsa_e, child.tbs_der, child.signature_bytes, hash_name
        )
    return False


# ---------------------------------------------------------------------------
# Root-First OID .17 Attestation Extension Parser (Step 3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedAttestation:
    attestation_version: int
    attestation_security_level: int  # 0=SOFTWARE, 1=TEE, 2=STRONG_BOX
    keymaster_version: int
    keymaster_security_level: int
    attestation_challenge: bytes
    root_of_trust_present: bool
    root_of_trust_hw_enforced: bool
    device_locked: Optional[bool]
    verified_boot_state: Optional[int]  # 0=VERIFIED, 1=SELF_SIGNED, 2=UNVERIFIED, 3=FAILED
    verified_boot_hash_hex: Optional[str]
    app_packages: Tuple[str, ...]
    app_signature_digests: Tuple[str, ...]
    trusted_cert_index: int
    extension_count: int


def _parse_auth_list(elem: DerElement) -> Dict[int, DerElement]:
    if not elem.is_universal(16) or not elem.constructed:
        raise DerError("AuthorizationList is not SEQUENCE")
    tags: Dict[int, DerElement] = {}
    for item in elem.children():
        if not item.is_context() or not item.constructed:
            raise DerError("AuthorizationList entry must be constructed context-specific tag")
        if item.tag_number in tags:
            raise DerError(f"Duplicate AuthorizationList tag: {item.tag_number}")
        tags[item.tag_number] = item.single_child()
    return tags


def parse_attestation_root_first(chain: Sequence[ParsedX509Certificate]) -> Optional[ParsedAttestation]:
    trusted_idx = -1
    ext_count = 0
    for i in range(len(chain) - 1, -1, -1):
        if KEY_ATTESTATION_OID in chain[i].extensions:
            ext_count += 1
            if trusted_idx < 0:
                trusted_idx = i
    if trusted_idx < 0:
        return None

    outer_ext = parse_der_single(chain[trusted_idx].extensions[KEY_ATTESTATION_OID])
    inner = outer_ext.as_octets()
    seq = parse_der_single(inner)
    if not seq.is_universal(16) or not seq.constructed:
        raise DerError("KeyDescription is not SEQUENCE")
    fields = seq.children()
    if len(fields) < 8:
        raise DerError(f"KeyDescription has fewer than 8 fields: {len(fields)}")

    att_ver = fields[0].as_int()
    att_sec = fields[1].as_int()
    km_ver = fields[2].as_int()
    km_sec = fields[3].as_int()
    att_challenge = fields[4].as_octets()
    sw_tags = _parse_auth_list(fields[6])
    hw_tags = _parse_auth_list(fields[7])

    merged = dict(sw_tags)
    merged.update(hw_tags)

    rot_present = False
    rot_hw = False
    device_locked: Optional[bool] = None
    verified_boot_state: Optional[int] = None
    verified_boot_hash_hex: Optional[str] = None
    if 704 in merged:
        rot_present = True
        rot_hw = 704 in hw_tags
        rot_elem = merged[704]
        if not rot_elem.is_universal(16) or not rot_elem.constructed:
            raise DerError("RootOfTrust must be SEQUENCE")
        rot_fields = rot_elem.children()
        if len(rot_fields) < 3:
            raise DerError("RootOfTrust must have >= 3 fields")
        _ = rot_fields[0].as_octets()
        device_locked = rot_fields[1].as_bool()
        verified_boot_state = rot_fields[2].as_int()
        if len(rot_fields) >= 4:
            verified_boot_hash_hex = rot_fields[3].as_octets().hex()

    packages: List[str] = []
    sig_digests: List[str] = []
    if 709 in merged:
        app_id_raw = merged[709].as_octets()
        app_id_seq = parse_der_single(app_id_raw)
        if not app_id_seq.is_universal(16) or not app_id_seq.constructed:
            raise DerError("AttestationApplicationId must be SEQUENCE")
        parts = app_id_seq.children()
        if len(parts) < 2 or not parts[0].is_universal(17) or not parts[1].is_universal(17):
            raise DerError("AttestationApplicationId must have 2 SET fields")
        for pkg_info in parts[0].children():
            if not pkg_info.is_universal(16):
                raise DerError("AttestationPackageInfo must be SEQUENCE")
            pf = pkg_info.children()
            if pf:
                packages.append(pf[0].as_octets().decode("utf-8"))
        for sig_elem in parts[1].children():
            sig_digests.append(sig_elem.as_octets().hex())

    return ParsedAttestation(
        attestation_version=att_ver,
        attestation_security_level=att_sec,
        keymaster_version=km_ver,
        keymaster_security_level=km_sec,
        attestation_challenge=att_challenge,
        root_of_trust_present=rot_present,
        root_of_trust_hw_enforced=rot_hw,
        device_locked=device_locked,
        verified_boot_state=verified_boot_state,
        verified_boot_hash_hex=verified_boot_hash_hex,
        app_packages=tuple(packages),
        app_signature_digests=tuple(sig_digests),
        trusted_cert_index=trusted_idx,
        extension_count=ext_count,
    )


# ---------------------------------------------------------------------------
# CRL Normalization, Canonical JSON & Nonce Replay Store
# ---------------------------------------------------------------------------


def normalize_serial_token(token: str) -> Optional[str]:
    cleaned = token.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("0") or "0"
    return cleaned if cleaned else None


def serial_candidates(serial_int: int) -> List[str]:
    candidates: List[str] = []
    if serial_int >= 0:
        candidates.append(str(serial_int))
        candidates.append(format(serial_int, "x"))
    else:
        bit_len = (serial_int.bit_length() + 8) & ~7
        unsigned = serial_int & ((1 << bit_len) - 1)
        candidates.append(str(unsigned))
        candidates.append(format(unsigned, "x"))
    out: List[str] = []
    for c in candidates:
        norm = normalize_serial_token(c)
        if norm:
            out.append(norm)
    return out


def load_builtin_revoked_serials_from_java(java_path: Optional[pathlib.Path] = None) -> Set[str]:
    """Loads the monotonic offline CRL floor directly from GoogleAttestationRootStore.java if present."""
    if java_path is None:
        java_path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "riskengine-sdk"
            / "src"
            / "main"
            / "java"
            / "com"
            / "wsttxm"
            / "riskenginesdk"
            / "attestation"
            / "GoogleAttestationRootStore.java"
        )
    if not java_path.is_file():
        return set()
    content = java_path.read_text(encoding="utf-8")
    m = re.search(
        r"BUILTIN_REVOKED_SERIAL_CHUNKS\s*=\s*\{(.*?)\};",
        content,
        flags=re.DOTALL,
    )
    if not m:
        return set()
    revoked: Set[str] = set()
    for chunk in re.findall(r'"([^"]+)"', m.group(1)):
        for raw_token in chunk.split(","):
            norm = normalize_serial_token(raw_token)
            if norm:
                revoked.add(norm)
    return revoked


def load_revoked_serials_from_status_json(status_json: Dict[str, Any]) -> Set[str]:
    entries = status_json.get("entries", status_json)
    out: Set[str] = set()
    if isinstance(entries, dict):
        for serial_key in entries.keys():
            if isinstance(serial_key, str):
                norm = normalize_serial_token(serial_key)
                if norm:
                    out.add(norm)
    return out


def canonical_json_bytes(obj: Any) -> bytes:
    """UTF-8 recursively key-sorted JSON matching CanonicalJsonWriter.java bit-for-bit."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def base64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class InMemoryNonceStore:
    """Reference one-time nonce store (replace with Redis SETNX EX in production)."""

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def consume_if_fresh(self, nonce: str) -> bool:
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        return True


# ---------------------------------------------------------------------------
# 6-Step Offline Verifier Configuration & Result
# ---------------------------------------------------------------------------


@dataclass
class VerificationPolicy:
    trusted_root_spki_sha256: Set[str] = field(
        default_factory=lambda: set(BUILTIN_GOOGLE_ROOT_SPKI_SHA256)
    )
    revoked_serials: Set[str] = field(default_factory=load_builtin_revoked_serials_from_java)
    expected_package: Optional[str] = None
    expected_app_sig_sha256: Set[str] = field(default_factory=set)
    require_hardware: bool = True
    require_fresh_attestation: bool = False
    max_age_ms: int = 5 * 60 * 1000
    max_future_skew_ms: int = 60 * 1000
    min_coverage: int = 80
    min_confidence: int = 70
    reject_score_threshold: int = 60


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    decision: str  # ALLOW | STEP_UP | REJECT
    reason_code: str
    step_failed: int  # 0=precheck/none, 1..6=RFC step
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "decision": self.decision,
            "reasonCode": self.reason_code,
            "stepFailed": self.step_failed,
            "message": self.message,
            "details": self.details,
        }


def _fail(step: int, code: str, message: str, details: Optional[Dict[str, Any]] = None) -> VerificationResult:
    return VerificationResult(
        ok=False,
        decision=DECISION_REJECT,
        reason_code=code,
        step_failed=step,
        message=message,
        details=details or {},
    )


def verify_signed_envelope(
    envelope_or_report: Dict[str, Any],
    expected_challenge: bytes,
    policy: Optional[VerificationPolicy] = None,
    nonce_store: Optional[InMemoryNonceStore] = None,
    eval_time_utc: Optional[datetime.datetime] = None,
) -> VerificationResult:
    """Executes the full RFC §4.8.3 6-step offline verification pipeline."""
    pol = policy if policy is not None else VerificationPolicy()
    now_utc = (
        eval_time_utc.astimezone(datetime.timezone.utc)
        if eval_time_utc is not None
        else datetime.datetime.now(datetime.timezone.utc)
    )

    if not isinstance(envelope_or_report, dict):
        return _fail(0, CODE_ENVELOPE_MALFORMED, "Input must be a JSON object")

    outer_report: Optional[Dict[str, Any]] = None
    if "signedEnvelope" in envelope_or_report:
        envelope = envelope_or_report.get("signedEnvelope")
        outer_report = {k: v for k, v in envelope_or_report.items() if k != "signedEnvelope"}
    else:
        envelope = envelope_or_report

    if not isinstance(envelope, dict):
        return _fail(0, CODE_ENVELOPE_MALFORMED, "signedEnvelope must be a JSON object")

    payload = envelope.get("payload")
    sig_b64 = envelope.get("signatureBase64")
    cert_chain_pem = envelope.get("certChainPem")
    attestation_mode = envelope.get("attestationMode")
    key_sec_level = envelope.get("keySecurityLevel")

    if (
        not isinstance(payload, dict)
        or not isinstance(sig_b64, str)
        or not sig_b64
        or not isinstance(cert_chain_pem, list)
        or not isinstance(attestation_mode, str)
    ):
        return _fail(0, CODE_ENVELOPE_MALFORMED, "Missing required signedEnvelope fields")

    proto_ver = payload.get("v")
    if not isinstance(proto_ver, int) or isinstance(proto_ver, bool):
        return _fail(0, CODE_ENVELOPE_MALFORMED, "Missing or non-integer payload.v")
    if proto_ver != PROTOCOL_VERSION:
        return _fail(
            0,
            CODE_UNSUPPORTED_PROTOCOL_VERSION,
            f"Unsupported envelope protocol version v={proto_ver} (expected {PROTOCOL_VERSION})",
        )

    score = payload.get("score")
    if not isinstance(score, int) or isinstance(score, bool) or score < 0 or score > 100:
        return _fail(0, CODE_ENVELOPE_MALFORMED, "payload.score must be an integer in 0..100")

    action = payload.get("action")
    if not isinstance(action, str) or action not in VALID_RISK_ACTIONS:
        return _fail(0, CODE_ENVELOPE_MALFORMED, f"Invalid or missing payload.action: {action}")

    confidence = payload.get("confidence")
    if (
        not isinstance(confidence, int)
        or isinstance(confidence, bool)
        or confidence < 0
        or confidence > 100
    ):
        return _fail(0, CODE_ENVELOPE_MALFORMED, "payload.confidence must be an integer in 0..100")

    dimensions = payload.get("dimensions")
    if not isinstance(dimensions, dict) or set(dimensions.keys()) != set(REQUIRED_DIMENSIONS):
        return _fail(
            0,
            CODE_ENVELOPE_MALFORMED,
            "payload.dimensions must contain exact keys TAMPERING, PRIVILEGE, ENVIRONMENT, FRAUD_CONTEXT",
        )
    for dim_key in REQUIRED_DIMENSIONS:
        dim_val = dimensions.get(dim_key)
        if not isinstance(dim_val, int) or isinstance(dim_val, bool) or dim_val < 0 or dim_val > 100:
            return _fail(
                0,
                CODE_ENVELOPE_MALFORMED,
                f"payload.dimensions.{dim_key} must be an integer in 0..100",
            )

    if pol.require_hardware and (
        attestation_mode == "SOFTWARE_FALLBACK" or key_sec_level == "SOFTWARE"
    ):
        return _fail(
            0,
            CODE_SOFTWARE_FALLBACK_REJECTED,
            f"Hardware attestation required but envelope reported {attestation_mode}/{key_sec_level}",
        )

    if pol.require_fresh_attestation and attestation_mode != "FRESH_ATTESTATION":
        return _fail(
            0,
            CODE_ENVELOPE_MALFORMED,
            f"FRESH_ATTESTATION required but got {attestation_mode}",
        )

    if outer_report is not None:
        expected_report_sha256 = hashlib.sha256(canonical_json_bytes(outer_report)).hexdigest()
        actual_report_sha256 = payload.get("reportSha256")
        if actual_report_sha256 != expected_report_sha256:
            return _fail(
                0,
                CODE_REPORT_SHA256_MISMATCH,
                "Outer RiskReport canonical SHA-256 does not match payload.reportSha256",
            )

    # ------------------------------------------------------------------
    # Step 1: Certificate chain parsing, signatures, constraints, validity & root SPKI
    # ------------------------------------------------------------------
    if len(cert_chain_pem) < 2:
        return _fail(1, CODE_CERT_CHAIN_TOO_SHORT, f"Expected >=2 certificates, got {len(cert_chain_pem)}")

    certs: List[ParsedX509Certificate] = []
    for idx, pem in enumerate(cert_chain_pem):
        try:
            certs.append(parse_x509_der(pem_to_der(pem)))
        except DerError as exc:
            return _fail(1, CODE_CERT_PARSE_ERROR, f"Cert[{idx}] DER/PEM error: {exc}")

    for i in range(len(certs) - 1):
        child = certs[i]
        issuer = certs[i + 1]
        if not verify_x509_signature(child, issuer):
            return _fail(1, CODE_CERT_SIGNATURE_INVALID, f"Cert[{i}] signature verification failed")
        if child.issuer_der != issuer.subject_der:
            return _fail(1, CODE_CERT_ISSUER_MISMATCH, f"Cert[{i}] issuer DN != Cert[{i + 1}] subject DN")
        if not issuer.is_ca:
            return _fail(1, CODE_CERT_CA_CONSTRAINT_INVALID, f"Cert[{i + 1}] is not a CA")
        if issuer.path_len_constraint is not None:
            non_self_issued = sum(
                1 for k in range(1, i + 1) if certs[k].issuer_der != certs[k].subject_der
            )
            if non_self_issued > issuer.path_len_constraint:
                return _fail(
                    1,
                    CODE_CERT_CA_CONSTRAINT_INVALID,
                    f"Cert[{i + 1}] pathLenConstraint={issuer.path_len_constraint} exceeded",
                )
        if issuer.key_usage_present and not issuer.key_cert_sign:
            return _fail(1, CODE_CERT_CA_CONSTRAINT_INVALID, f"Cert[{i + 1}] lacks keyCertSign")

    root = certs[-1]
    if root.issuer_der != root.subject_der:
        return _fail(1, CODE_CERT_ISSUER_MISMATCH, "Root certificate is not self-issued")
    if not verify_x509_signature(root, root):
        return _fail(1, CODE_CERT_SIGNATURE_INVALID, "Root certificate self-signature invalid")

    for i, cert in enumerate(certs):
        if now_utc < cert.not_before or now_utc > cert.not_after:
            return _fail(1, CODE_CERT_VALIDITY_EXPIRED, f"Cert[{i}] outside validity window")

    trusted_roots = {r.strip().lower() for r in pol.trusted_root_spki_sha256 if r}
    if root.public_key.spki_sha256 not in trusted_roots:
        return _fail(
            1,
            CODE_ROOT_ANCHOR_UNTRUSTED,
            f"Root SPKI {root.public_key.spki_sha256} not in trusted Google Hardware Attestation roots",
        )

    # ------------------------------------------------------------------
    # Step 2: Revocation / CRL check across entire chain
    # ------------------------------------------------------------------
    normalized_crl = {
        n for s in pol.revoked_serials for n in [normalize_serial_token(s)] if n
    }
    for i, cert in enumerate(certs):
        for cand in serial_candidates(cert.serial_number):
            if cand in normalized_crl:
                return _fail(
                    2,
                    CODE_CERT_SERIAL_REVOKED,
                    f"Cert[{i}] serial {cand} is revoked in CRL",
                    {"revokedSerial": cand, "certIndex": i},
                )

    # ------------------------------------------------------------------
    # Step 3: Root-first OID .17 hardware extension, RootOfTrust & AppId
    # ------------------------------------------------------------------
    try:
        att = parse_attestation_root_first(certs)
    except DerError as exc:
        return _fail(3, CODE_ATTESTATION_EXTENSION_INVALID, f"OID .17 DER error: {exc}")

    if att is None:
        return _fail(3, CODE_ATTESTATION_EXTENSION_MISSING, "Missing OID 1.3.6.1.4.1.11129.2.1.17")

    if att.attestation_security_level not in (1, 2) or att.keymaster_security_level not in (1, 2):
        return _fail(
            3,
            CODE_ATTESTATION_SECURITY_LEVEL_INVALID,
            f"Expected hardware TEE/STRONG_BOX level, got att={att.attestation_security_level} km={att.keymaster_security_level}",
        )

    if not att.root_of_trust_present or not att.root_of_trust_hw_enforced:
        return _fail(3, CODE_ROOT_OF_TRUST_MISSING, "Hardware-enforced RootOfTrust missing")

    if att.device_locked is not True:
        return _fail(3, CODE_ROOT_OF_TRUST_UNLOCKED, "Bootloader is unlocked (deviceLocked=false)")

    if att.verified_boot_state != 0:
        return _fail(
            3,
            CODE_ROOT_OF_TRUST_BOOT_UNVERIFIED,
            f"VerifiedBootState is not VERIFIED (got {att.verified_boot_state})",
        )

    if pol.expected_package:
        if payload.get("pkg") != pol.expected_package or pol.expected_package not in att.app_packages:
            return _fail(
                3,
                CODE_APP_ID_PACKAGE_MISMATCH,
                f"Expected package {pol.expected_package}, payload={payload.get('pkg')}, att={list(att.app_packages)}",
            )

    if pol.expected_app_sig_sha256:
        expected_sigs = {s.strip().lower() for s in pol.expected_app_sig_sha256 if s}
        actual_sigs = {s.lower() for s in att.app_signature_digests}
        if not (expected_sigs & actual_sigs):
            return _fail(
                3,
                CODE_APP_ID_SIGNATURE_MISMATCH,
                "attestationApplicationId signing certificate SHA-256 mismatch",
            )

    # ------------------------------------------------------------------
    # Step 4: Challenge, freshness & replay nonce binding
    # ------------------------------------------------------------------
    expected_challenge_b64url = base64url_no_pad(expected_challenge)
    if payload.get("challenge") != expected_challenge_b64url:
        return _fail(4, CODE_CHALLENGE_MISMATCH, "payload.challenge does not match server challenge")

    if attestation_mode == "FRESH_ATTESTATION" and att.attestation_challenge != expected_challenge:
        return _fail(
            4,
            CODE_ATTESTATION_CHALLENGE_MISMATCH,
            "FRESH_ATTESTATION certificate attestationChallenge does not match server challenge",
        )

    ts_ms = payload.get("ts")
    if not isinstance(ts_ms, int) or isinstance(ts_ms, bool):
        return _fail(4, CODE_ENVELOPE_EXPIRED, "Missing or non-integer payload.ts")
    eval_ms = int(now_utc.timestamp() * 1000)
    if ts_ms < eval_ms - pol.max_age_ms or ts_ms > eval_ms + pol.max_future_skew_ms:
        return _fail(
            4,
            CODE_ENVELOPE_EXPIRED,
            f"Envelope timestamp {ts_ms} outside allowed window around {eval_ms}",
        )

    if nonce_store is not None and not nonce_store.consume_if_fresh(expected_challenge_b64url):
        return _fail(4, CODE_NONCE_REPLAYED, "Challenge nonce has already been consumed")

    # ------------------------------------------------------------------
    # Step 5: SHA256withECDSA over canonical UTF-8 payload bytes
    # ------------------------------------------------------------------
    try:
        sig_raw = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return _fail(5, CODE_SIGNATURE_INVALID, "Invalid base64 signature")

    leaf_pub = certs[0].public_key
    if leaf_pub.algorithm != "EC" or not leaf_pub.curve_oid or not leaf_pub.ec_point:
        return _fail(5, CODE_SIGNATURE_INVALID, "Leaf certificate public key is not EC")

    payload_bytes = canonical_json_bytes(payload)
    if not verify_ecdsa_der_signature(
        leaf_pub.curve_oid, leaf_pub.ec_point, payload_bytes, sig_raw, "sha256"
    ):
        return _fail(5, CODE_SIGNATURE_INVALID, "SHA256withECDSA payload signature verification failed")

    # ------------------------------------------------------------------
    # Step 6: Business risk policy decision (protocol v=2, 0-100 scale)
    # ------------------------------------------------------------------
    hard_triggers = payload.get("hardTriggers") or []
    risk_level = str(payload.get("riskLevel", "UNKNOWN"))
    coverage = payload.get("coverage", 0)
    details = {
        "protocolVersion": PROTOCOL_VERSION,
        "attestationMode": attestation_mode,
        "attestationSecurityLevel": att.attestation_security_level,
        "riskLevel": risk_level,
        "score": score,
        "action": action,
        "confidence": confidence,
        "dimensions": {k: int(dimensions[k]) for k in REQUIRED_DIMENSIONS},
        "coverage": coverage,
        "hardTriggers": list(hard_triggers),
        "fpHardware": payload.get("fpHardware", ""),
        "rootSpkiSha256": root.public_key.spki_sha256,
    }

    if isinstance(hard_triggers, list) and len(hard_triggers) > 0:
        return VerificationResult(
            ok=False,
            decision=DECISION_REJECT,
            reason_code=CODE_POLICY_HARD_TRIGGER,
            step_failed=6,
            message=f"Hard triggers present: {hard_triggers}",
            details=details,
        )

    if (
        risk_level in ("HIGH", "DEADLY")
        or action in ("RESTRICT", "BLOCK")
        or score >= pol.reject_score_threshold
    ):
        return VerificationResult(
            ok=False,
            decision=DECISION_REJECT,
            reason_code=CODE_POLICY_HIGH_RISK,
            step_failed=6,
            message=f"Risk exceeds threshold (level={risk_level}, action={action}, score={score})",
            details=details,
        )

    if (
        risk_level in ("MEDIUM", "UNKNOWN")
        or action in ("CHALLENGE", "REVIEW")
        or confidence < pol.min_confidence
        or (isinstance(coverage, int) and not isinstance(coverage, bool) and coverage < pol.min_coverage)
    ):
        return VerificationResult(
            ok=True,
            decision=DECISION_STEP_UP,
            reason_code=CODE_POLICY_STEP_UP,
            step_failed=0,
            message=(
                f"Step-up auth required (level={risk_level}, action={action}, "
                f"confidence={confidence}, coverage={coverage})"
            ),
            details=details,
        )

    return VerificationResult(
        ok=True,
        decision=DECISION_ALLOW,
        reason_code=CODE_OK,
        step_failed=0,
        message="All 6 offline hardware envelope verification steps passed",
        details=details,
    )


def _decode_challenge_arg(raw: str) -> bytes:
    padded = raw + "=" * ((4 - len(raw) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return bytes.fromhex(raw)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline 6-step verifier for RiskEngine SignedRiskEnvelope (RFC §4.8.3)."
    )
    parser.add_argument("--envelope", required=True, help="Path to envelope or full report JSON (or '-' for stdin)")
    parser.add_argument("--challenge", required=True, help="Expected server challenge (base64url or hex)")
    parser.add_argument("--expected-package", default=None, help="Expected Android package name")
    parser.add_argument("--expected-app-sig", action="append", default=[], help="Expected signing cert SHA-256 hex")
    parser.add_argument("--trusted-root-spki", action="append", default=[], help="Override/add trusted root SPKI SHA-256")
    parser.add_argument("--crl-file", default=None, help="Optional Google attestation status JSON file")
    parser.add_argument("--revoked-serial", action="append", default=[], help="Additional revoked certificate serial")
    parser.add_argument("--eval-epoch-ms", type=int, default=None, help="Fixed UTC evaluation timestamp in epoch ms")
    parser.add_argument("--require-fresh", action="store_true", help="Require FRESH_ATTESTATION mode")
    parser.add_argument("--allow-software-fallback", action="store_true", help="Allow SOFTWARE_FALLBACK envelopes")
    parser.add_argument("--min-coverage", type=int, default=80, help="Minimum coverage percent for ALLOW")
    parser.add_argument("--min-confidence", type=int, default=70, help="Minimum assessment confidence percent for ALLOW")
    parser.add_argument(
        "--reject-score-threshold",
        type=int,
        default=60,
        help="Normalized 0-100 risk score threshold at or above which REJECT is returned",
    )
    args = parser.parse_args(argv)

    raw_text = sys.stdin.read() if args.envelope == "-" else pathlib.Path(args.envelope).read_text(encoding="utf-8")
    data = json.loads(raw_text)
    challenge = _decode_challenge_arg(args.challenge)

    roots = set(BUILTIN_GOOGLE_ROOT_SPKI_SHA256)
    if args.trusted_root_spki:
        roots.update(s.strip().lower() for s in args.trusted_root_spki)

    revoked = load_builtin_revoked_serials_from_java()
    if args.crl_file:
        crl_data = json.loads(pathlib.Path(args.crl_file).read_text(encoding="utf-8"))
        revoked.update(load_revoked_serials_from_status_json(crl_data))
    for s in args.revoked_serial:
        norm = normalize_serial_token(s)
        if norm:
            revoked.add(norm)

    eval_dt = (
        datetime.datetime.fromtimestamp(args.eval_epoch_ms / 1000.0, tz=datetime.timezone.utc)
        if args.eval_epoch_ms is not None
        else None
    )

    policy = VerificationPolicy(
        trusted_root_spki_sha256=roots,
        revoked_serials=revoked,
        expected_package=args.expected_package,
        expected_app_sig_sha256=set(args.expected_app_sig),
        require_hardware=not args.allow_software_fallback,
        require_fresh_attestation=args.require_fresh,
        min_coverage=args.min_coverage,
        min_confidence=args.min_confidence,
        reject_score_threshold=args.reject_score_threshold,
    )
    result = verify_signed_envelope(data, challenge, policy=policy, eval_time_utc=eval_dt)
    print(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")))
    return 0 if result.decision != DECISION_REJECT else 1


_stop = SystemExit

if __name__ == "__main__":
    raise _stop(main())
