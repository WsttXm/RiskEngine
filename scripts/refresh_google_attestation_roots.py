#!/usr/bin/env python3
"""Refresh embedded Google Hardware Attestation Root hashes and monotonic offline CRL floor.

Updates the generated marker block inside:
  riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/attestation/GoogleAttestationRootStore.java

Supports:
  - Live fetch from Google endpoints (https://android.googleapis.com/attestation/root & /status)
  - Offline refresh from local JSON snapshots (--roots-file / --status-file)
  - --dry-run validation without mutating source files
  - Strict monotonicity enforcement: offline CRL floor never shrinks/downgrades
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.request

ROOT_URL = "https://android.googleapis.com/attestation/root"
STATUS_URL = "https://android.googleapis.com/attestation/status"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_JAVA = (
    REPO_ROOT
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

BEGIN_MARKER = "// BEGIN GENERATED GOOGLE ATTESTATION DATA (scripts/refresh_google_attestation_roots.py)"
END_MARKER = "// END GENERATED GOOGLE ATTESTATION DATA"
CHUNK_SIZE = 200


def parse_roots_pem_list(payload: str) -> list[str]:
    roots = json.loads(payload)
    if not isinstance(roots, list) or not roots:
        raise ValueError("Google attestation root payload must be a non-empty JSON list.")
    normalized: list[str] = []
    for idx, pem in enumerate(roots):
        if (
            not isinstance(pem, str)
            or "-----BEGIN CERTIFICATE-----" not in pem
            or "-----END CERTIFICATE-----" not in pem
        ):
            raise ValueError(f"Root entry {idx} is not a valid PEM certificate.")
        normalized.append(pem.strip())
    return normalized


def extract_root_hashes(pems: list[str]) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for pem in pems:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", encoding="utf-8") as tf:
            tf.write(pem + "\n")
            tf.flush()
            der = subprocess.check_output(
                ["openssl", "x509", "-in", tf.name, "-outform", "DER"],
                stderr=subprocess.DEVNULL,
            )
            pub_pem = subprocess.check_output(
                ["openssl", "x509", "-in", tf.name, "-pubkey", "-noout"],
                stderr=subprocess.DEVNULL,
            )
            spki_der = subprocess.check_output(
                ["openssl", "pkey", "-pubin", "-outform", "DER"],
                input=pub_pem,
                stderr=subprocess.DEVNULL,
            )
            subj = subprocess.check_output(
                ["openssl", "x509", "-in", tf.name, "-subject", "-noout"],
                stderr=subprocess.DEVNULL,
            ).decode("utf-8", errors="replace").strip()
            clean_subj = re.sub(r"[\r\n]+", " ", subj.replace("subject=", "")).strip()
            results.append(
                {
                    "subject": clean_subj,
                    "cert_sha256": hashlib.sha256(der).hexdigest(),
                    "spki_sha256": hashlib.sha256(spki_der).hexdigest(),
                }
            )
    return results


def _normalize_serial(raw: str) -> str | None:
    norm = raw.strip().lower()
    if norm.startswith("0x"):
        norm = norm[2:]
    norm = norm.lstrip("0") or ("0" if norm else "")
    if not norm or not re.fullmatch(r"[0-9a-f]+", norm):
        return None
    return norm


def parse_revoked_serials(payload: str) -> set[str]:
    obj = json.loads(payload)
    entries = obj.get("entries") if isinstance(obj, dict) else None
    if not isinstance(entries, dict):
        raise ValueError("Attestation status JSON must contain an 'entries' object.")
    revoked: set[str] = set()
    for serial, meta in entries.items():
        if not isinstance(serial, str) or not isinstance(meta, dict):
            continue
        status = str(meta.get("status", "")).upper()
        if status in ("REVOKED", "SUSPENDED"):
            norm = _normalize_serial(serial)
            if norm is not None:
                revoked.add(norm)
    return revoked


def extract_existing_serials(java_source: str) -> set[str]:
    existing: set[str] = set()
    block_match = re.search(
        re.escape(BEGIN_MARKER) + r"(.*?)" + re.escape(END_MARKER),
        java_source,
        re.DOTALL,
    )
    if not block_match:
        return existing
    block = block_match.group(1)
    chunks_match = re.search(
        r"BUILTIN_REVOKED_SERIAL_CHUNKS\s*=\s*\{(.*?)\};",
        block,
        re.DOTALL,
    )
    if not chunks_match:
        return existing
    for m in re.finditer(r'"([^"]*)"', chunks_match.group(1)):
        for token in m.group(1).split(","):
            norm = _normalize_serial(token)
            if norm is not None:
                existing.add(norm)
    return existing


def render_java_block(roots: list[dict[str, str]], revoked_serials: list[str]) -> str:
    lines: list[str] = [BEGIN_MARKER]
    lines.append("    private static final String[] BUILTIN_ROOT_SPKI_SHA256 = {")
    for r in roots:
        lines.append(f'        "{r["spki_sha256"]}", // {r["subject"]}')
    lines.append("    };")
    lines.append("")
    lines.append("    private static final String[] BUILTIN_ROOT_CERT_SHA256 = {")
    for r in roots:
        lines.append(f'        "{r["cert_sha256"]}", // {r["subject"]}')
    lines.append("    };")
    lines.append("")
    lines.append("    private static final String[] BUILTIN_REVOKED_SERIAL_CHUNKS = {")
    for i in range(0, len(revoked_serials), CHUNK_SIZE):
        chunk = ",".join(revoked_serials[i : i + CHUNK_SIZE])
        lines.append(f'        "{chunk}",')
    lines.append("    };")
    lines.append("    " + END_MARKER)
    return "\n".join(lines)


def fetch_text(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "RiskEngine-RootRefresh/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refresh embedded Google Hardware Attestation roots & monotonic CRL floor."
    )
    parser.add_argument("--roots-file", type=pathlib.Path, help="Local JSON file of Google root PEMs.")
    parser.add_argument("--status-file", type=pathlib.Path, help="Local JSON file of Google CRL status.")
    parser.add_argument("--target", type=pathlib.Path, default=TARGET_JAVA, help="Target Java file.")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print summary without writing.")
    args = parser.parse_args(argv)

    if not args.target.exists():
        print(f"ERROR: Target file not found: {args.target}", file=sys.stderr)
        return 1

    java_source = args.target.read_text(encoding="utf-8")
    if BEGIN_MARKER not in java_source or END_MARKER not in java_source:
        print("ERROR: Generated marker block missing in target Java file.", file=sys.stderr)
        return 1

    existing_serials = extract_existing_serials(java_source)

    if args.roots_file:
        roots_payload = args.roots_file.read_text(encoding="utf-8")
    elif args.dry_run and not args.status_file:
        print(
            f"Dry-run check OK: target={args.target} existing_crl_floor={len(existing_serials)} "
            "(pass --roots-file/--status-file or omit --dry-run to fetch live endpoints)."
        )
        return 0
    else:
        roots_payload = fetch_text(ROOT_URL, args.timeout)

    if args.status_file:
        status_payload = args.status_file.read_text(encoding="utf-8")
    else:
        status_payload = fetch_text(STATUS_URL, args.timeout)

    roots = extract_root_hashes(parse_roots_pem_list(roots_payload))
    fetched_serials = parse_revoked_serials(status_payload)

    # Monotonic floor union: never shrink or drop previously revoked keybox serials.
    merged_serials = sorted(existing_serials | fetched_serials)
    new_block = render_java_block(roots, merged_serials)

    updated_source = re.sub(
        r"[ \t]*" + re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER),
        lambda _: "    " + new_block,
        java_source,
        count=1,
        flags=re.DOTALL,
    )

    if args.dry_run:
        print(
            f"Dry-run OK: roots={len(roots)}, fetched_crl={len(fetched_serials)}, "
            f"monotonic_floor={len(merged_serials)} (previous={len(existing_serials)})"
        )
        return 0

    args.target.write_text(updated_source, encoding="utf-8")
    print(
        f"Updated {args.target}: roots={len(roots)}, "
        f"monotonic_crl_floor={len(merged_serials)} (added={len(merged_serials) - len(existing_serials)})"
    )
    return 0


if __name__ == "__main__":
    _stop = SystemExit
    raise _stop(main())
