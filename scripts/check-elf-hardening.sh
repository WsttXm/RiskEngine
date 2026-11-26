#!/usr/bin/env bash
# Deterministic Release AAR ELF Hardening & Binary Size Gate
# Usage: ./scripts/check-elf-hardening.sh [path/to/riskengine-sdk-release.aar]

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AAR_PATH="${1:-${ROOT_DIR}/riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar}"

MAX_AAR_BYTES=4194304   # 4 MiB (4 * 1024 * 1024)
MAX_SO_BYTES=2048000    # 2000 KiB (2000 * 1024)
MIN_LOAD_ALIGN=16384    # 16 KiB (0x4000)

if [[ ! -s "$AAR_PATH" ]]; then
  echo "ERROR: Release AAR not found or empty: $AAR_PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required by check-elf-hardening.sh" >&2
  exit 1
fi

read_prop() {
  local file="$1"
  local key="$2"
  if [[ -f "$file" ]]; then
    grep -E "^${key}=" "$file" | tail -n 1 | cut -d'=' -f2- | tr -d '\r' | xargs || true
  fi
}

find_readelf() {
  if [[ -n "${LLVM_READELF:-}" && -x "${LLVM_READELF}" ]]; then
    printf '%s' "${LLVM_READELF}"
    return 0
  fi

  local ndk_ver
  ndk_ver="$(read_prop "${ROOT_DIR}/gradle.properties" "androidNdkVersion")"

  local -a ndk_candidates=()
  if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
    ndk_candidates+=("${ANDROID_NDK_HOME}")
  fi
  if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
    ndk_candidates+=("${ANDROID_NDK_ROOT}")
  fi

  local -a sdk_roots=()
  if [[ -n "${ANDROID_HOME:-}" ]]; then
    sdk_roots+=("${ANDROID_HOME}")
  fi
  if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
    sdk_roots+=("${ANDROID_SDK_ROOT}")
  fi
  local local_sdk
  local_sdk="$(read_prop "${ROOT_DIR}/local.properties" "sdk.dir")"
  if [[ -n "$local_sdk" ]]; then
    # Unescape Gradle properties escaping (e.g. \: or \\)
    local_sdk="${local_sdk//\\:/:}"
    local_sdk="${local_sdk//\\\\/\\}"
    sdk_roots+=("$local_sdk")
  fi
  sdk_roots+=("${HOME}/Library/Android/sdk" "${HOME}/Android/Sdk")

  local root
  for root in "${sdk_roots[@]}"; do
    [[ -d "$root/ndk" ]] || continue
    if [[ -n "$ndk_ver" && -d "$root/ndk/$ndk_ver" ]]; then
      ndk_candidates+=("$root/ndk/$ndk_ver")
    fi
    local latest
    for latest in "$root"/ndk/*; do
      [[ -d "$latest" ]] && ndk_candidates+=("$latest")
    done
  done

  local ndk_dir host_bin
  for ndk_dir in "${ndk_candidates[@]}"; do
    for host_bin in "$ndk_dir"/toolchains/llvm/prebuilt/*/bin/llvm-readelf; do
      if [[ -x "$host_bin" ]]; then
        printf '%s' "$host_bin"
        return 0
      fi
    done
  done

  if command -v llvm-readelf >/dev/null 2>&1; then
    command -v llvm-readelf
    return 0
  fi
  if command -v readelf >/dev/null 2>&1; then
    command -v readelf
    return 0
  fi
  return 1
}

READELF_BIN="$(find_readelf || true)"
if [[ -z "$READELF_BIN" ]]; then
  echo "ERROR: Could not locate llvm-readelf or readelf (checked NDK and PATH)." >&2
  exit 1
fi

echo "==> ELF Hardening Gate: ${AAR_PATH}"
echo "    Using readelf: ${READELF_BIN}"

python3 - "$AAR_PATH" "$READELF_BIN" "$MAX_AAR_BYTES" "$MAX_SO_BYTES" "$MIN_LOAD_ALIGN" <<'PY'
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from sys import exit as die

aar_path = sys.argv[1]
readelf_bin = sys.argv[2]
max_aar_bytes = int(sys.argv[3])
max_so_bytes = int(sys.argv[4])
min_load_align = int(sys.argv[5])

expected_abis = ["arm64-v8a", "x86_64"]
expected_exports = {"JNI_OnLoad", "JNI_OnUnload"}
errors = []

aar_size = os.path.getsize(aar_path)
if aar_size > max_aar_bytes:
    errors.append(
        f"AAR size {aar_size} bytes exceeds limit {max_aar_bytes} bytes (4 MiB)"
    )

print(f"    AAR size: {aar_size:,} bytes (limit: {max_aar_bytes:,} bytes)")

with tempfile.TemporaryDirectory(prefix="riskengine-elf-gate-") as tmpdir:
    try:
        zf = zipfile.ZipFile(aar_path, "r")
    except zipfile.BadZipFile as exc:
        print(f"ERROR: Corrupt AAR archive: {exc}", file=sys.stderr)
        die(1)

    with zf:
        bad_entry = zf.testzip()
        if bad_entry is not None:
            errors.append(f"Corrupt ZIP entry in AAR: {bad_entry}")

        names = set(zf.namelist())
        expected_entries = {f"jni/{abi}/libriskengine.so" for abi in expected_abis}
        actual_so_entries = {n for n in names if n.startswith("jni/") and n.endswith(".so")}
        unexpected_so = sorted(actual_so_entries - expected_entries)
        if unexpected_so:
            errors.append(f"Unexpected native libraries in AAR: {', '.join(unexpected_so)}")

        for abi in expected_abis:
            entry = f"jni/{abi}/libriskengine.so"
            if entry not in names:
                errors.append(f"[{abi}] Missing {entry} in release AAR")
                continue

            so_path = zf.extract(entry, tmpdir)
            so_size = os.path.getsize(so_path)
            if so_size == 0:
                errors.append(f"[{abi}] libriskengine.so is empty")
                continue
            if so_size > max_so_bytes:
                errors.append(
                    f"[{abi}] libriskengine.so size {so_size} bytes exceeds limit "
                    f"{max_so_bytes} bytes (2000 KiB)"
                )

            # 1. Section headers: verify stripped (no .symtab / SYMTAB / .debug_*) and no .comment
            sec_out = subprocess.check_output(
                [readelf_bin, "-S", "-W", so_path], text=True
            )
            section_names = set()
            section_types = set()
            for line in sec_out.splitlines():
                m = re.match(r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+", line)
                if m:
                    section_names.add(m.group(1))
                    section_types.add(m.group(2))

            if not section_names:
                errors.append(f"[{abi}] Failed to parse ELF section headers from readelf -S output")
            has_symtab = ".symtab" in section_names or "SYMTAB" in section_types
            if has_symtab:
                errors.append(f"[{abi}] Not stripped: .symtab / SYMTAB section present")
            debug_secs = sorted(s for s in section_names if s.startswith(".debug"))
            if debug_secs:
                errors.append(f"[{abi}] Debug sections present: {', '.join(debug_secs)}")
            has_comment = ".comment" in section_names
            if has_comment:
                errors.append(f"[{abi}] .comment section present (must be stripped)")

            # 2. Dynamic symbols: verify ONLY JNI_OnLoad and JNI_OnUnload are exported
            dynsym_out = subprocess.check_output(
                [readelf_bin, "--dyn-syms", "-W", so_path], text=True
            )
            exported = set()
            for line in dynsym_out.splitlines():
                cols = line.split()
                if len(cols) < 8 or not cols[0].endswith(":"):
                    continue
                bind = cols[4]
                vis = cols[5]
                ndx = cols[6]
                raw_name = cols[7]
                sym_name = raw_name.split("@", 1)[0]
                if (
                    bind in ("GLOBAL", "WEAK")
                    and vis in ("DEFAULT", "PROTECTED")
                    and ndx != "UND"
                    and sym_name
                ):
                    exported.add(sym_name)

            if exported != expected_exports:
                errors.append(
                    f"[{abi}] Exported dynamic symbols mismatch: "
                    f"found={sorted(exported)}, expected={sorted(expected_exports)}"
                )

            # 3. Program headers: verify 16KB PT_LOAD alignment, GNU_RELRO, non-exec GNU_STACK
            ph_out = subprocess.check_output(
                [readelf_bin, "-l", "-W", so_path], text=True
            )
            load_aligns = []
            has_relro = False
            has_gnu_stack = False
            stack_exec = False
            for line in ph_out.splitlines():
                stripped = line.strip()
                if stripped.startswith("LOAD "):
                    cols = stripped.split()
                    align = int(cols[-1], 0)
                    load_aligns.append(align)
                elif stripped.startswith("GNU_RELRO "):
                    has_relro = True
                elif stripped.startswith("GNU_STACK "):
                    has_gnu_stack = True
                    # Flags appear just before Align (last column); check for 'E'
                    cols = stripped.split()
                    # e.g. GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x0
                    flags = " ".join(cols[6:-1])
                    if "E" in flags:
                        stack_exec = True

            if not load_aligns:
                errors.append(f"[{abi}] No PT_LOAD program headers found")
            else:
                bad_aligns = [
                    hex(a) for a in load_aligns
                    if a < min_load_align or (a % min_load_align) != 0
                ]
                if bad_aligns:
                    errors.append(
                        f"[{abi}] PT_LOAD alignment below 16KB (0x4000): {bad_aligns}"
                    )
            if not has_relro:
                errors.append(f"[{abi}] Missing GNU_RELRO program header")
            if not has_gnu_stack:
                errors.append(f"[{abi}] Missing GNU_STACK program header")
            if stack_exec:
                errors.append(f"[{abi}] Executable GNU_STACK detected")

            align_summary = ",".join(sorted({hex(a) for a in load_aligns})) or "none"
            strip_status = "FAIL" if (has_symtab or debug_secs) else "OK"
            comment_status = "FAIL" if has_comment else "OK"
            print(
                f"    [{abi:11s}] size={so_size:7,d} B | exports={len(exported)} "
                f"| LOAD align={align_summary} | stripped={strip_status} | no-.comment={comment_status}"
            )

if errors:
    print("\nELF HARDENING GATE FAILED:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    die(1)

print("==> ELF Hardening Gate PASSED for all 2 64-bit ABIs.")
PY

if [[ "${CHECK_JNI_DEX:-0}" == "1" ]]; then
  python3 "${ROOT_DIR}/scripts/check-jni-and-dex.py" --aar "${AAR_PATH}"
fi
