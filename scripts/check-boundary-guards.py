#!/usr/bin/env python3
"""
CI Static Gate 5 — Reflection Allowlist & UI Display Text-Protocol Boundary Audit.

Audits core `:riskengine-sdk` Java and C++ main sources to enforce:
  1. Every restricted reflection primitive (`Class.forName`, `getMethod(s)`,
     `getDeclaredMethod(s)`, `getField(s)`, `getDeclaredField(s)`,
     `getConstructor(s)`, `getDeclaredConstructor`, `setAccessible`) under
     `riskengine-sdk/src/main/java/` MUST be explicitly registered in
     `REFLECTION_ALLOWLIST` with exact call-site count, target description,
     and non-empty documented degradation strategy, and the enclosing file
     MUST contain exception-handling `catch (...)` guards.
  2. Core HMA/threat probes (`detector/probe/threat/`) MUST NOT reflect on
     Android 12–16 blocked hidden APIs (per D66).
  3. Core Java (`riskengine-sdk/src/main/java/`) and C++ (`riskengine-sdk/src/main/cpp/`)
     MUST NOT import/reference UI presentation layers or branch on localized UI
     display text strings or prose summaries.
"""

import argparse
import os
import re
import sys

# Explicit, audited allowlist of every restricted reflection primitive in core SDK.
# Key: (relative_path_under_sdk_java, primitive_name)
# Value: dict with exact expected `count`, `target`, and `degradation_strategy`.
REFLECTION_ALLOWLIST = {
    (
        "com/wsttxm/riskenginesdk/detector/HookFrameworkDetector.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "Xposed/LSPosed class probing via target ClassLoader without static initialization",
        "degradation_strategy": "Catches ClassNotFoundException/Throwable and returns null (no hit; degrades cleanly to clean/other hook signals).",
    },
    (
        "com/wsttxm/riskenginesdk/detector/HookFrameworkDetector.java",
        "getDeclaredField",
    ): {
        "count": 1,
        "target": "de.robv.android.xposed.XposedBridge#sHookedMethodCallbacks",
        "degradation_strategy": "Catches Exception/LinkageError and falls back to native/maps/stack-trace hook probes with zero crash.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/HookFrameworkDetector.java",
        "setAccessible",
    ): {
        "count": 1,
        "target": "de.robv.android.xposed.XposedBridge#sHookedMethodCallbacks",
        "degradation_strategy": "Guarded inside try/catch; inability to read private field degrades without false positive.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/CustomRomDetector.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "com.huawei.system.BuildEx#getOsBrand (HarmonyOS/EMUI OEM marker)",
        "degradation_strategy": "Catches Exception/LinkageError and falls back to read-only system properties.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/CustomRomDetector.java",
        "getMethod",
    ): {
        "count": 1,
        "target": "com.huawei.system.BuildEx#getOsBrand()",
        "degradation_strategy": "Catches Exception/LinkageError and falls back to read-only system properties.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/tee/KeyMintQuirks.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "android.os.SystemProperties#get (read-only TEE/OEM quirk lookup)",
        "degradation_strategy": "Catches Exception/LinkageError and returns default empty string (safe quirk fallback).",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/tee/KeyMintQuirks.java",
        "getMethod",
    ): {
        "count": 1,
        "target": "android.os.SystemProperties#get(String, String)",
        "degradation_strategy": "Catches Exception/LinkageError and returns default empty string.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/tee/VintfHalAndErrorPathProbe.java",
        "getField",
    ): {
        "count": 1,
        "target": "KeyStoreException#errorCode field lookup on API 30-32",
        "degradation_strategy": "Catches Exception/LinkageError and falls back to getNumericErrorCode()/UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/tee/VintfHalAndErrorPathProbe.java",
        "setAccessible",
    ): {
        "count": 1,
        "target": "KeyStoreException#errorCode field inspection on API 30-32",
        "degradation_strategy": "Catches Exception/LinkageError and falls back to getNumericErrorCode()/UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/threat/ThanoxIpcProbe.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "android.os.ServiceManager#getService('dropbox') greylisted Binder lookup",
        "degradation_strategy": "Catches Exception/LinkageError and returns UNAVAILABLE (never false-positives on stock/OriginOS).",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/threat/ThanoxIpcProbe.java",
        "getMethod",
    ): {
        "count": 1,
        "target": "android.os.ServiceManager#getService(String)",
        "degradation_strategy": "Catches Exception/LinkageError and returns UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/hook/LsposedProbe.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "android.os.ServiceManager#getService greylisted Binder lookup for LSPosed daemon",
        "degradation_strategy": "Catches Exception/LinkageError and degrades to UNAVAILABLE/no-hit.",
    },
    (
        "com/wsttxm/riskenginesdk/detector/probe/hook/LsposedProbe.java",
        "getMethod",
    ): {
        "count": 1,
        "target": "android.os.ServiceManager#getService(String)",
        "degradation_strategy": "Catches Exception/LinkageError and degrades to UNAVAILABLE/no-hit.",
    },
    (
        "com/wsttxm/riskenginesdk/process/Keystore2ParcelClient.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "android.os.ServiceManager#getService('android.system.keystore2.IKeystoreService/default')",
        "degradation_strategy": "Catches Exception/LinkageError and degrades Keystore2 Binder probe to UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/process/Keystore2ParcelClient.java",
        "getMethod",
    ): {
        "count": 1,
        "target": "android.os.ServiceManager#getService(String)",
        "degradation_strategy": "Catches Exception/LinkageError and degrades Keystore2 Binder probe to UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/process/RiskIsolatedProbeService.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "android.security.keystore.KeyStoreManager (API 31+ cross-process grant check)",
        "degradation_strategy": "Catches Exception/LinkageError and degrades isolated KeyStoreManager probe to UNSUPPORTED/UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/process/RiskIsolatedProbeService.java",
        "getMethod",
    ): {
        "count": 1,
        "target": "KeyStoreManager public method lookup helper inside isolated service",
        "degradation_strategy": "Falls back to getDeclaredMethod / catches Exception and returns UNSUPPORTED/UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/process/RiskIsolatedProbeService.java",
        "getDeclaredMethod",
    ): {
        "count": 2,
        "target": "KeyStoreManager#getInstance and grant/revoke helper invocation on API 31+",
        "degradation_strategy": "Catches Exception/LinkageError and returns UNSUPPORTED/UNAVAILABLE without crashing isolated service.",
    },
    (
        "com/wsttxm/riskenginesdk/process/RiskIsolatedProbeService.java",
        "getField",
    ): {
        "count": 1,
        "target": "Parcel/KeyStore grant result public field lookup inside isolated service",
        "degradation_strategy": "Falls back to getDeclaredField / catches Exception and degrades cleanly to UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/process/RiskIsolatedProbeService.java",
        "getDeclaredField",
    ): {
        "count": 1,
        "target": "Parcel/KeyStore grant result field inspection inside isolated service",
        "degradation_strategy": "Catches Exception/LinkageError and degrades cleanly to UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/process/RiskIsolatedProbeService.java",
        "setAccessible",
    ): {
        "count": 4,
        "target": "KeyStoreManager method/field accessibility inside isolated probe process",
        "degradation_strategy": "All sites wrapped in try/catch; inaccessible members degrade to UNSUPPORTED/UNAVAILABLE.",
    },
    (
        "com/wsttxm/riskenginesdk/process/IsolatedProbeClient.java",
        "Class.forName",
    ): {
        "count": 1,
        "target": "android.security.keystore.KeyStoreManager (host-side grant preparation)",
        "degradation_strategy": "Catches Exception/LinkageError and falls back to UNSUPPORTED without blocking report collection.",
    },
    (
        "com/wsttxm/riskenginesdk/process/IsolatedProbeClient.java",
        "getMethod",
    ): {
        "count": 1,
        "target": "KeyStoreManager public method lookup helper",
        "degradation_strategy": "Falls back to getDeclaredMethod / catches Exception and returns UNSUPPORTED cleanly.",
    },
    (
        "com/wsttxm/riskenginesdk/process/IsolatedProbeClient.java",
        "getDeclaredMethod",
    ): {
        "count": 1,
        "target": "KeyStoreManager reflective invocation helper",
        "degradation_strategy": "Catches Exception/LinkageError and returns null/UNSUPPORTED cleanly.",
    },
    (
        "com/wsttxm/riskenginesdk/process/IsolatedProbeClient.java",
        "setAccessible",
    ): {
        "count": 1,
        "target": "KeyStoreManager reflective method helper",
        "degradation_strategy": "Wrapped in try/catch; failure degrades cleanly to UNSUPPORTED.",
    },
}

REFLECTION_PATTERNS = {
    "Class.forName": re.compile(r"\bClass\s*\.\s*forName\s*\("),
    "getMethod": re.compile(r"\.\s*getMethod\s*\("),
    "getMethods": re.compile(r"\.\s*getMethods\s*\("),
    "getDeclaredMethod": re.compile(r"\.\s*getDeclaredMethod\s*\("),
    "getDeclaredMethods": re.compile(r"\.\s*getDeclaredMethods\s*\("),
    "getField": re.compile(r"\.\s*getField\s*\("),
    "getFields": re.compile(r"\.\s*getFields\s*\("),
    "getDeclaredField": re.compile(r"\.\s*getDeclaredField\s*\("),
    "getDeclaredFields": re.compile(r"\.\s*getDeclaredFields\s*\("),
    "getConstructor": re.compile(r"\.\s*getConstructor\s*\("),
    "getConstructors": re.compile(r"\.\s*getConstructors\s*\("),
    "getDeclaredConstructor": re.compile(r"\.\s*getDeclaredConstructor\s*\("),
    "setAccessible": re.compile(r"\.\s*setAccessible\s*\("),
}

CATCH_GUARD_RE = re.compile(r"\bcatch\s*\(")

# Blocked hidden-API reflective access forbidden inside HMA / threat probes (D66).
# Frozen Binder wire descriptors passed to Parcel.writeInterfaceToken(...) are allowed per D66.
FORBIDDEN_HMA_HIDDEN_API_RE = re.compile(
    r"Class\s*\.\s*forName\s*\([^;]*(?:IPackageManager|IPermissionManager|IActivityManager|"
    r"ActivityThread|ApplicationPackageManager|PermissionManager)|"
    r"VMRuntime\s*\.\s*setHiddenApiExemptions|HiddenApiBypass"
)

# Presentation / UI classes forbidden in core SDK Java/C++ sources.
FORBIDDEN_UI_IMPORT_RE = re.compile(
    r"\b(com\.wsttxm\.riskenginesdk\.demo|"
    r"R\.string\.|R\.layout\.|R\.id\.|R\.drawable\.|R\.color\.|"
    r"android\.widget\.|androidx\.|com\.google\.android\.material\.|"
    r"TextView|RecyclerView|BottomSheetDialog|Toast\.makeText|"
    r"ReportFormatter|RiskGaugeView|FluidDetailSheet|ThreatStreamDrawer)\b"
)

# Display-text / prose-summary branching forbidden in core logic (multiline-safe).
FORBIDDEN_TEXT_BRANCH_RE = re.compile(
    r"(getSummary\s*\(\s*\)\s*\.\s*(equals|contains|startsWith|endsWith|matches)\s*\(|"
    r"getLocalizedMessage\s*\(\s*\)\s*\.\s*(equals|contains)\s*\(|"
    r"getDisplayName\s*\(\s*\)\s*\.\s*(equals|contains)\s*\(|"
    r"toJson\s*\(\s*\)\s*\.\s*(contains|equals)\s*\(|"
    r"(?:equals|equalsIgnoreCase|contains|strcmp|strstr|find)\s*\([^;]*\""
    r"(?:High Risk|Critical Risk|Medium Risk|Low Risk|Safe Device|"
    r"高风险|极高风险|中风险|低风险|安全设备|未检测到风险|已检测到风险)\")"
)

CJK_LITERAL_RE = re.compile(r'"[^"\n]*[\u4e00-\u9fff][^"\n]*"')
HEX_DIGIT_CHARS = set("0123456789abcdefABCDEF")
NUM_LITERAL_BODY_CHARS = set("0123456789abcdefABCDEFxXbB'")


def _is_cpp_digit_separator(source: str, idx: int) -> bool:
    """
    Detect C++14/17 numeric literal digit separators like `10'000` or `0xFF'00`
    so they are not misparsed as character literal openings.
    """
    n = len(source)
    if idx <= 0 or idx + 1 >= n:
        return False
    if source[idx + 1] not in HEX_DIGIT_CHARS:
        return False
    j = idx - 1
    while j >= 0 and source[j] in NUM_LITERAL_BODY_CHARS:
        j -= 1
    token_start = j + 1
    if token_start >= idx:
        return False
    if not source[token_start].isdigit():
        return False
    if j >= 0 and (source[j].isalnum() or source[j] == "_"):
        return False
    return True


def strip_c_style_comments(source: str) -> str:
    """
    Strip // line comments and /* ... */ block comments while preserving
    string/char literals, C++14/17 digit separators, and exact line numbers.
    """
    out = []
    i = 0
    n = len(source)
    state = "CODE"
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "CODE":
            if ch == "/" and nxt == "/":
                state = "LINE_COMMENT"
                out.append("  ")
                i += 2
            elif ch == "/" and nxt == "*":
                state = "BLOCK_COMMENT"
                out.append("  ")
                i += 2
            elif ch == '"':
                state = "STRING"
                out.append(ch)
                i += 1
            elif ch == "'":
                if _is_cpp_digit_separator(source, i):
                    out.append(ch)
                    i += 1
                else:
                    state = "CHAR"
                    out.append(ch)
                    i += 1
            else:
                out.append(ch)
                i += 1
        elif state == "LINE_COMMENT":
            if ch == "\n":
                state = "CODE"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif state == "BLOCK_COMMENT":
            if ch == "*" and nxt == "/":
                state = "CODE"
                out.append("  ")
                i += 2
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
        elif state == "STRING":
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
            else:
                if ch == '"':
                    state = "CODE"
                i += 1
        elif state == "CHAR":
            out.append(ch)
            if ch == "\n":
                # Unterminated char literal cannot span unescaped newline in Java/C++.
                state = "CODE"
                i += 1
            elif ch == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
            else:
                if ch == "'":
                    state = "CODE"
                i += 1
    return "".join(out)


def _line_number_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet_at(text: str, pos: int) -> str:
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


def validate_allowlist_schema(allowlist: dict) -> list:
    errors = []
    for key, meta in sorted(allowlist.items()):
        if not isinstance(meta.get("count"), int) or meta["count"] <= 0:
            errors.append(f"Allowlist entry {key} must have positive integer 'count'")
        if not str(meta.get("target", "")).strip():
            errors.append(f"Allowlist entry {key} is missing 'target' description")
        if not str(meta.get("degradation_strategy", "")).strip():
            errors.append(
                f"Allowlist entry {key} is missing documented 'degradation_strategy'"
            )
    return errors


def audit_core_boundaries(
    java_root: str,
    cpp_root: str,
    allowlist: dict = None,
) -> tuple:
    """
    Returns (errors: list[str], stats: dict).
    """
    if allowlist is None:
        allowlist = REFLECTION_ALLOWLIST

    errors = []
    errors.extend(validate_allowlist_schema(allowlist))

    observed_counts = {}
    java_files_scanned = 0
    cpp_files_scanned = 0

    if not os.path.isdir(java_root):
        return [f"Core Java source root not found: {java_root}"], {}
    if not os.path.isdir(cpp_root):
        return [f"Core C++ source root not found: {cpp_root}"], {}

    for dirpath, _, filenames in os.walk(java_root):
        for fn in sorted(filenames):
            if not fn.endswith(".java"):
                continue
            full_path = os.path.join(dirpath, fn)
            rel_path = os.path.relpath(full_path, java_root).replace(os.sep, "/")
            java_files_scanned += 1

            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
            cleaned = strip_c_style_comments(raw)

            file_had_reflection = False
            for api_name, pattern in REFLECTION_PATTERNS.items():
                hit_lines = [
                    _line_number_at(cleaned, m.start())
                    for m in pattern.finditer(cleaned)
                ]
                if hit_lines:
                    file_had_reflection = True
                    key = (rel_path, api_name)
                    observed_counts[key] = len(hit_lines)
                    if key not in allowlist:
                        errors.append(
                            f"Unregistered reflection '{api_name}' in {rel_path} "
                            f"(lines {hit_lines}): register in REFLECTION_ALLOWLIST "
                            "with a documented degradation strategy or remove reflection."
                        )
                    else:
                        expected = allowlist[key]["count"]
                        if len(hit_lines) != expected:
                            errors.append(
                                f"Reflection count drift for '{api_name}' in {rel_path}: "
                                f"found {len(hit_lines)} (lines {hit_lines}), allowlisted {expected}."
                            )

            if file_had_reflection and not CATCH_GUARD_RE.search(cleaned):
                errors.append(
                    f"Reflection in {rel_path} lacks exception-handling catch guard."
                )

            # D66: HMA / threat probes must not reflectively load blocked Android 12-16 hidden APIs.
            if rel_path.startswith("com/wsttxm/riskenginesdk/detector/probe/threat/"):
                for m in FORBIDDEN_HMA_HIDDEN_API_RE.finditer(cleaned):
                    lineno = _line_number_at(cleaned, m.start())
                    errors.append(
                        f"Blocked hidden-API reference in threat probe {rel_path}:{lineno}: "
                        f"{_snippet_at(cleaned, m.start())}"
                    )

            # UI presentation / display-text branching boundary checks (multiline-safe).
            for m in FORBIDDEN_UI_IMPORT_RE.finditer(cleaned):
                lineno = _line_number_at(cleaned, m.start())
                errors.append(
                    f"Core Java source references forbidden UI/presentation symbol "
                    f"at {rel_path}:{lineno}: {_snippet_at(cleaned, m.start())}"
                )
            for m in FORBIDDEN_TEXT_BRANCH_RE.finditer(cleaned):
                lineno = _line_number_at(cleaned, m.start())
                errors.append(
                    f"Core Java source branches on UI display text/prose summary "
                    f"at {rel_path}:{lineno}: {_snippet_at(cleaned, m.start())}"
                )
            for m in CJK_LITERAL_RE.finditer(cleaned):
                lineno = _line_number_at(cleaned, m.start())
                errors.append(
                    f"Core Java source contains localized CJK string literal "
                    f"(display text belongs in Demo/UI layer) at {rel_path}:{lineno}: "
                    f"{_snippet_at(cleaned, m.start())}"
                )

    # Check for stale allowlist entries whose files/calls no longer exist.
    for key, meta in sorted(allowlist.items()):
        if key not in observed_counts:
            errors.append(
                f"Stale REFLECTION_ALLOWLIST entry {key} (expected {meta['count']} calls, found 0)."
            )

    for dirpath, _, filenames in os.walk(cpp_root):
        for fn in sorted(filenames):
            if not fn.endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
                continue
            full_path = os.path.join(dirpath, fn)
            rel_path = os.path.relpath(full_path, cpp_root).replace(os.sep, "/")
            cpp_files_scanned += 1

            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
            cleaned = strip_c_style_comments(raw)
            for m in FORBIDDEN_TEXT_BRANCH_RE.finditer(cleaned):
                lineno = _line_number_at(cleaned, m.start())
                errors.append(
                    f"Core C++ source branches on UI display text at {rel_path}:{lineno}: "
                    f"{_snippet_at(cleaned, m.start())}"
                )
            for m in CJK_LITERAL_RE.finditer(cleaned):
                lineno = _line_number_at(cleaned, m.start())
                errors.append(
                    f"Core C++ source contains localized CJK string literal "
                    f"at {rel_path}:{lineno}: {_snippet_at(cleaned, m.start())}"
                )
            for lineno, line in enumerate(cleaned.splitlines(), 1):
                if "sanitize_maps_path" in line:
                    errors.append(
                        f"Forbidden legacy comma-protocol helper 'sanitize_maps_path' "
                        f"found at {rel_path}:{lineno}"
                    )

    stats = {
        "java_files": java_files_scanned,
        "cpp_files": cpp_files_scanned,
        "allowlist_entries": len(allowlist),
        "reflection_sites": sum(observed_counts.values()),
    }
    return errors, stats


def main(argv=None) -> int:
    repo_default = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    parser = argparse.ArgumentParser(
        description="CI Static Gate 5: Reflection Allowlist & UI Display Text Boundary Audit"
    )
    parser.add_argument("--repo-root", default=repo_default)
    parser.add_argument("--java-root", default="")
    parser.add_argument("--cpp-root", default="")
    args = parser.parse_args(argv)

    java_root = args.java_root or os.path.join(
        args.repo_root, "riskengine-sdk", "src", "main", "java"
    )
    cpp_root = args.cpp_root or os.path.join(
        args.repo_root, "riskengine-sdk", "src", "main", "cpp"
    )

    errors, stats = audit_core_boundaries(java_root, cpp_root)
    if errors:
        print("REFLECTION & BOUNDARY GUARD GATE FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        f"==> Gate 5 (Reflection & Text-Protocol Boundary): PASS "
        f"({stats['java_files']} Java + {stats['cpp_files']} C++ files, "
        f"{stats['reflection_sites']} audited reflection sites across {stats['allowlist_entries']} allowlist entries)"
    )
    return 0


if __name__ == "__main__":
    if main() != 0:
        raise RuntimeError("Reflection and boundary guard gate failed")
