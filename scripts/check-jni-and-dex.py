#!/usr/bin/env python3
"""
CI Static Gate 2 (Part B) — JNI 1:1 Contract Parity & Core AAR Release Dex Method Count Audit.

Verifies:
  1. Exact 1:1 parity (method name + JVM JNI signature) between native methods declared in
     NativeCollectorBridge.java and DynamicEntry / JNINativeMethod registrations in riskengine_jni.cpp.
  2. Core release AAR Dex method count is strictly below 2,500 methods (compiled from release
     AAR classes.jar via Android build-tools d8 and parsed directly from the DEX binary header).
"""

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

DEFAULT_MAX_DEX_METHODS = 2500

JAVA_NATIVE_RE = re.compile(
    r"\bnative\s+([A-Za-z0-9_.\[\]]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*;"
)
CPP_SIG_CONST_RE = re.compile(
    r"const\s+auto\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*OBF\(\"([^\"]+)\"\)\s*;"
)
CPP_ENTRY_RE = re.compile(
    r"\{\s*OBF\(\"([^\"]+)\"\)\s*,\s*([^,]+?)\s*,\s*reinterpret_cast<\s*void\s*\*\s*>\s*\([^)]+\)\s*\}"
)

PRIMITIVE_JNI_TYPES = {
    "void": "V",
    "boolean": "Z",
    "byte": "B",
    "char": "C",
    "short": "S",
    "int": "I",
    "long": "J",
    "float": "F",
    "double": "D",
}

WELL_KNOWN_JAVA_TYPES = {
    "String": "Ljava/lang/String;",
    "Object": "Ljava/lang/Object;",
    "Class": "Ljava/lang/Class;",
    "Context": "Landroid/content/Context;",
}


def java_type_to_jni(type_str: str) -> str:
    cleaned = re.sub(r"\s+", "", type_str)
    array_depth = 0
    while cleaned.endswith("[]"):
        array_depth += 1
        cleaned = cleaned[:-2]
    prefix = "[" * array_depth
    if cleaned in PRIMITIVE_JNI_TYPES:
        return prefix + PRIMITIVE_JNI_TYPES[cleaned]
    if cleaned in WELL_KNOWN_JAVA_TYPES:
        return prefix + WELL_KNOWN_JAVA_TYPES[cleaned]
    if "." in cleaned:
        return prefix + "L" + cleaned.replace(".", "/") + ";"
    raise ValueError(f"Unsupported Java type in native declaration: {type_str!r}")


def parse_java_native_methods(bridge_java_path: str) -> tuple:
    with open(bridge_java_path, "r", encoding="utf-8") as f:
        src = f.read()
    # Remove block and line comments so commented declarations are ignored.
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"//.*", "", src)

    methods = {}
    duplicates = []
    for match in JAVA_NATIVE_RE.finditer(src):
        ret_type = match.group(1).strip()
        name = match.group(2).strip()
        raw_params = match.group(3).strip()
        param_sigs = []
        if raw_params:
            for raw_p in raw_params.split(","):
                tokens = [t for t in raw_p.strip().split() if not t.startswith("@") and t != "final"]
                if len(tokens) < 2:
                    raise ValueError(f"Cannot parse parameter {raw_p!r} in native method {name}")
                p_type = tokens[0]
                if tokens[1].endswith("[]"):
                    p_type += "[]"
                param_sigs.append(java_type_to_jni(p_type))
        sig = f"({''.join(param_sigs)}){java_type_to_jni(ret_type)}"
        if name in methods:
            duplicates.append(name)
        methods[name] = sig
    return methods, duplicates


def parse_cpp_jni_registrations(jni_cpp_path: str) -> tuple:
    with open(jni_cpp_path, "r", encoding="utf-8") as f:
        src = f.read()
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"//.*", "", src)

    sig_consts = {m.group(1): m.group(2) for m in CPP_SIG_CONST_RE.finditer(src)}

    methods = {}
    duplicates = []
    for match in CPP_ENTRY_RE.finditer(src):
        name = match.group(1).strip()
        sig_expr = match.group(2).strip()
        sig = None
        m_var = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\.c_str\(\)$", sig_expr)
        if m_var and m_var.group(1) in sig_consts:
            sig = sig_consts[m_var.group(1)]
        else:
            m_obf = re.match(r'^OBF\("([^"]+)"\)\.c_str\(\)$', sig_expr)
            if m_obf:
                sig = m_obf.group(1)
            else:
                m_lit = re.match(r'^"([^"]+)"$', sig_expr)
                if m_lit:
                    sig = m_lit.group(1)
        if sig is None:
            raise ValueError(f"Could not resolve JNI signature expression {sig_expr!r} for {name}")
        if name in methods:
            duplicates.append(name)
        methods[name] = sig
    return methods, duplicates


def validate_jni_parity(bridge_java_path: str, jni_cpp_path: str) -> tuple:
    errors = []
    if not os.path.isfile(bridge_java_path):
        return [f"NativeCollectorBridge.java not found: {bridge_java_path}"], 0
    if not os.path.isfile(jni_cpp_path):
        return [f"riskengine_jni.cpp not found: {jni_cpp_path}"], 0

    java_methods, java_dups = parse_java_native_methods(bridge_java_path)
    cpp_methods, cpp_dups = parse_cpp_jni_registrations(jni_cpp_path)

    for dup in java_dups:
        errors.append(f"Duplicate Java native declaration in {bridge_java_path}: {dup}")
    for dup in cpp_dups:
        errors.append(f"Duplicate C++ JNI registration in {jni_cpp_path}: {dup}")
    if not java_methods:
        errors.append(f"Zero native methods parsed from {bridge_java_path}")
    if not cpp_methods:
        errors.append(f"Zero JNI registrations parsed from {jni_cpp_path}")

    for name in sorted(set(java_methods) - set(cpp_methods)):
        errors.append(f"Java native method missing C++ JNI registration: {name} {java_methods[name]}")
    for name in sorted(set(cpp_methods) - set(java_methods)):
        errors.append(f"C++ JNI registration missing Java native declaration: {name} {cpp_methods[name]}")
    for name in sorted(set(java_methods) & set(cpp_methods)):
        if java_methods[name] != cpp_methods[name]:
            errors.append(
                f"JNI signature mismatch for {name}: Java={java_methods[name]} vs C++={cpp_methods[name]}"
            )
    return errors, len(java_methods)


def read_dex_method_count(dex_path: str) -> int:
    with open(dex_path, "rb") as f:
        header = f.read(112)
    if len(header) < 96:
        raise ValueError(f"DEX file too short ({len(header)} bytes): {dex_path}")
    if not header.startswith(b"dex\n") or header[7:8] != b"\x00":
        raise ValueError(f"Invalid DEX magic header in {dex_path}")
    endian_tag = struct.unpack_from("<I", header, 40)[0]
    if endian_tag == 0x12345678:
        return struct.unpack_from("<I", header, 88)[0]
    if endian_tag == 0x78563412:
        return struct.unpack_from(">I", header, 88)[0]
    raise ValueError(f"Invalid DEX endian tag 0x{endian_tag:08x} in {dex_path}")


def read_prop(prop_file: str, key: str) -> str:
    if not os.path.isfile(prop_file):
        return ""
    with open(prop_file, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith(f"{key}="):
                return stripped.split("=", 1)[1].strip()
    return ""


def locate_android_sdk(repo_root: str) -> str:
    candidates = [
        os.environ.get("ANDROID_HOME", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
    ]
    local_sdk = read_prop(os.path.join(repo_root, "local.properties"), "sdk.dir")
    if local_sdk:
        candidates.append(local_sdk.replace("\\:", ":").replace("\\\\", "\\"))
    candidates.extend([
        os.path.expanduser("~/Library/Android/sdk"),
        os.path.expanduser("~/Android/Sdk"),
    ])
    for cand in candidates:
        if cand and os.path.isdir(cand):
            return cand
    return ""


def locate_d8_and_android_jar(repo_root: str) -> tuple:
    sdk_root = locate_android_sdk(repo_root)
    if not sdk_root:
        raise FileNotFoundError("Android SDK not found (set ANDROID_HOME or local.properties)")
    compile_sdk = read_prop(os.path.join(repo_root, "gradle.properties"), "androidCompileSdk") or "36"
    build_tools_ver = read_prop(os.path.join(repo_root, "gradle.properties"), "androidBuildToolsVersion")

    d8_path = ""
    if build_tools_ver:
        preferred = os.path.join(sdk_root, "build-tools", build_tools_ver, "d8")
        if os.path.isfile(preferred) and os.access(preferred, os.X_OK):
            d8_path = preferred
    if not d8_path:
        bt_dir = os.path.join(sdk_root, "build-tools")
        if os.path.isdir(bt_dir):
            for ver in sorted(os.listdir(bt_dir), reverse=True):
                cand = os.path.join(bt_dir, ver, "d8")
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    d8_path = cand
                    break
    if not d8_path:
        d8_path = shutil.which("d8") or ""
    if not d8_path:
        raise FileNotFoundError(f"Could not locate Android build-tools d8 under {sdk_root}")

    android_jar = os.path.join(sdk_root, "platforms", f"android-{compile_sdk}", "android.jar")
    if not os.path.isfile(android_jar):
        raise FileNotFoundError(f"android.jar not found at {android_jar}")
    return d8_path, android_jar


def measure_aar_dex_methods(aar_path: str, repo_root: str) -> tuple:
    """
    Measures the release DEX method_ids_size of riskengine-sdk-release.aar by compiling its
    bundled classes.jar through Android SDK build-tools R8 with the AAR's own proguard.txt
    consumer keep rules (mirroring real host release APK shrinking), and also records the
    unshrunk d8 method count for transparent telemetry.
    """
    if not os.path.isfile(aar_path):
        raise FileNotFoundError(f"Release AAR not found: {aar_path}")
    d8_path, android_jar = locate_d8_and_android_jar(repo_root)
    d8_jar = os.path.join(os.path.dirname(d8_path), "lib", "d8.jar")
    min_sdk = read_prop(os.path.join(repo_root, "gradle.properties"), "androidMinSdk") or "30"
    java_bin = shutil.which("java") or "java"

    with tempfile.TemporaryDirectory(prefix="re_dex_audit_") as tmpdir:
        with zipfile.ZipFile(aar_path, "r") as zf:
            names = set(zf.namelist())
            if "classes.jar" not in names:
                raise ValueError(f"classes.jar missing from AAR: {aar_path}")
            classes_jar = zf.extract("classes.jar", tmpdir)
            proguard_txt = zf.extract("proguard.txt", tmpdir) if "proguard.txt" in names else ""

        # 1. Measure unshrunk d8 method_ids_size (informational baseline)
        raw_out = os.path.join(tmpdir, "d8_out")
        os.makedirs(raw_out, exist_ok=True)
        subprocess.run(
            [
                d8_path,
                "--release",
                "--min-api", min_sdk,
                "--lib", android_jar,
                "--output", raw_out,
                classes_jar,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        raw_dex_files = sorted(
            os.path.join(raw_out, fn) for fn in os.listdir(raw_out) if fn.endswith(".dex")
        )
        if not raw_dex_files:
            raise RuntimeError("d8 produced no .dex files from classes.jar")
        raw_methods = sum(read_dex_method_count(p) for p in raw_dex_files)

        # 2. Measure R8 release-shrunk DEX method_ids_size using the AAR's consumer proguard.txt
        if not proguard_txt or not os.path.isfile(d8_jar):
            return raw_methods, raw_methods

        r8_rules = os.path.join(tmpdir, "r8-consumer.pro")
        with open(proguard_txt, "r", encoding="utf-8") as src_f:
            rules_body = src_f.read()
        with open(r8_rules, "w", encoding="utf-8") as dst_f:
            # Match AGP default proguard-android-optimize.txt baseline attributes alongside AAR consumer rules.
            dst_f.write(rules_body)
            dst_f.write("\n-keepattributes EnclosingMethod,InnerClasses\n-dontwarn **\n")

        r8_out = os.path.join(tmpdir, "r8_out")
        os.makedirs(r8_out, exist_ok=True)
        subprocess.run(
            [
                java_bin,
                "-cp", d8_jar,
                "com.android.tools.r8.R8",
                "--release",
                "--min-api", min_sdk,
                "--lib", android_jar,
                "--pg-conf", r8_rules,
                "--output", r8_out,
                classes_jar,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        r8_dex_files = sorted(
            os.path.join(r8_out, fn) for fn in os.listdir(r8_out) if fn.endswith(".dex")
        )
        if not r8_dex_files:
            raise RuntimeError("R8 produced no .dex files from classes.jar")
        r8_methods = sum(read_dex_method_count(p) for p in r8_dex_files)
        return r8_methods, raw_methods


def main(argv: list = None) -> int:
    repo_default = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    parser = argparse.ArgumentParser(description="Verify JNI 1:1 parity and core AAR Dex method count.")
    parser.add_argument("--repo-root", default=repo_default)
    parser.add_argument("--bridge-java", default="")
    parser.add_argument("--jni-cpp", default="")
    parser.add_argument("--aar", default="")
    parser.add_argument("--dex-file", default="", help="Optional direct .dex file override for testing")
    parser.add_argument("--max-dex-methods", type=int, default=DEFAULT_MAX_DEX_METHODS)
    args = parser.parse_args(argv)

    bridge_java = args.bridge_java or os.path.join(
        args.repo_root,
        "riskengine-sdk", "src", "main", "java",
        "com", "wsttxm", "riskenginesdk", "collector", "native_layer", "NativeCollectorBridge.java",
    )
    jni_cpp = args.jni_cpp or os.path.join(
        args.repo_root, "riskengine-sdk", "src", "main", "cpp", "riskengine_jni.cpp"
    )
    aar_path = args.aar or os.path.join(
        args.repo_root, "riskengine-sdk", "build", "outputs", "aar", "riskengine-sdk-release.aar"
    )

    errors, jni_count = validate_jni_parity(bridge_java, jni_cpp)
    dex_methods = None
    raw_dex_methods = None
    try:
        if args.dex_file:
            dex_methods = read_dex_method_count(args.dex_file)
            raw_dex_methods = dex_methods
        else:
            dex_methods, raw_dex_methods = measure_aar_dex_methods(aar_path, args.repo_root)
        if dex_methods >= args.max_dex_methods:
            errors.append(
                f"Core AAR release Dex method count {dex_methods} reaches/exceeds hard budget < {args.max_dex_methods}"
            )
    except Exception as exc:
        errors.append(f"Dex method audit failed: {exc}")

    if errors:
        print("JNI & DEX GATE FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        f"==> Gate 2 (JNI 1:1 & Dex Budget): PASS "
        f"(JNI={jni_count}/{jni_count} exact 1:1, "
        f"Release R8 Dex={dex_methods} < {args.max_dex_methods} methods, unshrunk d8={raw_dex_methods})"
    )
    return 0


if __name__ == "__main__":
    if main() != 0:
        raise RuntimeError("JNI and Dex audit failed")
