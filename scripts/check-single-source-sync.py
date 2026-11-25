#!/usr/bin/env python3
"""
CI Static Gate 3 — Single-Source Sync Validator.

Verifies:
  1. riskengine-sdk/src/main/AndroidManifest.xml declares ZERO <uses-permission>.
  2. AndroidManifest.xml <queries> stays in exact 1:1 sync with:
       - artifact_paths.ini [emulator_packages], [cloud_packages], [threat_app_packages]
       - NetworkRiskDetector.KNOWN_PROXY_TOOL_CERT_SHA256 package keys
  3. Generated DetectionLists.java arrays stay in exact sync with artifact_paths.ini sections.
  4. gradle.properties riskEngineVersion stays aligned with README.md and README_zh.md.
"""

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

INI_TO_JAVA_ARRAY = {
    "su": "SU_PATHS",
    "magisk": "MAGISK_PATHS",
    "kernelsu": "KERNELSU_PATHS",
    "apatch": "APATCH_PATHS",
    "modules": "MODULE_PATHS",
    "emulator_packages": "EMULATOR_PACKAGES",
    "cloud_packages": "CLOUD_PACKAGES",
    "threat_app_packages": "THREAT_APP_PACKAGES",
    "tamper_tool_paths": "TAMPER_TOOL_PATHS",
    "properties": "ALLOWED_PROPERTIES",
    "partition_fingerprint_properties": "PARTITION_FINGERPRINT_PROPERTIES",
    "cloud_phone_properties": "CLOUD_PHONE_PROPERTIES",
    "virtual_gpu_markers": "VIRTUAL_GPU_MARKERS",
}


def parse_artifact_ini(ini_path: str) -> dict:
    sections = {}
    current = None
    with open(ini_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                sections.setdefault(current, [])
            elif current is not None:
                sections[current].append(line)
    return sections


def parse_manifest_queries_and_permissions(manifest_path: str) -> tuple:
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    uses_perms = []
    for elem in root.findall("uses-permission"):
        uses_perms.append(elem.attrib.get(ANDROID_NS + "name", "<unnamed>"))
    queries = []
    for q in root.findall("queries"):
        for pkg in q.findall("package"):
            name = pkg.attrib.get(ANDROID_NS + "name", "").strip()
            if name:
                queries.append(name)
    return queries, uses_perms


def parse_proxy_tool_packages(network_detector_path: str) -> list:
    with open(network_detector_path, "r", encoding="utf-8") as f:
        src = f.read()
    # Extract map.put("<pkg>", ...) inside KNOWN_PROXY_TOOL_CERT_SHA256 static initializer
    m_block = re.search(r"KNOWN_PROXY_TOOL_CERT_SHA256;.*?static\s*\{(.*?)\n\s*\}", src, re.DOTALL)
    if not m_block:
        raise ValueError(f"Could not locate KNOWN_PROXY_TOOL_CERT_SHA256 static block in {network_detector_path}")
    block = m_block.group(1)
    return re.findall(r'map\.put\(\s*"([^"]+)"\s*,', block)


def _xorshift_mix_u32(val: int) -> int:
    val &= 0xFFFFFFFF
    val = (val ^ ((val << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
    val = (val ^ (val >> 17)) & 0xFFFFFFFF
    val = (val ^ ((val << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return 0x9E3779B9 if val == 0 else val


def _decode_obf_entry(seed: int, hex_str: str) -> str:
    raw = bytes.fromhex(hex_str)
    state = _xorshift_mix_u32(((seed * 0x01000193) ^ (len(raw) * 0x9E3779B9)) & 0xFFFFFFFF)
    out = bytearray(len(raw))
    for i, b in enumerate(raw):
        state = _xorshift_mix_u32(state)
        out[i] = b ^ (state & 0xFF)
    return out.decode("utf-8")


def parse_java_string_array(java_src: str, array_name: str) -> list:
    obf_pattern = re.compile(
        rf"public\s+static\s+final\s+String\[\]\s+{re.escape(array_name)}\s*=\s*"
        rf"ObfuscatedLists\.decode\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*new\s+String\[\]\s*\{{(.*?)\}}\s*\)\s*;",
        re.DOTALL,
    )
    m_obf = obf_pattern.search(java_src)
    if m_obf:
        seed = int(m_obf.group(1), 0)
        encoded_items = re.findall(r'"([^"]*)"', m_obf.group(2))
        return [_decode_obf_entry(seed + idx, item) for idx, item in enumerate(encoded_items)]

    plain_pattern = re.compile(
        rf"public\s+static\s+final\s+String\[\]\s+{re.escape(array_name)}\s*=\s*\{{(.*?)\}}\s*;",
        re.DOTALL,
    )
    m_plain = plain_pattern.search(java_src)
    if m_plain:
        return re.findall(r'"([^"]*)"', m_plain.group(1))

    raise ValueError(f"Array {array_name} not found in DetectionLists.java")


def read_gradle_properties(props_path: str) -> dict:
    props = {}
    with open(props_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    return props


def validate_single_source(
    ini_path: str,
    manifest_path: str,
    network_detector_path: str,
    detection_lists_java_path: str,
    gradle_props_path: str,
    readme_paths: list,
) -> tuple:
    errors = []

    for label, path in [
        ("artifact_paths.ini", ini_path),
        ("AndroidManifest.xml", manifest_path),
        ("NetworkRiskDetector.java", network_detector_path),
        ("DetectionLists.java", detection_lists_java_path),
        ("gradle.properties", gradle_props_path),
    ]:
        if not os.path.isfile(path):
            errors.append(f"{label} not found: {path}")
    if errors:
        return errors, {}

    ini = parse_artifact_ini(ini_path)
    manifest_queries, uses_perms = parse_manifest_queries_and_permissions(manifest_path)

    # 1. Zero <uses-permission>
    if uses_perms:
        errors.append(f"{manifest_path} MUST declare zero <uses-permission>; found: {uses_perms}")

    # 2. Exact <queries> 1:1 sync
    proxy_pkgs = parse_proxy_tool_packages(network_detector_path)
    expected_queries = (
        set(ini.get("emulator_packages", []))
        | set(ini.get("cloud_packages", []))
        | set(ini.get("threat_app_packages", []))
        | set(proxy_pkgs)
    )
    actual_queries = set(manifest_queries)
    if len(manifest_queries) != len(actual_queries):
        errors.append(f"Duplicate <package> entries inside <queries> in {manifest_path}")

    missing_q = sorted(expected_queries - actual_queries)
    extra_q = sorted(actual_queries - expected_queries)
    if missing_q:
        errors.append(f"AndroidManifest.xml <queries> missing packages from single-source lists: {missing_q}")
    if extra_q:
        errors.append(f"AndroidManifest.xml <queries> contains untracked packages not in single-source lists: {extra_q}")

    # 3. Generated DetectionLists.java exact sync with artifact_paths.ini
    with open(detection_lists_java_path, "r", encoding="utf-8") as f:
        java_src = f.read()
    for section, array_name in INI_TO_JAVA_ARRAY.items():
        if section not in ini:
            errors.append(f"Missing section [{section}] in {ini_path}")
            continue
        try:
            java_vals = parse_java_string_array(java_src, array_name)
        except Exception as exc:
            errors.append(str(exc))
            continue
        if java_vals != ini[section]:
            errors.append(
                f"DetectionLists.{array_name} drifted from artifact_paths.ini [{section}] "
                f"(java={len(java_vals)}, ini={len(ini[section])})"
            )

    # 4. gradle.properties & README version consistency
    props = read_gradle_properties(gradle_props_path)
    version = props.get("riskEngineVersion", "")
    if not version:
        errors.append(f"riskEngineVersion missing from {gradle_props_path}")
    else:
        for readme in readme_paths:
            if not os.path.isfile(readme):
                errors.append(f"Documentation file not found for version check: {readme}")
                continue
            with open(readme, "r", encoding="utf-8") as f:
                text = f.read()
            if version not in text:
                errors.append(
                    f"Version drift: {readme} does not mention gradle.properties riskEngineVersion '{version}'"
                )

    stats = {
        "queries": len(actual_queries),
        "ini_sections": len(INI_TO_JAVA_ARRAY),
        "version": version,
    }
    return errors, stats


def main(argv: list = None) -> int:
    repo_default = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    parser = argparse.ArgumentParser(description="Verify single-source <queries>, DetectionLists, and version sync.")
    parser.add_argument("--repo-root", default=repo_default)
    parser.add_argument("--ini", default="")
    parser.add_argument("--manifest", default="")
    parser.add_argument("--network-detector", default="")
    parser.add_argument("--detection-lists-java", default="")
    parser.add_argument("--gradle-props", default="")
    parser.add_argument("--readme", default="")
    parser.add_argument("--readme-zh", default="")
    args = parser.parse_args(argv)

    ini_path = args.ini or os.path.join(
        args.repo_root, "riskengine-sdk", "src", "main", "resources", "lists", "artifact_paths.ini"
    )
    manifest_path = args.manifest or os.path.join(
        args.repo_root, "riskengine-sdk", "src", "main", "AndroidManifest.xml"
    )
    network_detector = args.network_detector or os.path.join(
        args.repo_root,
        "riskengine-sdk", "src", "main", "java",
        "com", "wsttxm", "riskenginesdk", "detector", "NetworkRiskDetector.java",
    )
    detection_lists = args.detection_lists_java or os.path.join(
        args.repo_root,
        "riskengine-sdk", "src", "main", "java",
        "com", "wsttxm", "riskenginesdk", "generated", "DetectionLists.java",
    )
    gradle_props = args.gradle_props or os.path.join(args.repo_root, "gradle.properties")
    readme_en = args.readme or os.path.join(args.repo_root, "README.md")
    readme_zh = args.readme_zh or os.path.join(args.repo_root, "README_zh.md")

    errors, stats = validate_single_source(
        ini_path=ini_path,
        manifest_path=manifest_path,
        network_detector_path=network_detector,
        detection_lists_java_path=detection_lists,
        gradle_props_path=gradle_props,
        readme_paths=[readme_en, readme_zh],
    )
    if errors:
        print("SINGLE-SOURCE SYNC GATE FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        f"==> Gate 3 (Single-Source Sync): PASS "
        f"(<queries>={stats['queries']} exact 1:1, {stats['ini_sections']} lists synced, version={stats['version']})"
    )
    return 0


if __name__ == "__main__":
    if main() != 0:
        raise RuntimeError("Single-source sync validation failed")
