#!/usr/bin/env python3
"""
CI Static Gate 4 — Zero-Plugin javap Public ABI Lock & AAR Dependency Purity Audit.

Extracts deterministic, sorted public/protected class, method, and field signatures
from the release AAR's classes.jar using JDK 17 `javap` (zero third-party Gradle plugins
required, fully offline and configuration-cache friendly), then:
  1. In `dump` mode: writes the canonical snapshot to `riskengine-sdk/api/riskengine-sdk.api`.
  2. In `check` mode: enforces an exact diff against `riskengine-sdk/api/riskengine-sdk.api`.
  3. Always validates AAR `classes.jar` & release POM purity:
     - Zero classes outside `com/wsttxm/riskenginesdk/` (no shaded/bundled 3rd-party deps).
     - Zero UI/Activity/Fragment/View/Compose/Demo classes or non-empty `R.txt` resources.
     - Zero `<dependency>` elements in `pom-default.xml`.
"""

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

ALLOWED_CLASS_PREFIX = "com/wsttxm/riskenginesdk/"
ALLOWED_RESOURCE_ENTRIES = {
    "lists/artifact_paths.ini",
}
FORBIDDEN_CLASS_SUBSTRINGS = (
    "com/wsttxm/riskenginesdk/demo/",
    "androidx/",
    "android/support/",
    "com/google/android/material/",
    "kotlin/",
    "kotlinx/",
    "okhttp3/",
    "retrofit2/",
    "org/json/",
)
FORBIDDEN_SUPER_OR_IFACE = (
    "android.app.Activity",
    "android.app.Fragment",
    "android.app.Dialog",
    "android.view.View",
    "android.widget.",
    "androidx.fragment.",
    "androidx.appcompat.",
    "androidx.compose.",
)
CLASS_HEADER_RE = re.compile(
    r"^(public|protected)\s+.*?(?:@interface|\b(?:class|interface|enum))\s+([^\s<{]+)"
)
ANY_CLASS_HEADER_RE = re.compile(
    r"^.*?(?:@interface|\b(?:class|interface|enum))\s+([^\s<{]+)\s*.*\{$"
)
ANON_CLASS_PART_RE = re.compile(r"^\d+$")


def resolve_javap(explicit_javap: str = "") -> str:
    if explicit_javap:
        if os.path.isfile(explicit_javap):
            return explicit_javap
        raise FileNotFoundError(f"Explicit javap path does not exist: {explicit_javap}")
    java_home = os.environ.get("JAVA_HOME", "")
    if java_home:
        candidate = os.path.join(java_home, "bin", "javap")
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which("javap")
    if found:
        return found
    raise FileNotFoundError("Could not locate JDK javap executable (set JAVA_HOME or --javap)")


def is_named_class_entry(entry: str) -> bool:
    if not entry.endswith(".class"):
        return False
    base = entry[:-6]
    if base.endswith("/package-info") or base == "package-info" or base == "module-info":
        return False
    parts = base.split("$")
    for part in parts[1:]:
        if ANON_CLASS_PART_RE.match(part):
            return False
    return True


def audit_aar_purity(aar_path: str) -> list:
    errors = []
    if not os.path.isfile(aar_path):
        return [f"Release AAR not found: {aar_path}"]

    with zipfile.ZipFile(aar_path, "r") as aar_zip:
        names = set(aar_zip.namelist())
        if "classes.jar" not in names:
            return [f"Release AAR is missing classes.jar: {aar_path}"]

        if "R.txt" in names:
            r_txt = aar_zip.read("R.txt").decode("utf-8", errors="replace").strip()
            if r_txt:
                errors.append(
                    f"Core SDK AAR R.txt must be empty (no UI resources), found: {r_txt.splitlines()[0]}"
                )

        for entry in sorted(names):
            if entry.startswith("res/") and not entry.endswith("/"):
                errors.append(f"Core SDK AAR must not bundle UI resources under res/: {entry}")
            if entry.startswith("libs/") and entry.endswith(".jar"):
                errors.append(f"Core SDK AAR must not bundle third-party jar under libs/: {entry}")

        with tempfile.TemporaryDirectory(prefix="riskengine_api_purity_") as tmp_dir:
            classes_jar_path = os.path.join(tmp_dir, "classes.jar")
            with open(classes_jar_path, "wb") as f:
                f.write(aar_zip.read("classes.jar"))
            with zipfile.ZipFile(classes_jar_path, "r") as jar_zip:
                for entry in sorted(jar_zip.namelist()):
                    if entry.endswith("/"):
                        continue
                    if entry.startswith("META-INF/"):
                        continue
                    if entry.endswith(".class"):
                        for forbidden in FORBIDDEN_CLASS_SUBSTRINGS:
                            if forbidden in entry:
                                errors.append(
                                    f"Forbidden third-party or UI class in classes.jar: {entry}"
                                )
                                break
                        if not entry.startswith(ALLOWED_CLASS_PREFIX):
                            errors.append(
                                f"Unauthorized non-SDK class in classes.jar: {entry}"
                            )
                    else:
                        if entry not in ALLOWED_RESOURCE_ENTRIES:
                            errors.append(
                                f"Unexpected non-class resource in classes.jar: {entry}"
                            )
    return errors


def audit_pom_purity(pom_path: str) -> list:
    errors = []
    if not os.path.isfile(pom_path):
        return [f"Release POM not found: {pom_path}"]

    try:
        tree = ET.parse(pom_path)
    except ET.ParseError as exc:
        return [f"Failed to parse POM XML {pom_path}: {exc}"]

    root = tree.getroot()

    def local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    group_id = ""
    artifact_id = ""
    packaging = ""
    deps = []

    for child in root:
        tag = local_name(child.tag)
        if tag == "groupId":
            group_id = (child.text or "").strip()
        elif tag == "artifactId":
            artifact_id = (child.text or "").strip()
        elif tag == "packaging":
            packaging = (child.text or "").strip()
        elif tag == "dependencies":
            for dep in child:
                if local_name(dep.tag) == "dependency":
                    dep_g = ""
                    dep_a = ""
                    dep_v = ""
                    for field in dep:
                        ft = local_name(field.tag)
                        if ft == "groupId":
                            dep_g = (field.text or "").strip()
                        elif ft == "artifactId":
                            dep_a = (field.text or "").strip()
                        elif ft == "version":
                            dep_v = (field.text or "").strip()
                    deps.append(f"{dep_g}:{dep_a}:{dep_v}")

    if group_id != "com.wsttxm":
        errors.append(f"Unexpected POM groupId '{group_id}' (expected 'com.wsttxm')")
    if artifact_id != "riskengine-sdk":
        errors.append(f"Unexpected POM artifactId '{artifact_id}' (expected 'riskengine-sdk')")
    if packaging != "aar":
        errors.append(f"Unexpected POM packaging '{packaging}' (expected 'aar')")
    if deps:
        errors.append(
            f"Core :riskengine-sdk POM must have 0 runtime dependencies, found: {deps}"
        )

    return errors


def parse_javap_blocks(javap_output: str) -> tuple:
    """
    Parse `javap -protected` output into:
      (public_protected_blocks: dict[class_name, (header_line, sorted_member_lines)],
       all_headers: list[str])
    """
    blocks = {}
    all_headers = []
    current_cls = None
    current_header = None
    current_members = []
    in_block = False

    for raw_line in javap_output.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("Compiled from "):
            continue
        if not in_block:
            if line.endswith("{"):
                if ANY_CLASS_HEADER_RE.match(line):
                    all_headers.append(line)
                m = CLASS_HEADER_RE.match(line)
                if m:
                    current_cls = m.group(2)
                    current_header = line
                    current_members = []
                else:
                    current_cls = None
                    current_header = None
                    current_members = []
                in_block = True
        else:
            if line == "}":
                if current_cls is not None and current_header is not None:
                    # Exclude static initializer blocks if emitted.
                    filtered = [
                        mem for mem in current_members
                        if mem.strip() != "static {};"
                    ]
                    blocks[current_cls] = (current_header, sorted(filtered))
                current_cls = None
                current_header = None
                current_members = []
                in_block = False
            elif current_cls is not None:
                current_members.append(line)

    return blocks, all_headers


def extract_public_api_from_aar(aar_path: str, javap_bin: str) -> tuple:
    """
    Returns (api_text, ui_header_errors, class_count).
    """
    if not os.path.isfile(aar_path):
        raise FileNotFoundError(f"Release AAR not found: {aar_path}")

    with tempfile.TemporaryDirectory(prefix="riskengine_javap_") as tmp_dir:
        classes_jar_path = os.path.join(tmp_dir, "classes.jar")
        with zipfile.ZipFile(aar_path, "r") as aar_zip:
            with open(classes_jar_path, "wb") as f:
                f.write(aar_zip.read("classes.jar"))

        with zipfile.ZipFile(classes_jar_path, "r") as jar_zip:
            class_names = [
                entry[:-6].replace("/", ".")
                for entry in sorted(jar_zip.namelist())
                if is_named_class_entry(entry)
            ]

        all_blocks = {}
        all_headers = []
        batch_size = 80
        for start in range(0, len(class_names), batch_size):
            batch = class_names[start:start + batch_size]
            cmd = [javap_bin, "-J-Duser.language=en", "-protected", "-cp", classes_jar_path] + batch
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(
                    f"javap failed (rc={proc.returncode}): {proc.stderr.strip()}"
                )
            parsed_blocks, parsed_headers = parse_javap_blocks(proc.stdout)
            all_blocks.update(parsed_blocks)
            all_headers.extend(parsed_headers)

    ui_errors = []
    for header in all_headers:
        for forbidden in FORBIDDEN_SUPER_OR_IFACE:
            if forbidden in header:
                ui_errors.append(
                    f"Core SDK class extends/implements forbidden UI type '{forbidden}': {header}"
                )

    # Filter out nested public/protected classes whose enclosing class is not public/protected.
    reachable = {}
    for cls_name in sorted(all_blocks.keys()):
        parts = cls_name.split("$")
        outer_ok = True
        for depth in range(1, len(parts)):
            enclosing = "$".join(parts[:depth])
            if enclosing not in all_blocks:
                outer_ok = False
                break
        if outer_ok:
            reachable[cls_name] = all_blocks[cls_name]

    out_lines = [
        "// Auto-generated by scripts/check-public-api.py (JDK 17 javap -protected).",
        "// Run `./gradlew :riskengine-sdk:apiDump` after reviewing intentional public ABI changes.",
        "",
    ]

    for cls_name in sorted(reachable.keys()):
        header, members = reachable[cls_name]
        out_lines.append(header)
        for mem in members:
            out_lines.append(mem)
        out_lines.append("}")
        out_lines.append("")

    return "\n".join(out_lines), ui_errors, len(reachable)


def run_gate(
    mode: str,
    aar_path: str,
    api_file: str,
    pom_path: str = "",
    check_pom: bool = True,
    javap_bin: str = "",
) -> tuple:
    """
    Returns (errors: list[str], summary: str).
    """
    errors = []
    errors.extend(audit_aar_purity(aar_path))
    if check_pom:
        errors.extend(audit_pom_purity(pom_path))

    if errors:
        return errors, ""

    resolved_javap = resolve_javap(javap_bin)
    generated_api, ui_errors, class_count = extract_public_api_from_aar(aar_path, resolved_javap)
    errors.extend(ui_errors)
    if errors:
        return errors, ""

    if mode == "dump":
        os.makedirs(os.path.dirname(os.path.abspath(api_file)), exist_ok=True)
        with open(api_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(generated_api)
        return [], f"Dumped {class_count} public/protected types to {api_file}"

    if not os.path.isfile(api_file):
        return [
            f"Public ABI baseline file missing: {api_file}. "
            "Run `./gradlew :riskengine-sdk:apiDump` to create it."
        ], ""

    with open(api_file, "r", encoding="utf-8") as f:
        expected_api = f.read()

    if generated_api != expected_api:
        diff_lines = list(
            difflib.unified_diff(
                expected_api.splitlines(),
                generated_api.splitlines(),
                fromfile=api_file,
                tofile="<current release AAR>",
                lineterm="",
                n=2,
            )
        )
        preview = "\n".join(diff_lines[:120])
        if len(diff_lines) > 120:
            preview += f"\n... ({len(diff_lines) - 120} more diff lines truncated)"
        errors.append(
            "Public ABI mismatch detected against riskengine-sdk.api!\n"
            "If this public API change is intentional, run `./gradlew :riskengine-sdk:apiDump` "
            "and commit the updated riskengine-sdk/api/riskengine-sdk.api.\n"
            + preview
        )
        return errors, ""

    pom_note = "POM 0 deps" if check_pom else "POM check disabled"
    return [], f"{class_count} public/protected types locked, AAR classes.jar pure, {pom_note}"


def main(argv=None) -> int:
    repo_default = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    parser = argparse.ArgumentParser(
        description="CI Static Gate 4: Zero-Plugin javap Public ABI Lock & AAR Purity Audit"
    )
    parser.add_argument("--repo-root", default=repo_default)
    parser.add_argument("--mode", choices=("check", "dump"), default="check")
    parser.add_argument("--aar", default="")
    parser.add_argument("--api-file", default="")
    parser.add_argument("--pom", default="")
    parser.add_argument("--no-pom-check", action="store_true")
    parser.add_argument("--javap", default="")
    args = parser.parse_args(argv)

    aar_path = args.aar or os.path.join(
        args.repo_root,
        "riskengine-sdk", "build", "outputs", "aar", "riskengine-sdk-release.aar",
    )
    api_file = args.api_file or os.path.join(
        args.repo_root, "riskengine-sdk", "api", "riskengine-sdk.api"
    )
    pom_path = args.pom or os.path.join(
        args.repo_root,
        "riskengine-sdk", "build", "publications", "release", "pom-default.xml",
    )

    errors, summary = run_gate(
        mode=args.mode,
        aar_path=aar_path,
        api_file=api_file,
        pom_path=pom_path,
        check_pom=not args.no_pom_check,
        javap_bin=args.javap,
    )
    if errors:
        print("PUBLIC ABI & AAR PURITY GATE FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"==> Gate 4 (Public ABI & AAR Purity): PASS ({summary})")
    return 0


if __name__ == "__main__":
    if main() != 0:
        raise RuntimeError("Public ABI and AAR purity gate failed")
