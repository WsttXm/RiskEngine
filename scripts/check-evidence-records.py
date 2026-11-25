#!/usr/bin/env python3
"""
CI Static Gate 1 — Evidence Contract Record Validator.

Dynamically parses all registered detectors from DetectorRegistry.java, resolves each
detector's canonical runtime name from its getName() implementation, and enforces:
  1. Exact 1:1 parity between registered detectors and docs/evidence/<name>.md files.
  2. Presence of all 7 mandatory contract section headings with non-empty content in every file.
"""

import argparse
import os
import re
import sys

REQUIRED_HEADINGS = [
    "Observable Signals",
    "Producing Subsystem",
    "Mechanism (AOSP/Linux/ACK)",
    "Applicable API Range",
    "Visibility Boundaries",
    "False-Positive Defenses",
    "Result State Mapping",
]

ADD_DETECTOR_RE = re.compile(r"detectors\.add\(\s*new\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RETURN_LITERAL_RE = re.compile(
    r"public\s+String\s+getName\s*\(\s*\)\s*\{\s*return\s+\"([^\"]+)\"\s*;", re.DOTALL
)
RETURN_CONST_RE = re.compile(
    r"public\s+String\s+getName\s*\(\s*\)\s*\{\s*return\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.DOTALL,
)


def parse_registered_detector_classes(registry_path: str) -> list:
    with open(registry_path, "r", encoding="utf-8") as f:
        src = f.read()
    # Strip line comments to avoid matching commented-out detectors.
    cleaned = re.sub(r"//.*", "", src)
    classes = []
    for match in ADD_DETECTOR_RE.finditer(cleaned):
        cls = match.group(1)
        if cls not in classes:
            classes.append(cls)
    return classes


def resolve_detector_name(detectors_dir: str, class_name: str) -> str:
    java_path = os.path.join(detectors_dir, f"{class_name}.java")
    if not os.path.isfile(java_path):
        raise FileNotFoundError(f"Detector source not found for registered class {class_name}: {java_path}")
    with open(java_path, "r", encoding="utf-8") as f:
        src = f.read()
    m_lit = RETURN_LITERAL_RE.search(src)
    if m_lit:
        return m_lit.group(1).strip()
    m_const = RETURN_CONST_RE.search(src)
    if m_const:
        const_name = m_const.group(1)
        const_re = re.compile(
            rf"(?:static\s+final|final\s+static)\s+String\s+{re.escape(const_name)}\s*=\s*\"([^\"]+)\"\s*;"
        )
        m_val = const_re.search(src)
        if m_val:
            return m_val.group(1).strip()
    raise ValueError(f"Could not resolve getName() string in {java_path}")


def parse_markdown_h2_sections(md_text: str) -> dict:
    sections = {}
    current_heading = None
    current_lines = []
    for line in md_text.splitlines():
        m = re.match(r"^##\s+(.+?)\s*$", line)
        if m:
            if current_heading is not None:
                sections[current_heading] = "\n".join(current_lines).strip()
            current_heading = m.group(1).strip()
            current_lines = []
        elif current_heading is not None:
            current_lines.append(line)
    if current_heading is not None:
        sections[current_heading] = "\n".join(current_lines).strip()
    return sections


def validate_evidence_records(registry_path: str, detectors_dir: str, evidence_dir: str) -> list:
    errors = []
    if not os.path.isfile(registry_path):
        return [f"DetectorRegistry not found: {registry_path}"]
    if not os.path.isdir(evidence_dir):
        return [f"Evidence directory not found: {evidence_dir}"]

    classes = parse_registered_detector_classes(registry_path)
    if not classes:
        return [f"No detectors parsed from {registry_path}"]

    expected_names = []
    for cls in classes:
        try:
            name = resolve_detector_name(detectors_dir, cls)
            expected_names.append(name)
        except Exception as exc:
            errors.append(str(exc))

    expected_set = set(expected_names)
    actual_files = {
        fn[:-3]
        for fn in os.listdir(evidence_dir)
        if fn.endswith(".md") and os.path.isfile(os.path.join(evidence_dir, fn))
    }

    missing = sorted(expected_set - actual_files)
    extra = sorted(actual_files - expected_set)
    for name in missing:
        errors.append(f"Missing evidence contract record for registered detector '{name}': {os.path.join(evidence_dir, name + '.md')}")
    for name in extra:
        errors.append(f"Orphaned evidence contract record not registered in DetectorRegistry: {os.path.join(evidence_dir, name + '.md')}")

    for name in sorted(expected_set & actual_files):
        md_path = os.path.join(evidence_dir, f"{name}.md")
        with open(md_path, "r", encoding="utf-8") as f:
            sections = parse_markdown_h2_sections(f.read())
        norm_sections = {k.lower(): (k, v) for k, v in sections.items()}
        for req in REQUIRED_HEADINGS:
            entry = norm_sections.get(req.lower())
            if entry is None:
                errors.append(f"{md_path}: missing mandatory heading '## {req}'")
            elif not entry[1]:
                errors.append(f"{md_path}: empty section body under '## {entry[0]}'")

    return errors


def main(argv: list = None) -> int:
    repo_default = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    parser = argparse.ArgumentParser(description="Validate 1:1 detector Evidence Contract Records.")
    parser.add_argument("--repo-root", default=repo_default)
    parser.add_argument("--registry", default="")
    parser.add_argument("--detectors-dir", default="")
    parser.add_argument("--evidence-dir", default="")
    args = parser.parse_args(argv)

    registry = args.registry or os.path.join(
        args.repo_root,
        "riskengine-sdk", "src", "main", "java",
        "com", "wsttxm", "riskenginesdk", "detector", "DetectorRegistry.java",
    )
    detectors_dir = args.detectors_dir or os.path.dirname(registry)
    evidence_dir = args.evidence_dir or os.path.join(args.repo_root, "docs", "evidence")

    errors = validate_evidence_records(registry, detectors_dir, evidence_dir)
    if errors:
        print("EVIDENCE CONTRACT GATE FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    names = [
        resolve_detector_name(detectors_dir, cls)
        for cls in parse_registered_detector_classes(registry)
    ]
    print(f"==> Gate 1 (Evidence Contracts): PASS ({len(names)}/{len(names)} domains verified, 7 headings each)")
    return 0


if __name__ == "__main__":
    if main() != 0:
        raise RuntimeError("Evidence contract validation failed")
