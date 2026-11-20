#!/usr/bin/env python3
"""Generate GitHub Release notes for a given tag.

Priority order for release body content:
1. Matching section in CHANGELOG.md (e.g. '## [v1.4.0]' or '## [1.4.0]')
2. Multi-line annotated git tag message (excluding trivial single-line titles)
3. Git commit summary since the previous v*.*.* tag
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


DEMO_SIGNING_NOTICE = (
    "> **Demo APK Signing Note**: The Demo APK is intentionally signed with a temporary "
    "CI debug key and is provided only for sideload testing. It is not intended for "
    "production distribution or app stores. A later release may not install as an update "
    "because its temporary signing key can differ; uninstall the previous Demo first if "
    "Android reports a signature mismatch. No production signing secret is stored by this workflow."
)


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def extract_from_changelog(changelog_path: Path, tag: str) -> str:
    if not changelog_path.is_file():
        return ""

    version = tag[1:] if tag.startswith("v") else tag
    candidates = {tag, version}
    heading_re = re.compile(r"^##\s+\[?([^\]\s]+)\]?(?:\s+-\s+.*)?\s*$")

    lines = changelog_path.read_text(encoding="utf-8").splitlines()
    collecting = False
    collected: list[str] = []

    for line in lines:
        m = heading_re.match(line)
        if m:
            if collecting:
                break
            if m.group(1) in candidates:
                collecting = True
                continue
        elif collecting:
            collected.append(line)

    # Strip leading/trailing blank lines and trailing horizontal rules
    while collected and (not collected[0].strip() or collected[0].strip() == "---"):
        collected.pop(0)
    while collected and (not collected[-1].strip() or collected[-1].strip() == "---"):
        collected.pop()

    return "\n".join(collected).strip()


def extract_from_tag_annotation(tag: str) -> str:
    body = run_git(["tag", "-l", "--format=%(contents)", tag])
    if not body:
        return ""
    non_empty = [line for line in body.splitlines() if line.strip()]
    # Ignore trivial one-line annotations like "RiskEngine v1.4.0"
    if len(non_empty) <= 1 and len(body) < 80:
        return ""
    return body.strip()


def find_previous_tag(tag: str) -> str:
    # Prefer ancestry-based previous semantic tag
    tag_exists = bool(run_git(["rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"]))
    ref = f"{tag}^" if tag_exists else "HEAD"
    prev = run_git(["describe", "--tags", "--abbrev=0", "--match", "v*.*.*", ref])
    if prev and prev != tag:
        return prev

    # Fallback to version-sorted tag list
    all_tags = [
        t.strip()
        for t in run_git(["tag", "--list", "v*.*.*", "--sort=-v:refname"]).splitlines()
        if t.strip() and t.strip() != tag
    ]
    return all_tags[0] if all_tags else ""


def extract_from_commits(prev_tag: str, tag: str) -> str:
    tag_exists = bool(run_git(["rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"]))
    target_ref = tag if tag_exists else "HEAD"
    rev_range = f"{prev_tag}..{target_ref}" if prev_tag else target_ref
    log = run_git(["log", rev_range, "--no-merges", "--pretty=format:- %s (%h)"])
    if not log:
        return ""
    return f"### Changes\n\n{log}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate GitHub Release notes Markdown.")
    parser.add_argument("--tag", required=True, help="Release git tag (e.g. v1.4.0)")
    parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to CHANGELOG.md")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/repo")
    parser.add_argument("--output", required=True, help="Output Markdown file path")
    args = parser.parse_args()

    tag = args.tag.strip()
    prev_tag = find_previous_tag(tag)

    body = extract_from_changelog(Path(args.changelog), tag)
    source = "CHANGELOG.md"

    if not body:
        body = extract_from_tag_annotation(tag)
        source = "git tag annotation"

    if not body:
        body = extract_from_commits(prev_tag, tag)
        source = "git log"

    if not body:
        body = f"Release `{tag}`."
        source = "default"

    sections = [body, "---", DEMO_SIGNING_NOTICE]

    if args.repo and prev_tag:
        sections.append(
            f"**Full Changelog**: https://github.com/{args.repo}/compare/{prev_tag}...{tag}"
        )

    final_notes = "\n\n".join(sections).rstrip() + "\n"
    Path(args.output).write_text(final_notes, encoding="utf-8")
    print(f"Generated release notes for {tag} (source: {source}, prev_tag: {prev_tag or 'none'}) -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
