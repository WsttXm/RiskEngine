# RiskEngine Pending Items

This file contains only work that cannot be safely closed in the current workspace or requires an external device/infrastructure decision. All other remediation is implemented in source, tests, the Demo, or workflows.

## 1. ARM64/OEM false-positive and adversarial regression

- Cover Android 30–36 physical devices from major OEMs plus rooted, Magisk, LSPosed, and Frida Gadget/Server positive fixtures.
- Record SDK version, system build, execution coverage, raw evidence, and a human verdict for each run.
- Acceptance: zero strong-risk false positives on clean fixtures and corresponding evidence for every seeded positive fixture.
- Current evidence is an API 36 ARM64 emulator instrumentation and Demo run; it does not replace OEM hardware.

## 2. Single-source Java/native root paths

- Java and native lists currently match but remain separately maintained. Passing Java data into native code would weaken the native check's independence under Java-layer hooks.
- Preferred follow-up: generate both a Java class and C++ header from one read-only build-time manifest, with CI drift checks.
- Acceptance: one editable source list and generated outputs that CI refuses to accept when stale.

## 3. Hook-resistant native task traversal

- `/proc/self/maps` now uses raw syscalls, while thread directory traversal still uses `opendir/readdir` and can be targeted through libc hooks.
- Evaluate a tested `getdents64` wrapper for every ABI while preserving explicit unavailable/error semantics.
- Acceptance: libc directory hooks cannot silently turn thread checks into safe results; API 30–36 and all four ABIs pass.

## 4. Hosted workflow and release validation

- The user explicitly prohibited `git push`, so the new PR CI, scheduled device matrix, and tag Release workflows have not run on GitHub.
- After the first authorized push, use a temporary branch/test tag to validate artifact paths, permissions, Action versions, and release notes, then clean up according to repository policy.
- The temporary Debug-signed APK is intentional and sideload-only. Release notes must continue to state that signatures can change, old builds may need uninstalling, and the APK is not for stores or production.

## 5. Remote Maven repository selection

- AAR, sources JAR, POM, and a `maven-publish` publication are ready, but no remote repository or credential policy was selected. GitHub Release files remain the current distribution channel.
- A maintainer must choose GitHub Packages, Maven Central, or an internal repository before credentials and upload tasks can be configured.

