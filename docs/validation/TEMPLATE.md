# RiskEngine Release Validation & Adversarial Matrix Report Template

> Copy this template to `docs/validation/YYYY-MM/<version>-matrix-report.md` and fill in actual device/CI measurements before tagging a production release.

- **Release Version / Tag**: `vX.Y.Z`
- **Git Branch & Commit SHA**: `<branch>` / `<short-sha>`
- **Validation Date**: `YYYY-MM-DD`
- **Validator**: `<name>`
- **SDK Build Type**: Release AAR (`riskengine-sdk-release.aar`) + Demo APK (`demo-debug.apk` / `demo-release.apk`)

---

## 1. Automated CI Gates & Test Suite Snapshot

| Gate / Suite | Command | Status (`PASS`/`FAIL`) | Key Measured Metrics |
| :--- | :--- | :---: | :--- |
| Gate 1 — Evidence Contracts | `python3 -B scripts/check-evidence-records.py` | | `16/16` domains, 7 headings each |
| Gate 2 — ELF Hardening + JNI 1:1 + R8 Dex | `CHECK_JNI_DEX=1 ./scripts/check-elf-hardening.sh ...` | | AAR: `___ B` (`<= 8 MiB`), `.so`: `___–___ B` (`<= 2000 KiB`), 2 exports, 16KB align, JNI `41/41`, R8 Dex `___ < 2500` |
| Gate 3 — Single-Source `<queries>`/INI/Version | `python3 -B scripts/check-single-source-sync.py` | | `<queries>=52`, 13 lists synced, version aligned |
| Gate 4 — Public ABI Lock & AAR Purity | `./gradlew :riskengine-sdk:apiCheck` | | `___` public/protected types locked, POM 0 deps, AAR pure |
| Gate 5 — Reflection & Text-Protocol Boundary | `python3 -B scripts/check-boundary-guards.py` | | `___` audited reflection sites, 0 unregistered, 0 UI-text branching |
| Gate 6 — Trust-Root & CRL Freshness | `python3 -B scripts/refresh_google_attestation_roots.py --dry-run` | | Embedded roots & monotonic CRL floor verified |
| L1 JVM Unit Tests (Core SDK & Demo) | `./scripts/ci-verify.sh` & `./gradlew :demo:testDebugUnitTest` | | `:riskengine-sdk` & `:demo` |
| L2 Offline C++ Host Unit Tests | `./scripts/run-cpp-tests.sh` | | `3/3` CTest suites (`16` test cases) |
| L3 Binary-AAR Instrumentation (API 30/34/36) | `:integration-test:connectedDebugAndroidTest` | | API 30 / API 34 / API 36 KVM emulator matrix |
| Offline Envelope Verifier Parity (`v=2`) | `python3 -B scripts/test_verify_risk_envelope.py -v` | | Cross-language Java ↔ Python 6-step `v=2` verifier PASS |

---

## 2. Stock OEM Clean-Device Matrix (0 Actionable FP / 0 Crash / SLA Budgets)

Targets: `init < 5 ms`, `CRITICAL P95 < 20 ms`, `FAST P95 < 100 ms`, `PERSISTENT_KEY P95 < 10 ms`, `0` actionable FP, `0` crashes/tombstones.

| Brand / Model | Android API / ROM | `RiskLevel` (`STANDARD`) | `TrustTier` | Actionable FP | Coverage % | `init` (ms) | `CRITICAL` P95 (ms) | `FAST` P95 (ms) | `PERSISTENT_KEY` P95 (ms) | Crashes | Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Google Pixel (e.g. Pixel 6/8/9) | API 33–36 Stock | | | | | | | | | | |
| Samsung Galaxy (One UI + Knox) | API 33–35 One UI | | | | | | | | | | |
| Xiaomi / Redmi / POCO (HyperOS) | API 34–35 HyperOS | | | | | | | | | | |
| OPPO / OnePlus / realme (ColorOS) | API 33–35 ColorOS | | | | | | | | | | |
| vivo / iQOO (OriginOS) | API 33–35 OriginOS | | | | | | | | | | |
| Huawei (HarmonyOS) | HarmonyOS | | | | | | | | | | |
| Wi-Fi-Only Android Tablet | API 30–35 | | | | | | | | | | |

---

## 3. Adversarial Stack Detection Matrix

| Adversarial Scenario | Device / API | Expected Signals / Families | Observed `RiskLevel` | Observed Key `EvidenceItem` Codes | Verdict (`PASS`/`FAIL`) |
| :--- | :--- | :--- | :---: | :--- | :---: |
| Magisk (unhidden) | | `magisk_found`, `root_manager_cert` (`root_fw`) | | | |
| Magisk + Shamiko DenyList | | `isolated_mount_diff`, `C9:stealth_root_with_unmount` (`root_fw`) | | | |
| KernelSU / KSU-Next / SukiSU | | `ksu_*`, `statfs_overlay_on_system`, `root_manager_*` (`root_fw`) | | | |
| APatch / KernelPatch | | `kernelpatch_supercall_hello` / `apatch_*`, `root_manager_native_payload` (`root_fw`) | | | |
| SUSFS + `resetprop --delete` / Specter | | `prop_area_hole`, `kernel_uname_*`, `C8:spoofed_verified_boot` | | | |
| ZygiskNext / ReZygisk | | `zygisk_atexit_anon` / `zygisk_atexit_holes` | | | |
| LSPosed | | `lsposed_binder_magic`, `lsposed_gid_mismatch`, `lsposed_stack_trace` | | | |
| Frida (default / renamed / `/memfd` modded) | | `frida_*`, `fd_linjector`, `late_frida_fd`, `anon_elf_exec`, `C6` | | | |
| TrickyStore / TEES-RS / PlayIntegrityFix | | `tee_keybox_revoked`, `tee_grant_chain_split`, `tee_binder_ioctl_hook`, `pif_spoof` | | | |
| HideMyApplist (HMA / HMA-OSS) & Thanox | | `hma_uid_visibility_hidden`, `hma_cross_user_*`, `hma_broadcast_*`, `hma_permission_service_*`, `thanox_dropbox_ipc` (`hma_hiding`) | | | |
| VirtualApp / BlackBox Container | | `nested_container_path`, `dir_uid_mismatch`, `sacrificial_syscall_mismatch` | | | |
| Emulator / AVD / Cloud Phone | | `native_bridge`, `emu_*`, `zero_hw_codec`, `cloud_*` | | | |
| User CA / VPN / Mock Location / Screen Share | | `user_ca_cert`, `vpn_active`, `location_canary_tamper`, `virtual_display` | | | |

---

## 4. Demo Fluid UI v2 Manual Verification Checklist

- [ ] **Privacy Consent Gate**: Fresh install shows privacy consent dialog before `RiskEngine.initIfNeeded()`; declining keeps SDK uninitialized (`!RiskEngine.isInitialized()`); accepting persists consent and unlocks scanning.
- [ ] **3-Tier Progressive `RiskGaugeView` (`0–100`)**: Clicking "开始检测" renders smooth `1/3 CRIT -> 2/3 FAST -> 3/3 DEEP -> 3/3 DONE` segmented progress calibrated to `0–100` via `ExecutionStateListener`, along with the recommended `RiskAction` badge, Assessment Confidence, four `RiskDimension` bars (`TAMPERING` / `PRIVILEGE` / `ENVIRONMENT` / `FRAUD_CONTEXT`), and expandable `ScoreBreakdown` detail sheet without UI jank.
- [ ] **16/16 Converged Domains**: Report renders all 16 domains including `tee_integrity` and `threat_apps` with localized `EvidenceItem` detail sheets and clean filtering.
- [ ] **Fingerprint Continuity & Hardware Bucket Card**: Displays `FingerprintVersion` (`V2`), `FingerprintStability` (`OPTIMAL`), `anchorDriftCount`, `device_binding` status, 5 physical buckets (`gpu`/`cpu`/`sensor`/`camera`/`memory_battery`), and confirmed `resetFingerprintBaseline()` action.
- [ ] **Live Threat & Posture Stream Drawer**: Top-bar "推送流" pill opens `ThreatStreamDrawer` showing live `DeviceStateListener` posture snapshot and `ThreatListener` / runtime tamper events; clear button resets events cleanly.
- [ ] **Theme & Ergonomics**: Light/Dark theme toggle preserves report and threat stream state; Back gesture dismisses drawer/sheet cleanly.

---

## 5. Final Sign-Off

| Role | Decision (`APPROVED` / `HOLD`) | Notes | Date |
| :--- | :---: | :--- | :--- |
| Security / RASP Owner | | | |
| Release Engineering | | | |
