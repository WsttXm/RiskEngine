# RiskEngine Implementation Details

This document is the contract implemented by the current source, not a statement of intent. Host integration is in [README.md](../README.md). Expected evidence families on typical fixtures are in [Adversarial_Matrix.md](./Adversarial_Matrix.md).

## 1. Scope and modules

RiskEngine is a local Android risk-signal SDK. Java owns orchestration, privacy, scoring, and the report. C++17 JNI owns libc-hook-resistant I/O, maps parsing, path probes, and integrity checks. There is no server, no reporting, and no Play Integrity dependency.

| Module | Role |
| --- | --- |
| `riskengine-sdk` | Publishable AAR. Java 11 bytecode, minSdk 30, compileSdk 36. The AAR itself is not minified |
| `demo` | Local diagnostic console. Debug is temporarily signed; Release is minified but unsigned |
| `integration-test` | Depends only on the generated Release AAR; verifies a standalone host compiles and links the public API |

Current development version: `1.1.0-SNAPSHOT` (`riskEngineVersion` in `gradle.properties`). Tag release workflows override `releaseVersionName`.

## 2. Architecture and collection flow

```text
host call
  -> RiskEngine lifecycle snapshot (generation, config, registries, lock)
  -> single coordinator serializes requests (queue cap 16)
  -> collectionLock (queue wait is inside the deadline)
  -> SignalSnapshot.reset()
  -> parallel collectors on the 4-thread worker pool
  -> parallel detectors on the worker pool
  -> DataAggregator
       applyScene -> dedupeFamilies -> correlate
       collector coverage / multi-source inconsistency / synthesized fields
  -> immutable RiskReport
```

- `TaskScheduler` separates the coordinator from workers so a thread waiting on a batch cannot starve that batch.
- Asynchronous requests that hit a full or shut-down queue call `onError` (`RejectedExecutionException` wrapped as `IllegalStateException`).
- `collectTimeout` starts when the request is queued. Work that misses the deadline is filled in by `addMissingCollectorResults` / `addMissingDetectionResults` as explicit timeout/error coverage.
- Synchronous collection rejects the Android main thread. Asynchronous callbacks are not moved to the main thread.
- `shutdown()` advances the lifecycle generation, cancels work, and clears registries. Results from older generations are not delivered; in-flight `doCollectSync` re-checks generation at lock boundaries.

Concurrent requests are fairly serialized by `collectionLock`. A second request that cannot acquire the lock before the deadline returns a timeout report instead of running in parallel.

## 3. Lifecycle API

| API | Behavior |
| --- | --- |
| `init(context, config)` | Strict initialization; duplicate calls throw `IllegalStateException` |
| `initIfNeeded(context, config)` | Atomic initialize-if-absent; returns `false` when already initialized |
| `collect(callback)` | Asynchronous collection using the configured default `CollectScene` |
| `collect(scene, callback)` | Override the scene for this request |
| `collectSync()` / `collectSync(scene)` | Full synchronous collection; throws on the main thread |
| `collectReportJson()` | `collectSync()` then serialize |
| `reportToJson(report)` | Serialize only; no collection |
| `getReportJson()` | Deprecated alias for `collectReportJson()` |
| `shutdown()` | Cancel work and release resources |

Config defaults: every detector group enabled, `debugLog=false`, timeout 10_000 ms, `PrivacyProfile.BALANCED`, `CollectScene.STANDARD`. `native_tamper` is not gated by config and is always registered.

## 4. Collectors

`CollectorResult.Status` is `SUCCESS`, `EMPTY`, `ERROR`, or `UNSUPPORTED`.

`compareSources=true` is used only when every value is the same semantic field observed through a different source. Inconsistency is recorded by `DeviceFingerprint` and emitted as `multi_source_validation` (`MEDIUM` / `WARNING` / score 4 / actionable).

### 4.1 Java layer

| `fieldName` | Class | Contents | Privacy |
| --- | --- | --- | --- |
| `android_id` | `AndroidIdCollector` | App-scoped SHA-256 (package-name salt) | `BALANCED`/`DIAGNOSTIC`; overridable by `collectAndroidId` |
| `build_props` | `BuildPropsCollector` | Non-sensitive `Build.*` | Always |
| `screen_info` | `ScreenInfoCollector` | Size, dpi, density | Always; shared via `SignalSnapshot` |
| `apk_signature` | `ApkSignatureCollector` | Signing-certificate hash | Always |
| `bluetooth_info` | `BluetoothCapabilityCollector` | Capability; no MAC | Always |
| `wifi_info` | `WifiInfoCollector` | Capability (e.g. Wi-Fi Direct); no SSID/BSSID/MAC | Always |
| `telephony` | `TelephonyCollector` | Phone type, SIM state; no IMEI/IMSI | Always |
| `settings` | `SettingsCollector` | Developer options and similar | Always |
| `adb_state` | `AdbStateCollector` | USB/Wi-Fi ADB | Always; shares `AdbInspector` with the detector |
| `container_signals` | `ContainerSignalCollector` | cgroup / container paths | Always |

### 4.2 Native layer (JNI bridge)

| `fieldName` | Contents | Privacy |
| --- | --- | --- |
| `drm_id` | App-scoped Widevine hash | `DIAGNOSTIC` or `collectDrmId(true)` only |
| `boot_id` | App-scoped hash of `/proc/sys/kernel/random/boot_id` | `DIAGNOSTIC` or `collectBootId(true)` only |
| `system_properties_native` | Allowlisted properties from ini `[properties]` | Always |
| `cpu_info` | `/proc/cpuinfo` summary | Always |
| `disk_size` | Data-partition size | Always |
| `kernel_info` | `uname` and related | Always |

System-property lookups go through `DetectionLists.ALLOWED_PROPERTIES`. Keys outside the list return an empty string.

### 4.3 Synthesized fields

The aggregator appends these to the fingerprint. They **do not** count toward coverage:

- `hook_memory_signals`: summary of `anon_exec:` / `maps:` / `frida_pid_port:` from `hook_framework`
- `runtime_integrity_score_inputs`: per-detector status map and actionable score

Failed collectors also add a `collector:<fieldName>` `UNAVAILABLE` entry under `detections` for coverage accounting. The Demo does not render those as standalone risk rows.

## 5. Detectors

Risk presentation (`DetectionStatus`) is independent of execution (`DetectionExecutionStatus`). `BaseDetector.result(..., CheckCoverage)`:

- `attempted == 0` → `UNAVAILABLE` / `no_checks_attempted`
- `succeeded == 0` → `UNAVAILABLE` with failure reasons
- `failed > 0` with some successes → `PARTIAL`
- all succeeded, no risk → `SAFE`; risk present → `RISK`

`isInformational()` marks context that does not enter `riskScore`. Deprecated `isWarnOnly()` remains for compatibility.

`DetectorRegistry` honors config switches. `NativeTamperDetector` is always added.

### 5.1 `root`

Java path probes plus Native `nativeGetRootEvidenceRaw`.

| Strength | Example tokens | Score |
| --- | --- | --- |
| Strong | `su_found:`, `magisk_found:`, `ksu_found:`, `apatch_found:`, `modules_found:`, `native:su:` / `native:magisk:` / `native:mount:magisk` / `native:mount:module` | `HIGH` / `DANGER` / 8 |
| Medium | `native:syscall_mismatch:...` (access/stat/open disagree) | `MEDIUM` / `WARNING` / 4 |
| Weak | `selinux_permissive`, `test_keys` | `LOW` / `WARNING` / 1 / informational |

Path lists come from ini sections `[su]` `[magisk]` `[kernelsu]` `[apatch]` `[modules]`. Native also scans `PATH` for `su`/`ksud`/`apd`/`magisk` and Magisk/module mounts in `/proc/self/mountinfo`.

### 5.2 `mount_analysis`

Reads `/proc/mounts` and `/proc/self/mountinfo`. Magisk / `debug_ramdisk` / `/data/adb/modules` / docker overlay → `MEDIUM` / `WARNING` / 4 / actionable. Both proc files unreadable → `UNAVAILABLE`.

### 5.3 `hook_framework`

Java: Xposed class and `sHookedMethodCallbacks`, stack frames, Frida default port 27042, process names. Native: raw-syscall maps, `getdents64` over `/proc/self/task/*/comm`, GOT/inline hooks, JNI table.

`HookEvidenceClassifier` ranks tokens (the detector itself counts strong/medium):

| Rank | Tokens |
| --- | --- |
| STRONG | `inline_hook:`, `got_hook:`, `jni_table_hook:`, `maps:frida`, `maps:gadget`, `frida_pid`, `frida_pid_port` |
| MEDIUM | `thread:gum-js-loop`, `thread:frida`, `maps:xposed`, `maps:lsposed`, `maps:substrate`, `xposed_hooks_active`, `xposed_class_found`, `xposed_stack` |
| WEAK | `anon_exec:`, `frida_port_open`, anything containing `27042` |
| IGNORE | Lone `thread:gmain` (Native only emits it when a Frida family token is already present) |

Scoring: strong≥2 or (strong≥1 and medium≥2) → `DEADLY`/10; strong≥1 or medium≥2 → `HIGH`/8; medium≥1 → `MEDIUM`/2/**informational**; remaining weak → `LOW`/1/informational.

### 5.4 `process_scan`

Java `/proc` process list plus Native `getdents64` over `/proc` comm. Tokens must match as whole words (`ProcessScanDetector.containsProcessToken`) so names like `chrome` do not match `me`.

Tokens containing frida / magisk / ksud / lspd / zygisk → `HIGH`/`DANGER`/8; other hits → `MEDIUM`/`WARNING`/4. If only one of Java/Native produced evidence, `process_source_mismatch` is appended. Both unavailable → `UNAVAILABLE`.

### 5.5 `native_tamper`

Always runs. Reads Native `nGetSoIntegrityRaw`:

| Token | Handling |
| --- | --- |
| `text_mismatch` | In-memory RX CRC ≠ first 4 KiB of the file → `HIGH`/`DANGER`/8 |
| `text_mismatch:anonymous_map` | maps path empty / memfd / ashmem → same, actionable |
| `text_mismatch:missing_map` | `libriskengine.so` not in maps → **`UNAVAILABLE`** |
| `text_mismatch:file_unreadable` | File cannot be opened → `UNAVAILABLE` |
| `text_mismatch:bad_elf` | ELF parse failed → `UNAVAILABLE` |

`missing_map` is typical when Magisk Hide strips the SO from maps. It is recorded as a coverage gap, not as safe and not as proven tampering — userspace cannot tell “hidden” from “failed to load.”

GOT/inline-hook and JNI-table checks are produced by `native_get_integrity_evidence` and consumed by `hook_framework`, not by `native_tamper`.

### 5.6 `emulator`

`EmulatorEvidenceClassifier` ranks STRONG / WEAK and marks `aosp_sensor`, `missing_feature`, and `limited_hardware` as hardware noise.

| Rank | Examples |
| --- | --- |
| STRONG | `emu_file:`, `emu_pkg:`, `qemu_prop`, `qemu_pipe`, `cpu:hypervisor`, explicit fingerprint/model/manufacturer/product/hardware/board, `runtime_arch:x86` / `i386` |
| WEAK | `generic_fingerprint:`, `disk_small`, `screen_stock`, `no_thermal`, `emulator_ip:`, `cgroup:`, `mount_overlay`, `cmdline_mismatch` |
| Noise-weak | `aosp_sensor`, `missing_feature`, `limited_hardware` (common on tablets / slim OEM builds; do not upgrade alone) |

Scoring: strong≥2 or (strong≥1 and useful weak≥1) → `HIGH`/8; a single strong → `MEDIUM`/4; weak only → `LOW`/1/**informational**.

### 5.7 `debug`

TracerPid > 0 → `HIGH`/`DANGER`/8. Debugger connection or executable debug paths in maps → `MEDIUM`/4. Debuggable-only or IDA port → `LOW`/1/informational. `DIAGNOSTIC` still leaves a debuggable-only result informational so a Debug APK does not score itself as high risk.

### 5.8 `adb`

Informational by default. USB ADB: `LOW`/2; Wi-Fi ADB: `MEDIUM`/4. `CollectScene.PAYMENT` and `DIAGNOSTIC` make it actionable.

### 5.9 `sandbox` / `cloud_phone` / `custom_rom`

| Detector | Strong | Weak | Default score |
| --- | --- | --- | --- |
| `sandbox` | Parallel-space packages, abnormal data dir, ClassLoader markers | Virtualized fds | Strong `MEDIUM`/4; weak `LOW`/1/informational |
| `cloud_phone` | `cloud_pkg:` | Battery / camera / sensor anomalies | Same |
| `custom_rom` | — | `community_rom:`, `prop_mismatch:fingerprint` | Always `LOW`/1/informational. A community ROM is not proof of root |

`LOGIN`/`PAYMENT` make sandbox and cloud_phone actionable.

### 5.10 Aggregator-appended detections

| Name | Source |
| --- | --- |
| `signal_correlation` | `CorrelationEngine.correlate`, §8 |
| `multi_source_validation` | Fingerprint multi-source inconsistency |
| `collector:<field>` | Coverage placeholder for non-SUCCESS collectors |

## 6. Native layer

Shared library `libriskengine.so`. CMake 3.22.1, C++17, static libc++, hidden symbols.

### 6.1 Inline syscalls

`raw_syscall.h` issues instructions per ABI and **must not** call libc `syscall()`:

| ABI | Instruction |
| --- | --- |
| aarch64 | `svc #0` (number in x8, args x0–x5) |
| arm | `svc #0` (number in r7) |
| x86_64 | `syscall` |
| i386 | `int $0x80` (up to 5 args; the 6th is ignored) |

`syscall_wrapper.cpp` wraps `openat`/`faccessat`/`fstatat`/`read`/`close`/`mmap`/`munmap`. File reads, path probes, and maps all use this path.

### 6.2 Directory walks

`raw_dir.cpp` lists directories with `getdents64`, avoiding hooked `opendir`/`readdir`. Used for `/proc/self/task`, `/proc` process scans, and thermal zones.

### 6.3 String obfuscation

`OBF("...")` in `obf_str.h` XOR-encodes the literal with `0x5A` at compile time and decodes at runtime. Paths, Frida/Magisk keywords, and symbol names are not plaintext in `.rodata`. This is static-string hiding, not cryptography.

### 6.4 Maps

`maps_parser.cpp` reads `/proc/self/maps` via raw syscall and parses address ranges, permissions, and paths. Java `SignalSnapshot.getSelfMaps()` is a separate Java path shared by Java hook/debug checks. Native hook maps are **intentionally independent** so a libc hook cannot blind both layers at once.

### 6.5 Integrity

`native_integrity.cpp`:

1. **libc GOT / inline hook**: mmap on-disk `libc.so`, parse the ELF dynamic table, inspect `openat`/`faccessat`/`read`/`connect`/`ptrace`/`fopen`. A GOT target outside libc RX → `got_hook:<name>`. ARM64 recognizes `LDR X16/X17 + BR` and out-of-range `B`; ARM32 recognizes `bx/blx` and `ldr pc`. x86 has no trampoline heuristic.
2. **JNI table**: if `JNIEnv->FindClass` / `GetVersion` function pointers fall outside `libart.so` RX → `jni_table_hook:...`.
3. **Self SO CRC**: locate `libriskengine.so` in maps and compare CRC-32 of the first executable PT_LOAD’s file bytes vs the first 4 KiB in memory. Missing / anonymous / unreadable / bad ELF produce suffixed `text_mismatch:*` tokens.

### 6.6 Native detector entry points

| JNI | Native | Use |
| --- | --- | --- |
| `nativeCheckRootRaw` / `nativeGetRootEvidenceRaw` | `native_root_detector` | Root paths, mounts, syscall mismatch |
| `nativeGetHookEvidenceRaw` | `native_hook_detector` | maps / threads / integrity tokens |
| `nativeCheckEmulatorFilesRaw` | `native_emulator_detector` | Emulator files |
| `nativeGetThermalZoneCountRaw` | same | Thermal-zone count |
| `nativeGetRuntimeArchRaw` | `runtime_arch_checker` | Runtime ABI |
| `nativeGetTracerPidRaw` | `native_debug_detector` | TracerPid |
| `nGetSelinuxEnforceRaw` | root detector | SELinux |
| `nGetBuildPropFingerprintRaw` | read `/system/build.prop` | Compare with `ro.build.fingerprint` |
| `nScanProcessTokensRaw` | process scan in integrity | Native process tokens |
| `nGetSoIntegrityRaw` | `native_get_so_integrity_evidence` | SO CRC |

JNI strings never pass untrusted bytes to `NewStringUTF`: the implementation caps length, validates UTF-8, replaces malformed sequences, and constructs UTF-16 with `NewString`. C++ allocation failures and JNI character-access failures do not leave exceptions across the boundary. JNI registration failures clear pending exceptions and log the target class.

### 6.7 Native build hardening

- `-fstack-protector-strong`, Release `_FORTIFY_SOURCE=2`, `-Wformat -Wformat-security`
- `-fvisibility=hidden`
- Link: `relro,now`, `noexecstack`, `max-page-size=16384`, `--exclude-libs,ALL`

## 7. Shared signals

Each report starts with `SignalSnapshot.reset()`. `SignalResult<T>` preserves success / empty / unavailable / error. Collectors and detectors share:

- ADB state, system properties, `/proc/self/maps` (Java path)
- Loopback listening ports, process snapshots, text files, path existence, container signals
- Structured `ShellExecutor.Result` for the same command
- SELinux, `build.prop` fingerprint, CPU/disk/kernel, native process tokens, SO integrity, screen metrics

ADB collection is therefore not duplicated, and Java hook/debug checks reuse maps and ports. Native hook maps remain an independent raw-syscall read.

`ShellExecutor.Result` distinguishes `SUCCESS`, `INVALID_COMMAND`, `TIMEOUT`, `NON_ZERO_EXIT`, `INTERRUPTED`, and `EXECUTION_ERROR`, and carries stdout, stderr, exit code, duration, and failure reason. String-only helpers are deprecated.

## 8. Scene, family dedupe, and correlation

`DataAggregator.aggregate` order:

1. `CorrelationEngine.dedupeFamilies`: if an `EvidenceFamily` (`frida` / `debugger` / `xposed` / `root_fw` / `qemu`) is already claimed by an earlier detector, a later actionable result with `score > 0` becomes informational. Magisk must not add score twice via `root` and `process_scan`.
2. `CorrelationEngine.applyScene`: lifts named detectors from informational to actionable for the scene. It never disables a detector and never downgrades an already-actionable result.
3. `CorrelationEngine.correlate`: may append one `signal_correlation` result.
4. Collector coverage signals, multi-source inconsistency, synthesized fingerprint fields.

### 8.1 Scene lifts

| Scene | Made actionable |
| --- | --- |
| `STANDARD` | Nothing extra |
| `LOGIN` | `emulator`, `cloud_phone`, `sandbox` |
| `PAYMENT` | LOGIN + `adb` |
| `DIAGNOSTIC` | Every informational result except debug-and-debuggable-only |

### 8.2 Correlation rules

| ID | Condition | Result |
| --- | --- | --- |
| C1 | Emulator currently ≤ `LOW`, and hypervisor or (small disk + x86) | `MEDIUM` / `WARNING` / 4 |
| C2 | Exactly one STRONG + hypervisor/QEMU, emulator already `MEDIUM` | Raise to `HIGH` / `DANGER` / 4 |
| C3 | Inline/GOT hook **and** a Frida family token (hook or process_scan) | `DEADLY` / `DANGER` / 10, hard trigger |
| C4 | `syscall_mismatch` **and** module/Magisk mount | `HIGH` / `DANGER` / 8 |
| C5 | `prop_mismatch:fingerprint`, no `community_rom:`, emulator NORMAL | `LOW` / `WARNING` / 1 / informational (resetprop hint) |
| C7 | `LOGIN`/`PAYMENT`, cloud phone has no `cloud_pkg:` but ≥ 2 weak tokens | `LOW` / `WARNING` / 2 |

No match means no `signal_correlation` row. C3 also satisfies `RiskReport.hasHardTrigger()`.

## 9. Report and scoring

Thresholds live on `RiskReport`: `MEDIUM_THRESHOLD=4`, `HIGH_THRESHOLD=10`, `DEADLY_THRESHOLD=18`.

Overall level:

| Level | Rule (hard trigger first, then score/counts) |
| --- | --- |
| `DEADLY` | Hard trigger; or score ≥ 18; or actionable dangers ≥ 3 |
| `HIGH` | Score ≥ 10 or actionable dangers ≥ 1 |
| `MEDIUM` | Score ≥ 4 or actionable warnings ≥ 2 |
| `LOW` | Score > 0, or any warning/danger exists (including informational) |
| `UNKNOWN` | None of the above, and `unknownCount > 0` or an execution status of `PARTIAL`/`UNAVAILABLE`/`TIMEOUT`/`ERROR` |
| `SAFE` | Score 0, no informational/risk, complete coverage |

Hard triggers (informational results skipped):

- Any detection whose details contain `inline_hook:` or `got_hook:` and whose risk is ≥ `HIGH`
- `hook_framework` containing `frida_pid_port` / `maps:frida` / `maps:gadget`
- `signal_correlation` containing `C3:`

Other report fields:

- `riskScore`: sum of non-informational `score`
- `maxRiskScore`: sum of every `maxScore` (technical capacity)
- `displayThresholdMaximum`: fixed 18
- `warningCount` / `dangerCount` / `unknownCount`: counted by `DetectionStatus`, **including** informational
- `checkCount`: detections other than `collector:*` plus non-synthetic collectors
- `completedCheckCount`: detections whose execution is `SAFE`/`RISK` plus `SUCCESS` raw collectors
- `coveragePercent`: `round(completed / total * 100)`; 100 when total is 0
- `reportStatus`: `COMPLETE` when every check finished; `UNAVAILABLE` when none finished and no detection is available; otherwise `PARTIAL`

Aggregation freezes `RiskReport`, `DeviceFingerprint`, and nested `CollectorResult`s.

## 10. Privacy

| Profile | Android ID | Boot ID | Widevine |
| --- | --- | --- | --- |
| `MINIMAL` | off | off | off |
| `BALANCED` | on | off | off |
| `DIAGNOSTIC` | on | on | on |

Each of the three can be overridden on the Builder. `PrivacyUtils.hashIdentifier` computes hex `SHA-256(packageName + ":" + value)`. That is an app-scoped pseudonym, not encryption or anonymization.

The SDK does not collect raw IMEI, IMSI, MAC, SSID, or BSSID. Native property reads are constrained by the ini allowlist.

## 11. Single-source lists

Read-only manifest: `riskengine-sdk/src/main/resources/lists/artifact_paths.ini`.

Generated mirrors (checked in; must be regenerated when the ini changes):

- `riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java`
- `riskengine-sdk/src/main/cpp/generated/detection_lists.h`

`RootPathListConsistencyTest` fails if the Java arrays drift from the ini. Sections cover su / magisk / kernelsu / apatch / modules / emulator files and packages / cloud packages / sandbox packages / properties / process tokens.

## 12. JSON

`RiskReportJsonSerializer` uses `org.json` (provided by the Android framework; unit tests depend on `org.json:json`). Root fields:

`timestampMs`, `sdkVersion`, `riskScore`, `maxRiskScore`, `displayThresholdMaximum`, `warningCount`, `dangerCount`, `unknownCount`, `availableDetectionCount`, `detectionCount`, `checkCount`, `completedCheckCount`, `incompleteCheckCount`, `coveragePercent`, `reportStatus`, `overallRiskLevel`, `collectScene`, `fingerprint`, `detections`.

Each detection includes `detectorName`, `riskLevel`, `status`, `executionStatus`, `score`, `maxScore`, `informational`, `checksAttempted`/`Succeeded`/`Failed`, `failureReasons`, `details`, `evidence`, `timestampMs`.

## 13. ProGuard / R8

- SDK AAR `isMinifyEnabled = false`. Minifying the library module strips nested public types and breaks release unit tests.
- `consumer-rules.pro` keeps `RiskEngine`, `RiskEngineConfig` (including `Builder`), `RiskEngineCallback`, `PrivacyProfile`, `CollectScene`, `model.**`, `NativeCollectorBridge` (JNI registers by name), and every `native` method.
- Demo Release enables minify.

## 14. Demo presentation contract

The Demo depends on the in-tree SDK and is a diagnostic console:

1. No auto-collect, no marketing title, no privacy explainer card. The first screen is the status card.
2. Status card: localized conclusion, humanized primary reason, score / 18, coverage, elapsed time. Copy-report sits in the status-card header and appears after a result.
3. Environment detections sort risk first. A collapsed row is a localized title + semantic badge + summary, without a `snake_case` id. Expanded details then show `detector: root` and the raw token.
4. Humanized summaries: `native:mount:magisk` → Magisk mount; `text_mismatch:missing_map` → native library not found in memory maps. The raw token appears once in details and is not duplicated next to the sentence.
5. “Needs attention” excludes informational items (ADB, weak emulator, community ROM, debuggable-only, …).
6. `collector:*` rows are not listed as environment detections; coverage gaps still feed the header coverage figure.
7. Synthesized SDK fields (`hook_memory_signals`, `runtime_integrity_score_inputs`) have their own section.
8. Collection errors use gray and 0% progress, never the deadly-risk treatment.
9. Copied text is a redacted summary: no identifier hashes, raw properties, paths, or PIDs.
10. Expand ripple is drawn as foreground; pressed/focus is cleared after toggle so the row does not stay washed gray.
11. In-flight and completed UI state survive Activity recreation. Haptics fire only for newly delivered results.
12. `allowBackup=false`; device-transfer extraction is disabled.

## 15. Tests

Unit tests under `riskengine-sdk/src/test`:

| Test | Covers |
| --- | --- |
| `RiskScoringModelTest` | Level thresholds, informational not scored, hard triggers |
| `FailureSemanticsTest` | Collector/detector failure never becomes SAFE |
| `DetectorCoverageTest` | All-failed `CheckCoverage` → UNAVAILABLE |
| `CorrelationEngineTest` | Scene lifts, family dedupe, C1–C7 |
| `EmulatorScoringTest` | Strong / weak / noise-weak signals |
| `HookTokenRankingTest` | Hook token ranks |
| `ProcessPatternNegativeTest` | Whole-word process matching and negative cases |
| `RootPathListConsistencyTest` | Java lists match the ini |
| `RiskEngineConfigTest` | Privacy profiles, scene, timeout bounds |
| `RiskReportJsonSerializerTest` | JSON fields |
| `DataAggregatorTest` / `SignalSnapshotTest` / `TaskSchedulerTest` / `ShellExecutorTest` / `CollectorResultTest` / `ProcfsUtilsTest` | Aggregation, cache, threads, shell, model |

`integration-test` only compiles and links the public API; it does not run device detections. The instrumentation matrix (API 30/33/35/36 x86_64) is weekly/manual in CI and does not replace ARM64 OEM hardware.

## 16. Build and release

```bash
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug
```

- PRs and every branch push: unit tests, lint, AAR/POM/sources, Demo Debug APK, archive integrity.
- `vMAJOR.MINOR.PATCH` tags: AAR, sources JAR, POM, temporary Debug APK, SHA-256. CI stores no production signing key.
- A `maven-publish` publication exists; no remote repository has been selected. GitHub Release files remain the distribution channel.

## 17. Verification boundaries

- Kernel mount-namespace hiding (a complete Magisk DenyList / Shamiko) cannot be proven from userspace without attestation. A failed check in that situation must be `UNKNOWN`/`PARTIAL`/`UNAVAILABLE`, never silent `SAFE`.
- `native_tamper` `missing_map` is a coverage gap by design. If a host wants “SO disappeared from maps” to be risk, it should interpret that `UNAVAILABLE` itself rather than expecting the SDK to emit DANGER.
- x86/i386 has no ARM trampoline heuristic; GOT checks and CRC still run.
- Anonymous executable regions allowlist JIT/zygote/scudo and similar; OEM differences can still false-positive and need physical-device regression.
- Local signals can be adversarially tampered. This SDK complements, rather than replaces, server risk analysis, hardware attestation, or Play Integrity.
