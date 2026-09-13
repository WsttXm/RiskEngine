# RiskEngine Implementation Details

This document is the contract implemented by the current source, not a statement of intent. Host integration is in [README.md](../README.md). Expected evidence families on typical fixtures are in [Adversarial_Matrix.md](./Adversarial_Matrix.md).

Updated against the implementation in commit `15c55ef`; differences between implemented behavior and design intent are called out below.

## 1. Scope and modules

RiskEngine is a local Android risk-signal SDK. Java owns orchestration, privacy, scene scoring, layered fingerprints, and the final report. C++17 JNI owns libc-hook-resistant I/O, environment probes, ART/code integrity, an independent sealed verdict, and periodic re-verification. There is no server, no reporting, and no Play Integrity dependency.

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
       dedupeFamilies -> applyScene -> correlate
       collector coverage / multi-source inconsistency / synthesized fields
       FingerprintIdBuilder + FingerprintStore -> layered ID / continuity
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
| `shutdown()` | Cancel work, release resources, and request native monitor shutdown; fingerprint storage is retained |

Config defaults: every detector group enabled, `debugLog=false`, timeout 10_000 ms, `PrivacyProfile.BALANCED`, `CollectScene.STANDARD`. `native_tamper`, `consistency`, and `sealed_verdict` are always registered regardless of detector-group switches. Disabling Root/Hook groups does not disable equivalent probes inside `sealed_verdict`.

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
| `gpu_info` | `GpuInfoCollector` | Offscreen EGL pbuffer: vendor/renderer, GL/EGL versions, sorted extension hash, texture/renderbuffer/vertex-attribute limits | Always |
| `sensor_fingerprint` | `SensorFingerprintCollector` | Sorted sensor-tuple and vendor-set hashes, counts and capabilities | Always |
| `cpu_topology` | `CpuTopologyCollector` | Runtime/sysfs/procfs core counts, implementer/part distribution, per-core frequency ranges, ABI, SoC | Always; SoC fields require API 31+ |
| `hardware_profile` | `HardwareProfileCollector` | Memory buckets, display modes/HDR, camera specifications and hash, battery information, system shared-library-set hash | Always |
| `partition_fingerprints` | `PartitionFingerprintCollector` | Partition fingerprints, build date, verified boot/vbmeta and related properties | Always; native property allowlist |

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

### 4.4 Layered IDs and continuity

`FingerprintIdBuilder` takes selected nonblank fields only from `SUCCESS` collectors, sorts `field.key=value` entries, and computes `SHA-256(salt + "|" + layer + "|" + joined)` with U+001F between entries. A layer with no inputs returns an empty string.

| Layer | Candidate inputs | Contents |
| --- | --- | --- |
| hardware (`hw`) | 17 | GPU, sensors, camera, memory, display, battery, CPU/SoC, optional Widevine, screen xdpi/ydpi |
| system (`sys`) | 11 | Partition fingerprints, build date/vbmeta, Build fingerprint/patch/bootloader, kernel, shared-library hash |
| volatile (`vol`) | 2 | Enabled Android ID and Boot ID hashes |
| composite | hardware + system | `SHA-256(salt + "\|composite\|" + hardwareId + "\|" + systemId)`; excludes volatile and may be nonempty even when both layers are empty |

`FingerprintId` exposes layer getters, hardware/system field counts, and the list of contributing hardware fields. Hardware coverage uses integer truncation; reliability requires a nonempty digest and ≥ 50% coverage (currently at least 9/17). This is a field-coverage threshold, not a guarantee of uniqueness or stability across firmware changes.

`RiskEngine` injects `FingerprintStore` into `DataAggregator`. Private `riskengine_fp` SharedPreferences hold a hex-encoded random 32-byte salt, `last_hw`, `last_sys`, `first_seen`, and `observations`. A storage-free `DataAggregator()` uses the fixed salt `riskengine` without continuity comparisons; salt-access exceptions also fall back to that value.

Comparison order: no hardware baseline → `FIRST_OBSERVATION`; baseline exists but current hardware is unreliable → `INCONCLUSIVE`; both layers match → `STABLE`; only system changes → `SYSTEM_CHANGED`; hardware differs → `HARDWARE_CHANGED`; storage unavailable → `UNKNOWN`. Only reliable measurements replace the digest baseline; observation counts still advance. Hardware changes append actionable `fingerprint_continuity` (`MEDIUM`/`WARNING`/4), after scene processing, deduplication, and correlation.

The aggregator appends `fingerprint_id` with nonempty `composite`/`hardware`/`system`/`volatile` values, `hardware_coverage`, `system_coverage`, and `hardware_layer_reliable`; storage adds `continuity` and `observation_count`. `RiskReport.getFingerprintId()` exposes the model, or `null` on composition failure. `RiskReport.isSyntheticCollector` does not yet exclude `fingerprint_id`, so it contributes to total and completed check counts.

Changes in the contributing field set above the reliability threshold can still produce `HARDWARE_CHANGED`; drivers, privacy switches, and display configuration can also change the hardware digest. This state is not proof of physical hardware replacement or spoofing.

## 5. Detectors

Risk presentation (`DetectionStatus`) is independent of execution (`DetectionExecutionStatus`). `BaseDetector.result(..., CheckCoverage)`:

- `attempted == 0` → `UNAVAILABLE` / `no_checks_attempted`
- `succeeded == 0` → `UNAVAILABLE` with failure reasons
- `failed > 0` with some successes → `PARTIAL`
- all succeeded, no risk → `SAFE`; risk present → `RISK`

`isInformational()` marks context that does not enter `riskScore`. Deprecated `isWarnOnly()` remains for compatibility.

`DetectorRegistry` honors config switches. `NativeTamperDetector`, `ConsistencyDetector`, and `SealedVerdictDetector` are always added.

### 5.1 `root`

Java path probes plus Native `nativeGetRootEvidenceRaw`.

| Strength | Example tokens | Score |
| --- | --- | --- |
| Strong | `su_found:`, `magisk_found:`, `ksu_found:`, `apatch_found:`, `modules_found:`, `native:su:` / `native:magisk:` / `native:mount:magisk` / `native:mount:module` | `HIGH` / `DANGER` / 8 |
| Medium | `native:syscall_mismatch:...` (access/stat/open disagree) | `MEDIUM` / `WARNING` / 4 |
| Weak | `selinux_permissive`, `test_keys` | `LOW` / `WARNING` / 1 / informational |

Path lists come from ini sections `[su]` `[magisk]` `[kernelsu]` `[apatch]` `[modules]`. Native also scans `PATH` for `su`/`ksud`/`apd`/`magisk` and Magisk/module mounts in `/proc/self/mountinfo`.

New native probes are merged into root evidence:

- `ksu_prctl:`, `mount_hidden:`, `listing_mismatch:`, and `selinux_context:` rank strong; `ns_differs` and `mount_hidden_count` rank medium.
- Namespace checks read self/PID 1 `ns/mnt` and `mountinfo`, comparing selected system mount points. `RootDetector` records `ns_unreadable:*` only as `mount_ns:*` coverage failures.
- The KernelSU probe uses raw `prctl` to query a version/reply and checks `/proc/self/attr/current` for su/Magisk contexts; a negative result does not rule out all kernel-root variants.
- Directory cross-checks compare `faccessat(F_OK)` on su/Magisk paths against parent `getdents64` listings; these are not atomic filesystem snapshots. Native also probes `[tamper_tool_paths]`.

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

Additional ranks: `jni_slot_hook:`, `jni_self_hook:`, `art_native_flag:`, `wx_segment:self`, `unix_socket:frida`/`gum`, `late_text_mismatch`, `late_wx_self`, and `late_module:` are STRONG; `loader_unexpected:`, `loader_chain_deep:`, other `wx_segment:`, `late_tracer_attached`, and `late_wx_art` are MEDIUM. The classifier marks `loader_depth:` and `passes:` IGNORE.

IGNORE context remains available in details for diagnostics, but a context-only result such as `passes:0` now returns `SAFE`/0/informational and cannot become actionable in `DIAGNOSTIC` mode.

### 5.4 `process_scan`

Java `/proc` process list plus Native `getdents64` over `/proc` comm. Tokens must match as whole words (`ProcessScanDetector.containsProcessToken`) so names like `chrome` do not match `me`.

Tokens containing frida / magisk / ksud / lspd / zygisk → `HIGH`/`DANGER`/8; other hits → `MEDIUM`/`WARNING`/4. If only one of Java/Native produced evidence, `process_source_mismatch` is appended. Both unavailable → `UNAVAILABLE`.

### 5.5 `native_tamper`

Always registered; reads `nGetSoIntegrityRaw`:

| Token | Handling |
| --- | --- |
| `text_mismatch` (optionally with `text_mismatch_seg:<index>`) | Executable-segment file/memory FNV-1a differs → `HIGH`/`DANGER`/8 |
| `text_mismatch:anonymous_map` | Empty / memfd / ashmem maps path → same |
| `text_mismatch:missing_map` | SO absent: effective request scene `LOGIN`/`PAYMENT` → `MEDIUM`/`WARNING`/4; other scenes → `UNAVAILABLE` |
| `text_mismatch:file_unreadable` / `text_mismatch:unreadable_segments` | Same scene policy |
| `text_mismatch:bad_elf` | `UNAVAILABLE`, with no scene escalation |

JNI read failures remain `UNAVAILABLE`. The detector is constructed per report with that request's effective scene, so `collect(scene)` overrides and the final aggregation apply the same policy. A missing map is not proof of tampering; sensitive-scene escalation is a risk policy. `sealed_verdict` scores these tokens separately (§5.12), so this item's unavailability does not imply an overall coverage-only result.

GOT/inline and JNI-table checks still flow through `hook_framework`.

### 5.6 `emulator`

`EmulatorEvidenceClassifier` ranks STRONG / WEAK and marks `aosp_sensor`, `missing_feature`, and `limited_hardware` as hardware noise.

| Rank | Examples |
| --- | --- |
| STRONG | `virtual_gpu:`, `emu_file:`, `emu_pkg:`, `qemu_prop`, `qemu_pipe`, `cpu:hypervisor`, explicit fingerprint/model/manufacturer/product/hardware/board, `runtime_arch:x86` / `i386` |
| WEAK | `generic_fingerprint:`, `disk_small`, `screen_stock`, `no_thermal`, `emulator_ip:`, `cgroup:`, `mount_overlay`, `cmdline_mismatch` |
| Noise-weak | `aosp_sensor`, `missing_feature`, `limited_hardware` (common on tablets / slim OEM builds; do not upgrade alone) |

Scoring: strong≥2 or (strong≥1 and useful weak≥1) → `HIGH`/8; a single strong → `MEDIUM`/4; weak only → `LOW`/1/**informational**.

`ro.build.characteristics` containing `emulator` adds strong `qemu_prop:ro.build.characteristics=...` evidence.

### 5.7 `debug`

TracerPid > 0 → `HIGH`/`DANGER`/8. Debugger connection or executable debug paths in maps → `MEDIUM`/4. Debuggable-only or IDA port → `LOW`/1/informational. `DIAGNOSTIC` still leaves a debuggable-only result informational so a Debug APK does not score itself as high risk.

### 5.8 `adb`

Informational by default. USB ADB: `LOW`/2; Wi-Fi ADB: `MEDIUM`/4. `CollectScene.PAYMENT` and `DIAGNOSTIC` make it actionable.

### 5.9 `sandbox` / `cloud_phone` / `custom_rom`

| Detector | Strong | Weak | Default score |
| --- | --- | --- | --- |
| `sandbox` | Parallel-space packages, abnormal data dir/loader, dexElements > 12, UID/user-directory mismatches | Virtualized fds, dexElements 7–12 | Strong `MEDIUM`/4; weak `LOW`/1/informational |
| `cloud_phone` | `cloud_pkg:`, nonempty `cloud_prop:`, `virtual_gpu:`, `wired_interface:ethN` | Battery / camera / sensor anomalies | Any strong `HIGH`/7; ≥ 2 weak actionable `MEDIUM`/4; one weak `LOW`/1/informational |
| `custom_rom` | — | `community_rom:`, `prop_mismatch:fingerprint` | Always `LOW`/1/informational. A community ROM is not proof of root |

`LOGIN`/`PAYMENT` make sandbox and cloud_phone actionable.

### 5.10 Aggregator-appended detections

| Name | Source |
| --- | --- |
| `signal_correlation` | `CorrelationEngine.correlate`, §8 |
| `multi_source_validation` | Fingerprint multi-source inconsistency |
| `fingerprint_continuity` | Reliable hardware digest changed across observations (§4.4) |
| `collector:<field>` | Coverage placeholder for non-SUCCESS collectors |

### 5.11 `consistency`

Always registered. Seven groups cover partition fingerprints, Build versus native properties, core counts, ABI/os.arch, SDK/release, fingerprint shape/brand, and verified boot. Any strong evidence → `HIGH`/`DANGER`/7; weak only → `LOW`/`WARNING`/2/informational.

Strong tokens are `partition_fingerprint_mismatch:`, `build_prop_mismatch:`, `core_count_mismatch:`, `abi_arch_mismatch:`, and `abi_64bit_mismatch:`. Weak tokens are `api_release_mismatch:`, `fingerprint_malformed:`, `fingerprint_brand_mismatch:`, `verified_boot_state:`, and `bootloader_unlocked`. Missing sources count as coverage failures. The core-count detector currently compares only Runtime and `/proc/cpuinfo`; sysfs counts are collected but not compared here. Partition fingerprints use exact whole-string equality, so legitimate OEM partition differences can trigger a finding.

### 5.12 `sealed_verdict`

Always registered; checks both JNI self-registration pointers and a native sealed score. Native reruns root/hook/self-integrity/emulator/debug probes alongside the existing Java detectors. Native flag weights add up, capped at 100: text mismatch 10; inline/GOT/JNI-table/self-W+X 9; hidden root 8; KernelSU 8; strong root 7; framework 6; debugger 6; emulator files or zero thermal zones 4; namespace coverage loss 1.

A negative verification result emits `verdict_unverifiable:mac_or_nonce_rejected`; like `jni_self_hook:`, it returns `DEADLY`/`DANGER`/10. Valid native scores ≥ 9 map to `DEADLY`/10, ≥ 6 to `HIGH`/8, ≥ 3 to `MEDIUM`/4; remaining nonempty evidence maps to `LOW`/1/informational. No evidence returns safe according to coverage. Missing native library or failed read/verification calls record coverage failures, not automatic MAC rejection. `jni_self:no_range` currently counts as nonempty evidence rather than `jni_self_hook:`.

A `DEADLY` result from this detector does not add a report-level hard trigger: the final level still follows §9 scores, danger counts, and existing hard triggers. `native_score:*` does not carry existing evidence-family markers, so scores can overlap with those from other detectors.

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

`syscall_wrapper.cpp` wraps `openat`/`faccessat`/`fstatat`/`read`/`close`/`mmap`/`munmap`/`readlinkat`/`prctl`/`getppid`/`gettid`. File reads, path probes, and maps all use this path.

### 6.2 Directory walks

`raw_dir.cpp` lists directories with `getdents64`, avoiding hooked `opendir`/`readdir`. Used for `/proc/self/task`, `/proc` process scans, and thermal zones.

### 6.3 String obfuscation

`OBF("...")` derives a per-site seed from `__LINE__`, `__COUNTER__`, and literal length, then XOR-encodes with a rolling xorshift byte stream and decodes at runtime. It replaces the fixed `0x5A` key. This is static-string obfuscation, not an encryption guarantee. Java `ObfuscatedLists` is decoder scaffolding only; it is not wired into generation or consumption of `DetectionLists`, whose Java lists remain plaintext.

### 6.4 Maps

`maps_parser.cpp` reads `/proc/self/maps` via raw syscall and parses address ranges, permissions, and paths. Java `SignalSnapshot.getSelfMaps()` is a separate Java path shared by Java hook/debug checks. Native hook maps are **intentionally independent** so a libc hook cannot blind both layers at once.

### 6.5 Integrity

`native_integrity.cpp`:

1. **libc GOT / inline hook**: mmap on-disk `libc.so`, parse the ELF dynamic table, inspect the 18 symbols in `list_monitored_libc_symbols()` (including file, directory, network, property, and dynamic-loading functions). A GOT target outside libc RX → `got_hook:<name>`. ARM64 recognizes `LDR X16/X17 + BR` and out-of-range `B`; ARM32 recognizes `bx/blx` and `ldr pc`. x86 has no trampoline heuristic.
2. **JNI table**: if `JNIEnv->FindClass` / `GetVersion` function pointers fall outside `libart.so` RX → `jni_table_hook:...`.
3. **Self SO FNV-1a**: walk the file-backed extent of every executable PT_LOAD, comparing disk and readable memory in 64 KiB windows with segment-address/offset seeds. Differences emit `text_mismatch` and `text_mismatch_seg:<index>`; candidate segments with no readable windows emit `text_mismatch:unreadable_segments`. Unreadable individual windows are skipped without a separate partial-coverage token, so empty evidence does not guarantee every window was compared.
4. **JNI self-registration table**: check function pointers in this library's static `JNINativeMethod methods[]` against its RX range. Out-of-range pointers emit `jni_self_hook:<index>`; a missing range emits `jni_self:no_range`. This does not read ART's current registered targets and does not guarantee detection of later `RegisterNatives` rebinding.

ART checks use public reflection to read native modifiers on `Method.invoke`, `Runtime.exec`, `File.exists`, and `NativeCollectorBridge.isNativeAvailable`, without fixed ArtMethod offsets. They also inspect the ClassLoader parent chain and six reflection/registration-related JNIEnv slots against libart RX. Unix-socket scanning passively reads known Frida/gum names from `/proc/net/unix`; W+X scanning checks self, libart, and libc. Some native subprobes still return empty strings on read failure without individual coverage status.

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
| `nGetSoIntegrityRaw` | `native_get_so_integrity_evidence` | SO FNV-1a |
| `nGetMountNsEvidenceRaw` | `mount_namespace_diff` | Self/PID 1 mount differences |
| `nGetKernelRootEvidenceRaw` | `kernel_su_probe` | prctl / SELinux context |
| `nGetSealedVerdictRaw` / `nVerifySealedVerdictRaw` | `sealed_verdict` | Build sealed payload / verify and return score |
| `nGetJniSelfIntegrityRaw` | `native_get_jni_self_table_evidence` | Static self-registration pointer ranges |
| `nGetMonitorFindingsRaw` / `nStopMonitorRaw` | `periodic_monitor` | Read latched findings / request stop |

JNI strings never pass untrusted bytes to `NewStringUTF`: the implementation caps length, validates UTF-8, replaces malformed sequences, and constructs UTF-16 with `NewString`. C++ allocation failures and JNI character-access failures do not leave exceptions across the boundary. JNI registration failures clear pending exceptions and log the target class.

### 6.7 Native build hardening

- `-fstack-protector-strong`, Release `_FORTIFY_SOURCE=2`, `-Wformat -Wformat-security`
- `-fvisibility=hidden`
- Link: `relro,now`, `noexecstack`, `max-page-size=16384`, `--exclude-libs,ALL`
- Release adds thin LTO, removes unwind tables/frame pointers, merges constants, garbage-collects sections, and strips symbols. The `exports.map` version script exports only `JNI_OnLoad` and `JNI_OnUnload`; JNI methods still bind through `RegisterNatives`.

### 6.8 Sealed payload and periodic monitor

The sealed blob is 64 hex characters encoding an 8-byte nonce, 4-byte flags, 4-byte score, 8-byte monotonic timestamp, and 8-byte tag. A 32-byte key comes first from `/dev/urandom`, then `AT_RANDOM`, then an address/tid-derived fallback. Key initialization is serialized. The tag is custom keyed FNV-1a, **not HMAC or a standard cryptographic MAC**. Verification checks length, tag, and a 10-second monotonic freshness window. This avoids concurrent issuers invalidating each other while rejecting stale replay. The key lives in process memory, and Java calls/final scoring remain mutable, so this is not attestation.

`JNI_OnLoad` starts a joinable pthread. After each interruptible 20–26-second wait it checks self code, TracerPid, self/libart W+X, and Frida/LSPosed mappings. Deduplicated `late_*` findings accumulate and reads include `passes:<n>`. No frozen report is changed and no callback is pushed; a later `hook_framework` collection consumes findings. The monitor does not repeat full root/emulator scans.

`shutdown()` wakes and joins the monitor. Reinitialization uses an explicit JNI restart entry point and clears findings/pass counts. `JNI_OnUnload` also joins the thread before code can be unmapped.

## 7. Shared signals

Each report owns a new `SignalSnapshot`. Timed-out platform/native work can finish late without repopulating a later report's cache. `SignalResult<T>` preserves success / empty / unavailable / error. Collectors and detectors share:

- ADB state, system properties, `/proc/self/maps` (Java path)
- Loopback listening ports, process snapshots, text files, path existence, container signals
- Structured `ShellExecutor.Result` for the same command
- SELinux, `build.prop` fingerprint, CPU/disk/kernel, native process tokens, SO integrity, screen metrics

ADB collection is therefore not duplicated, and Java hook/debug checks reuse maps and ports. Native hook maps remain an independent raw-syscall read.

`ShellExecutor.Result` distinguishes `SUCCESS`, `INVALID_COMMAND`, `TIMEOUT`, `NON_ZERO_EXIT`, `INTERRUPTED`, and `EXECUTION_ERROR`, and carries stdout, stderr, exit code, duration, and failure reason. String-only helpers are deprecated.

New shared signals include GPU vendor/renderer, network-interface names, namespace/kernel-root evidence, JNI self-integrity, and sealed verdicts. `getGpuIdentity()` caches an offscreen probe for emulator/cloud detectors, but `GpuInfoCollector` still probes independently, so a report may create two EGL contexts. Interface names use sysfs first and Java enumeration only when empty, without comparing the two. System properties now use only the native allowlisted accessor; shell `getprop` fallback was removed and empty properties retain EMPTY status.

## 8. Scene, family dedupe, and correlation

`DataAggregator.aggregate` order:

1. `CorrelationEngine.dedupeFamilies`: if an `EvidenceFamily` (`frida` / `debugger` / `xposed` / `root_fw` / `qemu`) is already claimed by an earlier detector, a later actionable result with `score > 0` becomes informational. Magisk must not add score twice via `root` and `process_scan`.
2. `CorrelationEngine.applyScene`: lifts named detectors from informational to actionable for the scene. It never disables a detector and never downgrades an already-actionable result.
3. `CorrelationEngine.correlate`: may append one `signal_correlation` result.
4. Collector coverage signals, multi-source inconsistency, existing synthesized fields.
5. Layered fingerprint IDs, continuity comparison, and optional `fingerprint_continuity`. This final detection does not pass through scene/deduplication/correlation again and is absent from the earlier `runtime_integrity_score_inputs` summary.

## 8.1 Scene lifts

| Scene | Made actionable |
| --- | --- |
| `STANDARD` | Nothing extra |
| `LOGIN` | `emulator`, `cloud_phone`, `sandbox` |
| `PAYMENT` | LOGIN + `adb` |
| `DIAGNOSTIC` | Every informational result except debug-and-debuggable-only |

## 8.2 Correlation rules

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

Coverage currently excludes only the synthetic `hook_memory_signals` and `runtime_integrity_score_inputs` fields; `fingerprint_id` still counts (§4.4).

Aggregation freezes `RiskReport`, `DeviceFingerprint`, and nested `CollectorResult`s.

## 10. Privacy

| Profile | Android ID | Boot ID | Widevine |
| --- | --- | --- | --- |
| `MINIMAL` | off | off | off |
| `BALANCED` | on | off | off |
| `DIAGNOSTIC` | on | on | on |

Each of the three can be overridden on the Builder. `PrivacyUtils.hashIdentifier` computes hex `SHA-256(packageName + ":" + value)`. That is an app-scoped pseudonym, not encryption or anonymization.

The SDK does not collect raw IMEI, IMSI, MAC, SSID, or BSSID. Native property reads are constrained by the ini allowlist.

The five new hardware collectors and layered IDs run in every profile; `MINIMAL` does not disable them or `FingerprintStore`. Installation salt/digests live in private preferences and are normally removed by uninstall/data clearing. Keystore-based cross-reinstall linkage is not implemented; host backup/restore policy still affects persistence. A fixed-salt fallback on storage failure does not guarantee installation isolation.

## 11. Single-source lists

Read-only manifest: `riskengine-sdk/src/main/resources/lists/artifact_paths.ini`.

Generated mirrors (checked in; must be regenerated when the ini changes):

- `riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java`
- `riskengine-sdk/src/main/cpp/generated/detection_lists.h`

`RootPathListConsistencyTest` fails if the Java arrays drift from the ini. Sections cover su / magisk / kernelsu / apatch / modules / emulator files and packages / cloud packages / sandbox packages / properties / process tokens.

This change adds `[tamper_tool_paths]` and property entries and expands generated Java/native lists. Groups such as `PARTITION_FINGERPRINT_PROPERTIES`, `CLOUD_PHONE_PROPERTIES`, `VIRTUAL_GPU_MARKERS`, and `list_monitored_libc_symbols()` are also defined in generated source; not every group has a matching ini section. `ObfuscatedLists` has not replaced plaintext Java lists.

## 12. JSON

`RiskReportJsonSerializer` uses `org.json` (provided by the Android framework; unit tests depend on `org.json:json`). Root fields:

`timestampMs`, `sdkVersion`, `riskScore`, `maxRiskScore`, `displayThresholdMaximum`, `warningCount`, `dangerCount`, `unknownCount`, `availableDetectionCount`, `detectionCount`, `checkCount`, `completedCheckCount`, `incompleteCheckCount`, `coveragePercent`, `reportStatus`, `overallRiskLevel`, `collectScene`, `fingerprint`, `detections`.

Each detection includes `detectorName`, `riskLevel`, `status`, `executionStatus`, `score`, `maxScore`, `informational`, `checksAttempted`/`Succeeded`/`Failed`, `failureReasons`, `details`, `evidence`, `timestampMs`.

The serializer does not add a top-level `fingerprintId`; the Java getter does not automatically become a JSON field. Layered IDs and continuity use the existing collector serialization path at `fingerprint.fingerprint_id.values`, with string values. The hardware contributing-field list is available only on the Java `FingerprintId` model.

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

This commit does not update Demo name mappings or layouts. New detectors/collectors use the existing generic presentation path; there is no dedicated layered-ID/continuity interface yet.

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

`integration-test` only compiles and links the public API; it does not run device detections. There is currently no automated device-matrix workflow. `Adversarial_Matrix.md` describes expected evidence and cannot replace ARM64 OEM validation.

The September review reran 56 unit tests successfully and compiled all four Native ABIs. New EGL/ART/kernel/monitor behavior still needs device validation; host-side success does not establish detector accuracy on OEM devices.

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

- Namespace comparison depends on PID 1 procfs visibility and does not guarantee detection of complete DenyList/Shamiko hiding. Namespace differences and directory-listing contradictions can also arise from legitimate isolation or read timing.
- Failure semantics are intentionally conservative: `root` and the sealed verdict record `ns_unreadable:*` as coverage loss without adding risk points. The monitor can still latch late integrity findings, so a `native_tamper` `UNAVAILABLE` result does not imply that every later integrity path is unavailable.
- Sealed verification accepts authenticated blobs for a bounded 10-second freshness window to support concurrent requests. JNI self-checks inspect only the static registration table, not ART's live binding targets. See §5–6.
- x86/i386 has no ARM trampoline heuristic; GOT and FNV-1a comparisons still run. FNV-1a is not a cryptographic hash.
- Virtual GPUs, ethN, partition fingerprint differences, dynamic core counts, ClassLoader/dexElements, and anonymous mappings can have legitimate sources. OEM hardware and host-framework regression are required; offscreen GPU collection still needs driver compatibility validation.
- Layered IDs depend on available fields and installation salt and cannot guarantee unique identification across reinstall or firmware changes.
- Local signals, Java decisions, and in-process native keys can be tampered with. The SDK does not replace server risk analysis, hardware attestation, or Play Integrity.
