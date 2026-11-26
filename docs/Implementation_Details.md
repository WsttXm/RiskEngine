# RiskEngine Implementation Details

This document is the contract implemented by the current source, not a statement of intent. Host integration is in [README.md](../README.md). Expected evidence families on typical fixtures are in [Adversarial_Matrix.md](./Adversarial_Matrix.md). Server-side offline envelope verification is documented in [Signed_Envelope_Verification.md](./Signed_Envelope_Verification.md).

Updated against the `2.0.0-SNAPSHOT` (v2.0.0 Finalization) implementation.

## 1. Scope and modules

RiskEngine is a local Android risk-signal, hardware-attestation, and device-fingerprinting SDK. Java owns non-blocking orchestration, push-pull lifecycle, privacy, normalized `0–100` four-dimensional scoring (`RiskScoringEngine`), host-configurable local policy (`RiskPolicy`), structured evidence (`EvidenceItem`), security hygiene (`DevicePosture`), versioned layered fingerprints (`FingerprintVersion` V1/V2), hardware Keystore binding, TEE/KeyMint/RKP X.509 attestation + offline-verifiable `SignedRiskEnvelope` (`v=2`), curated threat-app / HMA behavioral probes (`ThreatAppPolicy`), and the final report. C++17 JNI owns libc-hook-resistant inline-syscall I/O, environment probes, raw `base.apk` signing verification, dual-path anti-debug & optional `PR_SET_DUMPABLE(0)`, COW-safe self-integrity (inside `hook_framework`), Widevine NDK parity, TEE Binder `ioctl` probes, disposable-child HMA UID/Seccomp-notif side-channels, the `NativePayloadCodec` wire protocol, and the event-driven periodic monitor. RiskEngine ships as a single zero-dependency core SDK (`:riskengine-sdk`) with zero server dependency, zero telemetry, and zero Play Integrity / Kotlin / 3rd-party runtime dependencies (see [ADR-0001](./adr/0001-single-core-sdk-without-extension-submodules.md)).

| Module | Role |
| --- | --- |
| `riskengine-sdk` | Publishable core AAR. Java 11 bytecode (built with JDK 17), minSdk 30, compileSdk 36, targetSdk 36. Zero 3rd-party runtime dependencies, zero `<uses-permission>`, zero `useAppZygote`; Public ABI locked via JDK 17 `javap` (`api/riskengine-sdk.api`); the AAR itself is not minified |
| `demo` | Local diagnostic console on Fluid Design v2 (privacy consent gate before `initIfNeeded`, `0–100` 3-tier progressive `RiskGaugeView`, 4-dimension sub-score bars, recommended `RiskAction` badge, Assessment Confidence, expandable `ScoreBreakdown` sheet, layered fingerprint continuity/bucket card + `resetFingerprintBaseline()`, live `ThreatStreamDrawer`, and `ReportFormatter` consuming all 16 converged Detection Domains). Debug is temporarily signed; Release is minified but unsigned |
| `integration-test` | Depends strictly on the standalone Release AAR binary (`riskengine-sdk-release.aar`); runs L3 end-to-end instrumentation (`SmokeActivity` + `RiskEngineInstrumentationTest`) across GitHub Actions KVM API 30/34/36 emulators |

Current development version: `2.0.0-SNAPSHOT` (`riskEngineVersion` in `gradle.properties`). Tag release workflows override `releaseVersionName`.

## 2. Architecture, tiered scheduling & collection flow

```text
host call (pull collect/collectSync/collectSignedEnvelopeSync OR push startMonitoring)
  -> RiskEngine lifecycle snapshot (generation, config, registries, lock)
  -> single coordinator serializes requests (queue cap 16)
  -> collectionLock (queue wait is inside the deadline)
  -> SignalSnapshot.reset()
  -> Tiered worker pool execution (TaskScheduler.submitAllWithSafeTimeout -> SafeExecutor.safeWithTimeout)
       Stage 1 CRITICAL: app_integrity, debug, hook_framework  -> onCriticalChecksFinished(TierReport, 0–100 scale)
       Stage 2 FAST:     11 fast detectors                     -> onFastChecksFinished(TierReport, 0–100 scale)
       Stage 3 POSTPONED: 22/24 collectors + tee_integrity (TEE/KeyMint/RKP + Grant-Domain split)
                          + threat_apps (Official Cert Lineage + HMA/Thanox Side-Channels)
                          + dual-pass detector postponed probes
                          (consistency, root, mount_analysis, hook_framework, emulator, cloud_phone, multi_instance)
                          -> full DataAggregator
  -> DataAggregator
       applyPolicy (CollectScene + RiskPolicy overrides)
       -> order-independent family-max dedupeFamilies -> correlate (C1–C10)
       -> collector ERROR coverage / multi-source inconsistency
       -> FingerprintIdBuilder (V1/V2 + Stability + Hasher) + FingerprintStore (AES-256-GCM DE + anchor + device_binding)
       -> DevicePosture closure (systemVpn, unofficialStore, lockscreenOrBiometricReset)
       -> multi-source EvidenceItem auto-merge (JAVA + NATIVE -> mergedSources)
       -> RiskScoringEngine (0–100 4-dimension Noisy-OR, Corroboration Lift, pure-LOW cap <= 35,
          Hard Trigger floor 95–100, tiered Assessment Confidence, ScoreBreakdown, RiskAction, TrustTier)
       -> synthesized fields (hook_memory_signals / runtime_integrity_score_inputs / fingerprint_id)
  -> immutable RiskReport / optional SignedRiskEnvelope (v=2, ECDSA P-256) / additive JSON v2
     / onPostponedChecksFinished + DeviceStateListener
```

- **Zero-blocking `init()`**: `NativeCollectorBridge` removes the blocking `static {}` `System.loadLibrary()` in favor of idempotent lazy `ensureNativeLoaded()` / `isNativeLoaded()`. `RiskEngine.init()` / `initIfNeeded()` performs zero synchronous `SharedPreferences`, Keystore, or `.so` loading on the caller thread; an async bootstrap task loads `libriskengine.so`, applies `enableAntiDumpable`, starts the native periodic monitor (generation-guarded with lock-free compensating stop if `shutdown()` races), and warms up `FingerprintStore`.
- `TaskScheduler` separates the coordinator from the 4-thread worker pool and enforces `TierBudgets` (`CRITICAL`, `FAST`, `POSTPONED`) via `SafeExecutor.safeWithTimeout` (which captures blocking `StackTraceElement[]` diagnostics on timeout and uses a `ThreadLocal<Boolean>` guard against nested-timeout pool starvation).
- Asynchronous requests that hit a full or shut-down queue call `onError` (`RejectedExecutionException` wrapped as `IllegalStateException`).
- `collectTimeout` starts when the request is queued. Work that misses the deadline is filled in by `addMissingCollectorResults` / `addMissingDetectionResults` as explicit timeout/error coverage.
- Synchronous collection rejects the Android main thread. Asynchronous and push callbacks run on SDK background threads.
- `shutdown()` atomically advances `lifecycleGeneration`, clears push listeners, unregisters `AppLifecycleObserver`, cancels work, and clears registries inside `synchronized (lifecycleLock)`, then **releases `lifecycleLock` before** calling native `native_monitor_stop()` (which joins its pthread outside its internal mutex).

## 3. Lifecycle, Push-Pull & Window Hardening API

| API | Behavior |
| --- | --- |
| `init(context, config)` | Non-blocking strict initialization; duplicate calls throw `IllegalStateException` |
| `initIfNeeded(context, config)` | Atomic initialize-if-absent; returns `false` when already initialized |
| `startMonitoring(threat, state, exec)` | Atomically binds `ThreatListener`, `DeviceStateListener`, `ExecutionStateListener` under `lifecycleLock`, runs `CRITICAL -> FAST -> POSTPONED` tiered startup scan, and routes async native monitor & screen capture/recording pushes |
| `stopMonitoring()` | Atomically clears push listeners & advances `monitoringGeneration` without shutting down |
| `collect(callback)` / `collect(scene, callback)` | Asynchronous pull collection |
| `collectSync()` / `collectSync(scene)` | Full synchronous pull collection; throws on the main thread |
| `collectSignedEnvelopeSync(scene, challenge, mode)` | Synchronous collection + ECDSA P-256 hardware-attested `SignedRiskEnvelope` (`v=2`, `EnvelopeMode.PERSISTENT_KEY` default fast path `< 10ms` or `EnvelopeMode.FRESH_ATTESTATION` per-request keypair with explicit `SOFTWARE_FALLBACK` on non-hardware devices) |
| `collectReportJson()` / `reportToJson(report)` | Collect+serialize or serialize-only additive JSON v2 (`SignedRiskEnvelope.toJson()` / `RiskReportJsonSerializer.serialize(report, envelope)` appends optional `signedEnvelope`) |
| `resetFingerprintBaseline()` | Explicitly clear/re-anchor the immutable hardware baseline while preserving the installation salt |
| `getReportJson()` | Deprecated alias for `collectReportJson()` |
| `shutdown()` | Cancel work, unregister `AppLifecycleObserver`, release resources, and join native monitor outside `lifecycleLock`; fingerprint storage is retained |
| `RiskPolicy` / `RiskPolicy.Builder` | Immutable local policy layered over a `CollectScene` preset: `dimensionWeight`, `actionThresholds`, `highAction`, `allowlistFamily`, `informationalOnlyFamily`, `familyMode`, `familyMultiplier`, `suppressHardTrigger`; attached via `RiskEngineConfig.Builder.riskPolicy(...)` |
| `RiskWindowGuard` | Explicit host opt-in helpers: `enableScreenCaptureProtection(Activity, boolean)` (`FLAG_SECURE`), `enableOverlayProtection(Activity, boolean)` (API 31+ `setHideOverlayWindows`), `enableTouchObscuredFilter(View, boolean)` |

Config defaults: all 16 converged Detection Domains enabled (`enableTeeAttestation=true`, `enableThreatAppDetection=true`), `debugLog=false`, timeout `10_000 ms`, `PrivacyProfile.BALANCED`, `CollectScene.STANDARD`, `RiskPolicy.forScene(CollectScene.STANDARD)`, `FingerprintVersion.V2`, `FingerprintStability.OPTIMAL`, `enableAntiDumpable=false`, `enableIsolatedProcessProbe=true`, `enablePeriodicMonitor=true`. `consistency` is always registered.

- **Dual-pass `POSTPONED` tiering**: `BaseDetector` exposes `hasPostponedProbes()` / `detectPostponed(DetectionResult prior)` / `callPostponed(prior)`. During `startMonitoring()` and `collectSync()`, Stage 1 (`CRITICAL`) and Stage 2 (`FAST`) return low-latency results first (scored on the same `0–100` scale via `RiskScoringEngine.evaluateTier`); Stage 3 (`POSTPONED`) executes `tee_integrity` plus heavy probes (`disposable_child` fork traps, `RiskIsolatedProbeService` mount diff & Keystore2 Grant-Domain chain split, `ZygiskProbe`, `LsposedProbe`, `SensorNoiseProbe`) across postponed-capable domains and merges them cleanly before final aggregation.
- **`RiskIsolatedProbeService` (`android:isolatedProcess="true"`)**: ephemeral cross-process helper for both `/proc/self/mountinfo` differential reads and Keystore2 Grant-Domain cross-UID certificate-chain validation (`IsolatedProbeClient.probeGrantDomainChain`). Fails closed (`onBind` returns `null`) unless `Process.isIsolated()` is `true`; `IsolatedProbeClient` enforces bounded timeouts and always calls `unbindService()` in `finally`. Hosts may opt out via `enableIsolatedProcessProbe(false)` or `tools:node="remove"` in their manifest.

## 4. Collectors (22 default / 24 in `DIAGNOSTIC`)

`CollectorResult.Status` is `SUCCESS`, `EMPTY`, `ERROR`, or `UNSUPPORTED`. Both `BaseCollector.call()` and `BaseDetector.call()` catch `Exception | LinkageError | OutOfMemoryError`.

`compareSources=true` is used only when every value is the same semantic field observed through a different source. Inconsistency emits `multi_source_validation` (`MEDIUM` / `WARNING` / score 4 / actionable).

### 4.1 Java layer (18 collectors)

| `fieldName` | Class | Contents | Privacy |
| --- | --- | --- | --- |
| `android_id` | `AndroidIdCollector` | App-scoped SHA-256 (package-name salt; `Uri.parse` inside try-guard) | `BALANCED`/`DIAGNOSTIC`; overridable by `collectAndroidId` |
| `build_props` | `BuildPropsCollector` | Non-sensitive `Build.*` | Always |
| `screen_info` | `ScreenInfoCollector` | Size, dpi, density | Always; shared via `SignalSnapshot` |
| `apk_signature` | `ApkSignatureCollector` | Signing-certificate hash | Always |
| `bluetooth_info` | `BluetoothCapabilityCollector` | Capability; no MAC | Always |
| `wifi_info` | `WifiInfoCollector` | Capability (e.g. Wi-Fi Direct); no SSID/BSSID/MAC | Always |
| `telephony` | `TelephonyCollector` | Phone type, SIM state; no IMEI/IMSI | Always |
| `settings` | `SettingsCollector` | Developer options and similar | Always |
| `adb_state` | `AdbStateCollector` | USB/Wi-Fi ADB | Always; shares `AdbInspector` |
| `container_signals` | `ContainerSignalCollector` | cgroup / container paths | Always |
| `gpu_info` | `GpuInfoCollector` | Offscreen EGL pbuffer (`eglReleaseThread()`, never `eglTerminate(EGL_DEFAULT_DISPLAY)`): vendor/renderer, GL/EGL versions, sorted extension hash, limits | Always |
| `sensor_fingerprint` | `SensorFingerprintCollector` | Sorted sensor-tuple and vendor-set hashes, counts and capabilities | Always |
| `cpu_topology` | `CpuTopologyCollector` | Runtime/sysfs/procfs core counts, implementer/part distribution, per-core frequency ranges, ABI, SoC (API 31+) | Always |
| `hardware_profile` | `HardwareProfileCollector` | Memory buckets, display modes/HDR, camera specs & hash, battery info, system shared-library-set hash | Always |
| `partition_fingerprints` | `PartitionFingerprintCollector` | Partition fingerprints, build date, verified boot/vbmeta properties | Always; native property allowlist |
| `codec_info` | `MediaCodecCollector` | Zero-permission `MediaCodecList(ALL_CODECS)` sorted codec/hardware-accelerated/software matrix digest & counts | Always |
| `input_devices` | `InputDeviceCollector` | Zero-permission `InputManager` sorted `(name, vendorId, productId, sources)` digest & virtual-input counts | Always |
| `security_posture` | `SecurityPostureCollector` | Zero-permission `Security.getProviders()` digest, `KeyguardManager.isDeviceSecure()`, `DevicePolicyManager` storage encryption, Keystore security level (`STRONGBOX`/`TEE`/`SOFTWARE`), biometric readiness, dev-options state | Always |

### 4.2 Native layer (JNI bridge, 4 default / 6 in `DIAGNOSTIC`)

| `fieldName` | Contents | Privacy |
| --- | --- | --- |
| `drm_id` | App-scoped Widevine hash | `DIAGNOSTIC` or `collectDrmId(true)` only |
| `boot_id` | App-scoped hash of `/proc/sys/kernel/random/boot_id` | `DIAGNOSTIC` or `collectBootId(true)` only |
| `system_properties_native` | Allowlisted properties from ini `[properties]`; partial SELinux denials record `partial_errors` while keeping `Status.SUCCESS` when `>= 1` succeeds | Always |
| `cpu_info` | Structured `CpuInfoParser` over `/proc/cpuinfo` (`commonInfo` + `perCoreInfo`; retains `flags` `hypervisor`/`vmx`/`svm` and `model name`; strips volatile `BogoMIPS` and `cpu MHz` from fingerprint hashes) | Always |
| `disk_size` | Data-partition size (`__NR_statfs` on 64-bit ABIs) | Always |
| `kernel_info` | `uname` and related | Always |

System-property lookups validate keys against the sorted compile-time 64-bit FNV-1a hash table `kAllowedPropertyHashes` (zero runtime OBF decoding or heap allocations).

### 4.3 Synthesized fields and coverage semantics

Appended by `DataAggregator` (excluded from coverage denominators): `hook_memory_signals`, `runtime_integrity_score_inputs`, `fingerprint_id`.

Only `Status.ERROR` (including timeouts) collectors emit `collector:<fieldName>` coverage failure entries and lower coverage. `UNSUPPORTED` and `EMPTY` increment `RiskReport.getUnsupportedCheckCount()` and never degrade a clean device from `SAFE` to `UNKNOWN`.

### 4.4 Versioned Layered Fingerprints (V1/V2), Hardware Binding & DirectBoot

`FingerprintIdBuilder` uses declarative `FingerprintSignalSpec` entries governed by `FingerprintVersion`, `FingerprintStability`, and pluggable `FingerprintHasher` (default UTF-8 SHA-256):

- **`FingerprintVersion.V1`** (frozen, locked by `FingerprintVersionGoldenTest`): 13 hardware fields across 5 physical buckets (`gpu`, `sensor`, `camera`, `cpu`, `memory_battery`), 11 system fields, 2 volatile fields; composite = `hash(salt|composite|hw|sys)`.
- **`FingerprintVersion.V2`** (default): adds `codec_info`, `input_devices`, `security_posture` provider digest, and structured `CpuInfoParser` output (excluding `BogoMIPS`/`cpu MHz`). `FingerprintVersion.LATEST` is `@Deprecated`.
- **`FingerprintStability`**: `STABLE` (physical hardware buckets only), `OPTIMAL` (default: hardware + system + new zero-permission dimensions), `UNIQUE` (includes enabled volatile IDs).
- **`isHardwareLayerReliable()`**: `true` iff `!hardwareId.isEmpty() && getHardwareCoveragePercent() >= 50` and at least 2 core physical buckets (`gpu`, `cpu`, `sensor`) are present.

`FingerprintStore` persists state in device-protected (DE) `riskengine_fp` SharedPreferences (`createDeviceProtectedStorageContext()`, executing one-time CE→DE migration only when `UserManager.isUserUnlocked()` is `true`):

- **Hardware wrapping**: `AndroidKeyStore` non-exportable `AES/GCM/NoPadding` key `riskengine_fp_wrap_key` (StrongBox preferred, auto-fallback to TEE, random 12-byte IV, 128-bit auth tag) protects the installation salt and anchor payload.
- **Immutable anchor vs drift**: `anchor_hw` / `anchor_hw_buckets` (auto-migrated from v1 `last_hw`) are never overwritten on `HARDWARE_CHANGED`; `drift_count` increments instead. Re-anchor explicitly via `RiskEngine.resetFingerprintBaseline()`.
- **Device binding clone/tamper check**: if persisted ciphertext exists while the `AndroidKeyStore` wrapping key is absent or GCM verification (`AEADBadTagException`) fails, emits `device_binding_broken` (`HIGH`/7 actionable in `fingerprint_continuity`, family `device_binding`).
- **Biometric/lockscreen invalidation sentinel**: detects `KeyPermanentlyInvalidatedException` and surfaces `devicePosture.lockscreenOrBiometricReset = true`.
- **Host backup exclusion**: hosts must exclude `riskengine_fp.xml` in both `sharedpref` and `device_sharedpref` inside `data_extraction_rules.xml` (API 31+) and `backup_rules.xml` (API 30).

## 5. Sixteen Converged Core Detection Domains

`BaseDetector.result(..., CheckCoverage)` maps `attempted == 0` / `succeeded == 0` → `UNAVAILABLE`, `failed > 0` with successes → `PARTIAL`, all succeeded → `SAFE` / `RISK`. Every detector attaches its `ScanTier` and emits `List<EvidenceItem>` alongside backward-compatible `details[]`.

### 5.1 `app_integrity` (`CRITICAL`, family `app_tamper`)

- **Hardcoded package name**: compares `Context.getPackageName()` against `config.expectedPackageName` → `pkg_name_mismatch` (`DEADLY`/10 hard trigger).
- **APK v2/v3/v3.1 signing lineage + Native raw `base.apk` cross-check**: Java `GET_SIGNING_CERTIFICATES` verifies all `apkContentsSigners` (when `hasMultipleSigners()`) or active cert + `signingCertificateHistory` lineage against `expectedSigningCertSha256Base64`. Native `nVerifyApkSigningCertRaw` opens `base.apk` via raw syscalls (from `/proc/self/maps` or `sourceDir`), parses ZIP EOCD / APK Signing Block v2/v3/v3.1 (fallback v1 JAR), computes certificate SHA-256, and cross-checks Java vs Native → `apk_sig_mismatch` / `apk_native_java_sig_conflict` (`DEADLY`/10 hard trigger), `apk_signing_lineage_mismatch` (`HIGH`/8).
- **Installer provenance**: API 30+ `getInstallSourceInfo()` checks `installingPackageName` / `initiatingPackageName` against presets or `trustedInstallerPackages` → `unofficial_installer:<pkg>` (`LOW`/2 info, sets `devicePosture.unofficialStore = true`).
- **Release obfuscation self-check**: on non-debuggable builds, checks whether `ObfuscationSentinel` class name remains unobfuscated → `release_unobfuscated` (`LOW`/2 info). `consumer-rules.pro` explicitly excludes `ObfuscationSentinel`.

### 5.2 `hook_framework` (`CRITICAL` + `POSTPONED`, families `hook_integrity` / `frida` / `xposed`)

- **Fast pass (`CRITICAL`)**: Java Xposed/Frida probes (35 ms bounded loopback port probes on `27042`; expected Android 10+ `/proc/net/tcp` SELinux `UNAVAILABLE` never degrades clean devices from `SAFE` to `UNKNOWN`) + Native `NativePayloadCodec` probes (maps, `/proc/self/fd` `fd:linjector` / `fd:frida:` [`frida-gadget`/`libgadget`], dual `comm`+`status Name:` threads [`pool-frida`/`pool-spawner`/`frida-helper`/`gdbus`; `gmain` collaborative+`IGNORE`], Unix sockets, W+X, `memfd` & anon `r-xp` 16B-validated ELFs via `pipe2`, `dl_iterate_phdr` vs `/proc/self/maps` diff with 4KB/16KB half-open overlap + live re-verify, read-only `sigaction` on `SIGSEGV`/`SIGTRAP`/`SIGILL`, ART reflection/JNI slots, COW-safe `SelfIntegrityProbe`) + background periodic monitor `late_*` latches (`late_frida_fd` ranked `STRONG`).
- **Postponed pass (`POSTPONED`)**: `ZygiskProbe` (`zygisk_atexit_probe.cpp`: parses disk `libc.so` `SHT_SYMTAB` for `_ZL7g_array` + LLVM SRA splits & `_ZL13g_atexit_lock` across API 30–37, strict `pthread_mutex_trylock`, `PipeMemoryReader`, pre/post map intersection flagging anon-exec callbacks `STRONG` and `>= 3` runtime-anchored holes `MEDIUM`), `LsposedProbe` (Binder magic `0x5F4C5350` on `activity`/`serial`, Zygote granted-permission vs `/proc/self/status` `Groups:` AOSP `platform.xml` GID audit, protected-API exception stack, `Thread.getAllStackTraces()`, `UncaughtExceptionHandler`), plus extra Frida D-Bus ports `27043–27045`.

Scoring: strong≥2 or (strong≥1 and medium≥2) → `DEADLY`/10; strong≥1 or medium≥2 → `HIGH`/8; medium≥1 → `MEDIUM`/2/informational; remaining weak → `LOW`/1/informational.

### 5.3 `debug` (`CRITICAL`, family `debugger`)

Native `OBF`-protected `nGetDebugEvidenceRaw()` (over `NativePayloadCodec`, preserving `nativeGetTracerPidRaw()` compatibility):
- Dual-path `TracerPid` across `/proc/self/status`, `/proc/<pid>/task/<pid>/status`, `/proc/self/task/*/status` + cross-path mismatch (`tracer_pid:`, `tracer_pid_mismatch:`).
- `/proc/self/task/*/stat` field-3 lowercase `'t'` (locating last `')'` to safely handle process names with spaces/parentheses) (`stat_tracing_stop:`).
- `/proc/self/task/*/wchan` `ptrace_stop` (`wchan_ptrace_stop:`).
- JDWP threads (`JDWP`/`ADB connection`) and abstract socket `@jdwp-control` (`jdwp_thread:`, `jdwp_socket:`).

Scoring: active tracer/stop/mismatch (`tracer_pid:`, `tracer_pid_mismatch:`, `stat_tracing_stop:`, `wchan_ptrace_stop:`) → `HIGH`/`DANGER`/8; debugger connection / JDWP / executable maps debug paths → `MEDIUM`/4; `debuggable_flag`-only or IDA port → `LOW`/1/informational (remains informational across all 4 scenes including `DIAGNOSTIC`).

### 5.4 `root` & `mount_analysis` (`FAST` + `POSTPONED`, family `root_fw`)

- `root`: Java path probes + cached `SignalSnapshot.getNativeRootEvidence()` + `kernel_sidechannel_probe.cpp` (fast KernelPatch `sys_truncate`, KSU `reboot`/ioctl, SUSFS path/mount probes, Netlink cap leak + Stage 3 `disposable_child` KSU timing side-channel) + `selinux_audit_probe.cpp` (enforce conflict, status page ABI/header, controlled context probing, zero-PII Netlink policy-reload leaks). Strong `HIGH`/8, Medium `MEDIUM`/4, Weak `LOW`/1/info (`busybox` never triggers standalone actionable risk).
- `mount_analysis`: `/proc/mounts` & `/proc/self/mountinfo` + `mount_forensics.cpp` (`statx(STATX_MNT_ID)` double-check vs `mountinfo`, RO partition exact comma-tokenized `rw`, zero-init 3-way `fstatat` `st_mtime`, `statfs` `overlayfs`/`tmpfs`) + Stage 3 `RiskIsolatedProbeService` cross-process mount diff (`MountViewNormalizer` suppressing pure Mount ID gaps and OEM noise). Strong `HIGH`/8, Medium `MEDIUM`/4 actionable; pairs with clean `root` for `C9:stealth_root_with_unmount`.

### 5.5 `multi_instance` (`FAST` + `POSTPONED`, family `virtual_container`)

Zero hidden reflection. Combines `InstallTokenSanitizer` (strips 16–32 char Base64 install tokens to prevent random `ksu`/`Riru` false positives) with:
- Canonical `filesDir`/`dataDir`/`sourceDir` depth & `uid / 100000` separation: primary user `0` and Work Profile `10..89` are clean; OEM dual-app (`999`, `>=900`, `95`, `128..150`) → `oem_dual_app:` (`LOW`/2 info in `STANDARD`, actionable in `LOGIN`/`PAYMENT`).
- Nested VirtualApp/ParallelSpace/BlackBox container paths, `user_id_path_mismatch:`, `dir_uid_mismatch:` (`st_uid` vs `Process.myUid()`), `multi_apk_maps:`, `container_maps_artifact:`, and `binder_dynamic_proxy:` (`Proxy$` on `ActivityManager`/`PackageManager`) → `MEDIUM`/5 actionable.
- Stage 3 (`POSTPONED`): consumes `virtualization_traps.cpp` `sacrificial_syscall_pack` (`disposable_child` comparing libc `syscall()` vs raw inline asm for `statx`/`memfd_create`/`renameat2` + seccomp-isolated `openat2`/`pidfd_open`) → `sacrificial_syscall_mismatch` (`MEDIUM`/5 actionable, `NATIVE`/`STRONG`).

### 5.6 `network_risk` (`FAST`, family `network_mitm`)

Zero `<uses-permission>`:
- `AndroidCAStore` `user:` aliases & `/data/misc/user/<uid>/cacerts-added` (`user_ca_cert:`) → `MEDIUM`/5 actionable.
- Runtime-guarded `ConnectivityManager` `TRANSPORT_VPN` with `/sys/class/net` (`tun*`/`ppp*`/`wg*`/`utun*`) fallback (`vpn_active:`, populates `devicePosture.systemVpn`), proxy source tag without credentials (`http_proxy:`), official proxy tool cert SHA-256 (`proxy_tool_cert:`), and read-only `/data/adb/modules/{box4,box_for_root}` (`proxy_module:`) → `LOW`/2 info in `STANDARD`, `proxy_tool_cert:`/`proxy_module:` elevate to actionable `MEDIUM`/4 in `PAYMENT`.

### 5.7 `location_risk` (`FAST`, family `location_spoof`)

Zero location permissions, zero coordinate PII:
- Local `Location` contract canary (injectable `LocationCanaryAdapter`, safe on JVM default stubs): tests getter/setter round-trip, `reset()`/field-mask parity, and API 31+ `setMock`/`isMock` → `location_canary_tamper:` (`HIGH`/7 actionable in all scenes).
- Optional host-permitted cached `Location.isMock()` (`cached_location_mock:`) + `AppOpsManager` `OPSTR_MOCK_LOCATION` (`mock_location_appop_allowed`) → `MEDIUM`/4 info in `STANDARD`, actionable in `LOGIN`/`PAYMENT`.

### 5.8 `screen_and_fraud` (`FAST`, families `screen_control` / `fraud_context`)

Zero extra permissions:
- `virtual_display:` (presentation/virtual displays), `third_party_a11y:` (excludes system services), `virtual_input:` (non-builtin virtual inputs), plus static capture/recording state updated by `AppLifecycleObserver` (`screen_capture_observed`, `screen_recording_active`) → `MEDIUM`/4 actionable (`PAYMENT` elevates screen sharing/3rd-party a11y to `HIGH`/7).
- `ongoing_call:` (`AudioManager` call modes) → `LOW`/1 info alone; combines with screen sharing or 3rd-party a11y in `PAYMENT` for `C10:vishing_fraud_combo` (`HIGH`/8).
- `time_spoofing:` (`currentTimeMillis < Build.TIME`, `AUTO_TIME == 0`, wall-vs-`elapsedRealtime` rollback/jump) → `MEDIUM`/4 actionable in all scenes.

### 5.9 `adb`, `emulator`, `cloud_phone`, `custom_rom`, `consistency` (`FAST` / `POSTPONED`)

- `adb`: `AdbInspector` adds conditional 1.5s 2-sample debounce (0 sleep on clean consistent devices) and `native_get_adb_protocol_evidence()` (`/dev/socket/adbd` 3-way `fstatat` + sibling `ENOENT` sentinel + non-blocking `@jdwp-control` + `init.svc.adbd`). Persistent hidden-`adbd` contradiction → `HIGH`/7 actionable in all scenes; normal USB (`LOW`/2) / Wi-Fi (`MEDIUM`/4) stay informational until `PAYMENT`/`DIAGNOSTIC`.
- `emulator` (`FAST` + `POSTPONED`, family `emulator`): modern virtualization catalog (`Waydroid`/`Cuttlefish`/`WSA`/`Corellium`/`LDPlayer 9`/`MuMu 12` + AVF `>= 2` joint-marker guard), Native Bridge (`houdini`/`libnb`/`libndk_translation` `STRONG`), zero-SoC-hardware `MediaCodec` (`zero_hw_codec`), plus Stage 3 `sched_yield_low_cv` (`INFO`-only, never standalone actionable), ARM64 overflow-safe `cntvct_el0` clock drift, and joint-only `SensorNoiseProbe` (`<= 200ms`). Preserves `GpuClassifier` ANGLE-on-Vulkan exemption and never calls `eglTerminate(EGL_DEFAULT_DISPLAY)`.
- `cloud_phone` (`FAST` + `POSTPONED`, family `emulator`): strong `HIGH`/7, ≥2 weak `MEDIUM`/4, 1 weak `LOW`/1/info; corroborates zero-SoC-hardware `MediaCodec` and Stage 3 joint-only `SensorNoiseProbe` (`stddev == 0.0` paired with battery/camera/hardware anomaly); emits structured `EvidenceItem`s.
- `custom_rom` (`FAST`, family `custom_rom`): community ROM props, `custom_rom_probe.cpp` (`libstagefright.so` symbols + `framework-res.apk` multi-dev mapping) with Pixel/HarmonyOS false-positive guards; always `LOW`/1/info.
- `consistency` (`FAST` + `POSTPONED`, families `prop_tamper`/`boot_integrity`/`hw_spoof`): always registered; integrates `BootloaderProbe` (VBMeta empty-input digest trap `vbmeta_empty_input_digest` hard trigger + `ro.boot.flash.locked`/`ro.boot.verifiedbootstate`/`ro.boot.vbmeta.device_state` cross-check), `bionic_prop_forensics.cpp` (`prop_area` trie holes/serial/tail residuals + PlayIntegrityFix side-channels), `hardware_consistency_probe.cpp` (ARM64 `MIDR_EL1` via `disposable_child`, 3-source kernel consistency), and `WidevineParityProbe` (`widevine_ndk_probe.cpp` `AMediaDrm` vs Java `MediaDrm` L1/L3 securityLevel & `systemId` parity + `widevine_l3_with_strongbox_locked` / `widevine_java_ndk_mismatch`); strong spoofing `HIGH`/8; confirmed bootloader unlock / orange verified boot `MEDIUM`/4/info (`STANDARD`) → actionable `MEDIUM` (`LOGIN`) → `HIGH`/7 (`PAYMENT`).

### 5.10 `tee_integrity` (`POSTPONED`, family `tee_tamper`)

Enabled by default (`enableTeeAttestation=true`). Performs zero-dependency ASN.1/DER X.509 hardware Key Attestation & Keystore2 / Binder / VINTF adversarial auditing without external crypto libraries:

- **ASN.1/DER Attestation & Root/CRL Verification**: `KeyAttestationCollector` (StrongBox/TEE EC P-256 attestation chain + `AttestationCapability` + `RkpCapabilityProbe`), `Asn1DerParser` (strict minimal DER, 64 KiB cap, max depth 16), `KeyAttestationParser` (OID `1.3.6.1.4.1.11129.2.1.17` Keymaster v3/v4/KeyMint 100/200/300/400 schemas, `RootOfTrust`, `AttestationApplicationId`), `GoogleAttestationRootStore` (pinned Google Hardware Root RSA-4096/ECDSA-P384 + RKP ECDSA-P384 roots + built-in monotonic CRL floor + offline revoked-serial check).
- **TrickyStore / TEE Hook Countermeasures**:
  - `GrantDomainSplitProbe` (`RiskIsolatedProbeService` Keystore2 `Domain.GRANT` cross-UID certificate-chain split detection → `tee_grant_chain_split`, `DEADLY`/10 hard trigger).
  - `TeeNativeProbe` (`tee_binder_probe.cpp` `/dev/binder` `ioctl` trampoline & `libbinder`/`libkeystore2` hook verification → `tee_binder_ioctl_hook`, `DEADLY`/10 hard trigger).
  - `Keystore2DeepProbe` & `VintfHalAndErrorPathProbe` (OID `2.1.17` double-injection, `osPatchLevel` vs `ro.build.version.security_patch` contradiction, Keystore2 error-code path & VINTF HAL manifest checks).
  - Revoked keybox (`tee_keybox_revoked`) → `DEADLY`/10 hard trigger; untrusted root / invalid chain / RoT mismatch → `HIGH`/8; non-attested software fallback / OEM-signed quirks gracefully graded without false positives on genuine stock devices.

### 5.11 `threat_apps` (`POSTPONED`, families `root_fw` / `hma_hiding` / `threat_app`)

16th and final converged domain, enabled by default (`enableThreatAppDetection=true`), configurable via immutable `ThreatAppPolicy.Builder` (`additionalThreatPackages`, custom cert SHA-256s, custom permission combinations, and HMA probe toggles):

- **`ThreatAppPackageProbe` & `ThreatAppSignatureLibrary`**: inspects curated `<queries>` targets (synced 1:1 with `artifact_paths.ini` `[threat_app_packages]`, zero `<uses-permission>`) for full v2/v3/v3.1 certificate lineage (`apkContentsSigners` + `signingCertificateHistory`) across 10+ official release SHA-256 fingerprints (KernelSU, KSU-Next, SukiSU, Magisk, APatch, HideMyApplist, HMA-OSS, LSPosed, GameGuardian, LuckyPatcher, Shizuku), `Os.stat` `nativeLibraryDir` daemon payloads (`libksud.so`/`libapd.so`/`libmagisk.so`), and public manifest XML `android:zygotePreloadName` (zero blocked hidden-API reflection). Root manager hits map to `root_fw` so `DataAggregator` deduplicates them automatically with `root` and `mount_analysis`.
- **Full-Generation HMA & Thanox Side-Channels (`hma_hiding` family, `HIGH`/7 actionable in all 4 scenes)**:
  - `HmaUidVisibilityProbe` (`hma_uid_probe.cpp` strictly inside `disposable_child`): `__NR_getpriority(PRIO_USER, uid)` active-app-UID scan vs uncached `getPackagesForUid` (gated on host `QUERY_ALL_PACKAGES` + pre/post self-controls + TOCTOU recheck) plus zero-permission Linux >= 5.0 `SECCOMP_FILTER_FLAG_NEW_LISTENER` interception check.
  - `HmaCrossUserProbe`: cross-user `MATCH_ANY_USER` exception suppression (`NameNotFoundException`/`null` instead of `SecurityException`) validated against pre/post self-controls.
  - `HmaOrderedBroadcastProbe`: detects HMA-OSS #164 missing `resultTo` and #173 erroneous `isOrderedBroadcast()==true` via initial & interleaved before/between/after host self-controls on a background `HandlerThread`.
  - `HmaPermissionServiceProbe`: strictly gated to API >= 35 + host `QUERY_ALL_PACKAGES` + 1000ms hard wall-clock budget (truncated scans -> `PARTIAL`), using public `Context.checkPermission` / typed `IBinder.transact` + `Parcel` wire helpers (zero blocked hidden-API reflection per `D66`).
  - `ThanoxIpcProbe`: queries `dropbox` Binder and strictly requires `interfaceDescriptor == "github.tornaco.android.thanos.core.IThanos"` (zero FP on OriginOS/stock Android).
- Signed threat tools / Root managers / custom policy matches score `MEDIUM`/5 actionable across all 4 scenes.

### 5.12 Aggregator-appended synthetic detections

| Name | Source |
| --- | --- |
| `signal_correlation` | `CorrelationEngine.correlate` (`C1`–`C10`), §8 |
| `multi_source_validation` | Fingerprint multi-source inconsistency |
| `fingerprint_continuity` | Hardware drift (`HARDWARE_CHANGED`, `MEDIUM`/4) and/or Keystore `device_binding_broken` (`HIGH`/7) |
| `collector:<field>` | Coverage placeholder for `ERROR`/timed-out collectors (excludes `UNSUPPORTED`/`EMPTY`) |

## 6. Native layer

Shared library `libriskengine.so`. CMake 3.22.1, C++17, `-fno-exceptions -fno-rtti`, static libc++, hidden symbols (`exports.map`: only `JNI_OnLoad` and `JNI_OnUnload`).

- **Inline syscalls & streaming parsers**: 64-bit raw inline syscalls (`raw_syscall.h`, `syscall_wrapper.cpp` with `-EINTR` retry, `__NR_statfs`, 3-arg `__NR_faccessat` / 4-arg `__NR_faccessat2`), `getdents64` (`raw_dir.cpp`), streaming `maps_parser.cpp` (no 2 MiB truncation).
- **COW-safe memory reads, `disposable_child` & wire protocol**: `util/safe_mem_read.{h,cpp}` (`pipe2(O_CLOEXEC|O_NONBLOCK)` 4 KiB kernel `copy_from_user` + `PagemapReader`); `util/disposable_child.{h,cpp}` (pre-resolved raw Bionic `sigaction`/`sigprocmask` before `fork()`, raw `__NR_exit_group`, concurrency=1 mutex + clamped deadlines isolating `SIGSYS`/`SIGILL` & kernel side-channels); `util/payload_codec.{h,cpp}` ↔ `NativePayloadCodec`.
- **Polymorphic OBF & hashed allowlist**: `util/obf_str.h` (`ScopedObfString<N>` + `secure_zero`); compile-time FNV-1a `kAllowedPropertyHashes`.
- **Phase 2–4 native forensic modules**: `bionic_prop_forensics.cpp`, `hardware_consistency_probe.cpp`, `custom_rom_probe.cpp`, `kernel_sidechannel_probe.cpp`, `selinux_audit_probe.cpp`, `mount_forensics.cpp`, `zygisk_atexit_probe.cpp`, `virtualization_traps.cpp`, `widevine_ndk_probe.cpp` (`AMediaDrm` dlopen parity), `tee_binder_probe.cpp` (Binder `ioctl` & `libkeystore2`/`libbinder` hook audit), `hma_uid_probe.cpp` (`disposable_child` `getpriority(PRIO_USER)` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`), plus upgraded `native_debug_detector.cpp` (ADB protocol forensics) and `native_hook_detector.cpp` (FD/thread/anon-ELF/linker-diff/sigaction). All native code ships exclusively inside core `libriskengine.so`.
- **APK signing parser (`apk_sig_verifier.cpp`)**: raw-syscall ZIP EOCD + APK Signing Block v2/v3/v3.1 certificate SHA-256 extractor (fallback v1 JAR) exposed via `nVerifyApkSigningCertRaw`.
- **COW-safe self-integrity (`native_integrity.cpp`)**: 64 KiB windowed SHA-256 (`dl_iterate_phdr` + `SHF_EXECINSTR`/`PT_LOAD`, supporting `extractNativeLibs=false` and 16KB pages), 64-bit (`arm64-v8a`, `x86_64`) trampolines (with `branch_stays_in_image`), XOR-masked JNI table & core prologues, PLT + RELA/REL `STT_FUNC` GOT & `JNIEnv` verification.
- **Event-driven periodic monitor (`periodic_monitor.cpp`)**: started asynchronously by `RiskEngine.init()` when `enablePeriodicMonitor(true)` (NOT in `JNI_OnLoad`). Schedule: 2–4s initial pass, 20–26s foreground jitter, 120s background backoff, immediate recheck on foreground resume after `> 10s` in background. Checks dual-path `TracerPid`, W+X, `memfd`, `/proc/self/fd` (`late_frida_fd`), and COW-safe `.text`/prologue (`late_text_mismatch`). Pushes newly discovered `late_*` findings via lock-free JNI upcall to pre-cached `NativeMonitorDispatcher.onNativeThreatDetected` (`NewGlobalRef` cached in `JNI_OnLoad`). `AppLifecycleObserver` drives foreground/background notifications and permission-gated API 34/35 screen capture/recording hooks with zero `androidx.lifecycle` dependency.
- **Hardening & ELF gate**: `IS_RELEASE_LIKE` (`Release` & `RelWithDebInfo`) applies `-Os`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, ThinLTO, `--gc-sections`, `--icf=safe`, `--wrap=__cxa_demangle`, `--strip-all`, `llvm-strip -R .comment`, `max-page-size=16384`. `scripts/check-elf-hardening.sh` enforces 2 exports, stripped, no `.comment`, 16KB `LOAD` align, single-ABI `.so <= 2000 KiB`, AAR `<= 4 MiB` across both 64-bit ABIs (`arm64-v8a`, `x86_64`).

## 7. Shared signals (`SignalSnapshot`)

Per-request isolated cache covering ADB state, system properties, Java `/proc/self/maps`, loopback ports, process snapshots, text files, path existence, container signals, SELinux, `build.prop` fingerprint, `/proc/cmdline` boot props, CPU/disk/kernel, cached native root evidence, full GPU attributes, and network interface names.

## 8. Scene, `RiskPolicy`, 0–100 four-dimensional scoring & correlation

`DataAggregator.aggregate` order: `CorrelationEngine.applyPolicy(detections, effectivePolicy)` (applies `CollectScene` rules plus `ALLOWLIST` / `INFORMATIONAL_ONLY` overrides) → `CorrelationEngine.dedupeFamilies` (order-independent family-max winner selection across all 21 Evidence Families; non-winning duplicates stay visible as `deduped:corroborating_evidence`) → `CorrelationEngine.filterForCorrelation` & `correlate` (`C1`–`C10`, re-checked against policy) → collector `ERROR` coverage & multi-source inconsistency → Fingerprint v1/v2 & `FingerprintStore` continuity/device-binding → `mergeMultiSourceEvidence` → synthesized fields & `DevicePosture` closure → freeze `RiskReport` via `RiskScoringEngine.evaluate(...)` (also shared by `TierReport` via `RiskScoringEngine.evaluateTier(...)`) and compute `TrustTier` (upgrading to `STRONG_HARDWARE` when StrongBox/TEE attestation passes with locked verified boot and clean runtime).

### 8.1 Normalized 0–100 scoring engine (`RiskScoringEngine`, ADR-0002)

- **Four orthogonal `RiskDimension`s (21 Evidence Families mapped by `EvidenceFamily.dimensionOf`)**:
  - `TAMPERING` (6): `app_tamper`, `hook_integrity`, `frida`, `xposed`, `debugger`, `tee_tamper`
  - `PRIVILEGE` (8): `root_fw`, `boot_integrity`, `prop_tamper`, `hw_spoof`, `hma_hiding`, `device_binding`, `custom_rom`, `adb`
  - `ENVIRONMENT` (3): `emulator`, `virtual_container`, `threat_app`
  - `FRAUD_CONTEXT` (4): `network_mitm`, `location_spoof`, `screen_control`, `fraud_context`
- **Stage 1 — Order-independent family-max**: Internal `0..10` detector scores map monotonically to probability intensities (`0->0.00, 1->0.10, 2->0.18, 3->0.26, 4->0.38, 5->0.46, 6->0.54, 7->0.64, 8->0.72, 9->0.78, 10->0.92`). For each Evidence Family, the strongest actionable detector wins regardless of registration order; custom `RiskPolicy` family multipliers apply via weighted Noisy-OR (`1 - (1 - p)^m`).
- **Stage 2 — Corroboration Lift**: When an actionable family is confirmed across `>= 2` independent `EvidenceItem.SourceLayer`s (`JAVA`/`NATIVE`/`ISOLATED`/`HARDWARE`) or `>= 2` distinct Detection Domains, apply `+0.06` clamped at `0.95` and emit a `ScoreBreakdown.Category.CORROBORATION_LIFT` entry.
- **Stage 3 — Per-dimension Noisy-OR, pure-LOW cap & Hard Trigger floor**:
  - Within each `RiskDimension`, combine families via Noisy-OR (`1 - product(1 - p_i)`) scaled to `0–100`. If no family in the dimension reaches `MEDIUM` or higher, cap the dimension score at `PURE_LOW_DIMENSION_CAP = 35`.
  - Combine weighted dimensions (`1 - (1 - d)^w`) and active `C1`–`C10` correlation rule probabilities (`C1: 0.38`, `C2: 0.45`, `C3/C6/C8: 0.90`, `C4: 0.60`, `C5: 0.00`, `C7: 0.18`, `C9/C10: 0.64`) via Noisy-OR into `preFloorScore` (`0–100`).
  - Resolve authoritative Hard Triggers once via `RiskScoringEngine.extractHardTriggers(...)` (shared 1:1 with `SignedEnvelopeSigner`). Unless suppressed by `RiskPolicy`, any active Hard Trigger sets `overallRiskLevel = DEADLY`, `recommendedAction = BLOCK`, and floors `riskScore` at `min(100, 95 + 2 * (count - 1))`, recording `ScoreBreakdown.Category.HARD_TRIGGER_FLOOR`.
- **Stage 4 — Tiered Assessment Confidence, `RiskLevel` & `RiskAction`**:
  - `confidencePercent` (`0–100`) weights completed vs attempted checks by tier (`CRITICAL = 3`, `FAST = 2`, `POSTPONED = 1`, collectors = `1`, excluding `UNSUPPORTED`/`EMPTY`).
  - Default thresholds: `0 SAFE`, `1–29 LOW` (or informational-only at `0`), `30–59 MEDIUM` (`CHALLENGE`), `60–84 HIGH` (`RESTRICT`, or `BLOCK` in `PAYMENT`), `85–100 DEADLY` (`BLOCK`).
  - Zero-risk reports become `UNKNOWN` (`RiskAction.REVIEW`) **only** when a `CRITICAL` Detection Domain fails/times out/is unavailable, weighted `confidencePercent < 70`, or all detectors are unavailable. Single non-critical timeouts keep clean devices `SAFE` alongside honest `ReportStatus.PARTIAL` and reduced `confidencePercent`.
- **Immutable `RiskPolicy`**: `RiskPolicy.forScene(CollectScene)` and `RiskPolicy.builder(CollectScene)` allow host customization of `dimensionWeight`, `actionThresholds` (`1 <= challenge < restrict < block <= 100`), `highAction`, per-family `FamilyMode` (`DEFAULT` / `ALLOWLIST` / `INFORMATIONAL_ONLY`), `familyMultiplier`, and `suppressHardTrigger`. When `RiskEngine.collect(sceneOverride, ...)` is called with a custom policy configured, the policy is cleanly re-based to `sceneOverride` via `withBaseScene(...)`.

### 8.2 Correlation rules (`C1`–`C10`)

| ID | Condition | Internal Severity / Dimension |
| --- | --- | --- |
| C1 | Emulator ≤ `LOW`, `strong == 0`, useful weak signals (excl. hardware noise) ≥ 3 | `MEDIUM` / `WARNING` / 4 (`ENVIRONMENT`, `p=0.38`) |
| C2 | Exactly 1 STRONG + hypervisor/QEMU, emulator already `MEDIUM` | Raise to `HIGH` / `DANGER` / 4 (`ENVIRONMENT`, `p=0.45`) |
| C3 | Inline/GOT hook **and** Frida family | `DEADLY` / `DANGER` / 10, Hard Trigger (`TAMPERING`, `p=0.90`, floor `95–100`) |
| C4 | `syscall_mismatch` **and** module/Magisk mount | `HIGH` / `DANGER` / 8 (`PRIVILEGE`, `p=0.60`) |
| C5 | `prop_mismatch:fingerprint`, no `community_rom:`, emulator NORMAL | `LOW` / `WARNING` / 1 / informational (`PRIVILEGE`, `p=0.00`) |
| C6 | `C6:bridge_or_integrity_tamper`: native self-integrity tamper while Java hook probes claim clean, OR `UnsatisfiedLinkError` + stealth signals | `DEADLY` / `DANGER` / 10, Hard Trigger (`TAMPERING`, `p=0.90`, floor `95–100`) |
| C7 | `LOGIN`/`PAYMENT`, cloud phone `cloudStrong == 0` and ≥ 2 weak cloud signals | `LOW` / `WARNING` / 2 (`ENVIRONMENT`, `p=0.18`) |
| C8 | `C8:spoofed_verified_boot`: TEE `RootOfTrust` reports `deviceLocked=false` or non-`VERIFIED` boot state while `ro.boot.*` system properties claim locked/`green` (or `vbmeta_empty_input_digest` contradicts hardware state) | `DEADLY` / `DANGER` / 10, Hard Trigger (family `boot_integrity`, `PRIVILEGE`, `p=0.90`, floor `95–100`) |
| C9 | `C9:stealth_root_with_unmount`: isolated cross-process mount diff or Bionic `prop_area` hole/serial tamper while runnable conventional `root` checks are negative | `HIGH` / `DANGER` / 8 (family `root_fw`, `PRIVILEGE`, `p=0.64`) |
| C10 | `C10:vishing_fraud_combo` (`PAYMENT` only): `ongoing_call` **and** active screen sharing / virtual display or 3rd-party accessibility service | `HIGH` / `DANGER` / 8 (family `fraud_context`, `FRAUD_CONTEXT`, `p=0.64`) |

## 9. Additive JSON v2 & Signed Risk Envelope (`v=2`)

`RiskReportJsonSerializer` emits zero-dependency additive JSON v2 preserving backward compatibility:

- **Root**: `schemaVersion` (`2`), `riskScore` (`0–100`), `maxRiskScore` (`100`), `displayThresholdMaximum` (`100`), `confidencePercent` (`0–100`), `recommendedAction` (`ALLOW`/`CHALLENGE`/`RESTRICT`/`BLOCK`/`REVIEW`), `hardTriggers[]`, `dimensionScores` (`{TAMPERING, PRIVILEGE, ENVIRONMENT, FRAUD_CONTEXT}`), `scoreBreakdown[]` (`{category, key, dimension?, points, source}`), `unsupportedCheckCount`, `trustTier`, `devicePosture` (`hasPasscode`, `storageEncrypted`, `storageEncryptionStatus`, `keystoreLevel`, `biometricStatus`, `devMode`, `adbEnabled`, `systemVpn`, `unofficialStore`, `lockscreenOrBiometricReset`), `fingerprintId` (`version`, `stability`, `anchorDriftCount`, `compositeId`, `hardwareId`, `systemId`, `volatileId`, coverage metrics, `contributingFields[]`, `hardwareBucketDigests{}`).
- **`detections[]`**: `scanTier`, `evidenceFamilies[]`, `evidenceItems[]` (`{code, primarySource, mergedSources[], location, value, family?, rank}`).
- **Optional `signedEnvelope`** (`SignedRiskEnvelope.PROTOCOL_VERSION = 2`, 17-field canonical payload): `{payload, signatureBase64, certChainPem[], attestationMode, keySecurityLevel}`, where `payload` is the recursively key-sorted UTF-8 canonical JSON (`v=2`, `pkg`, `sdk`, `scene`, `ts`, `monoMs`, `challenge`, `riskLevel`, `score`, `action`, `confidence`, `dimensions`, `hardTriggers`, `coverage`, `fpComposite`, `fpHardware`, `reportSha256`) signed by ECDSA P-256 (`SHA256withECDSA`). Verified offline via the 6-step pipeline in `scripts/verify_risk_envelope.py` (`reject_score_threshold = 60`, `min_confidence = 70`, `min_coverage = 80`) and [Signed_Envelope_Verification.md](./Signed_Envelope_Verification.md).

## 10. ProGuard / R8

- SDK AAR `isMinifyEnabled = false`.
- `consumer-rules.pro` keeps `RiskEngine`, `RiskEngineConfig` (+ `Builder`), `ThreatAppPolicy` (+ `$*`), `RiskPolicy` (+ `$*`), `RiskEngineCallback`, `PrivacyProfile`, `CollectScene`, `ScanTier`, `EnvelopeMode`, `FingerprintVersion`, `FingerprintStability`, `FingerprintHasher`, `ThreatListener`, `DeviceStateListener`, `ExecutionStateListener`, `RiskWindowGuard`, `model.**` (incl. `RiskDimension`, `RiskAction`, `ScoreBreakdown` + `$*`, `EvidenceItem` + `$*`, `DevicePosture` + `$*`, `ThreatEvent`, `TierReport`, `SignedRiskEnvelope` + `$*`), `AttestationRecord$SecurityLevel`, `RiskIsolatedProbeService`, `IsolatedProbeClient`, `NativeCollectorBridge`, `NativeMonitorDispatcher.onNativeThreatDetected`, and all `native` methods.
- `com.wsttxm.riskenginesdk.detector.ObfuscationSentinel` is **intentionally NOT kept** so `AppIntegrityDetector` can verify R8 obfuscation in release builds.

## 11. Single-source lists, executable governance gates & L1–L3 test baseline

- Single source: `riskengine-sdk/src/main/resources/lists/artifact_paths.ini` → `:riskengine-sdk:generateDetectionLists` → obfuscated `DetectionLists.java` and `detection_lists.h` (incl. `kAllowedPropertyHashes`), synced 1:1 with `AndroidManifest.xml` `<queries>` (52 packages).
- **6 CI Static Governance Gates** (enforced by `scripts/ci-verify.sh` and `.github/workflows/ci.yml`):
  1. `scripts/check-evidence-records.py`: 1:1 `DetectorRegistry` ↔ `docs/evidence/*.md` (16/16 domains, 7 required contract headings each).
  2. `scripts/check-elf-hardening.sh` + `scripts/check-jni-and-dex.py`: 64-bit 2-ABI ELF hardening (2 JNI exports, 16KB align, stripped, no `.comment`, `.so <= 2000 KiB`, AAR `<= 4 MiB`), 41/41 JNI 1:1 parity, and Release R8 Dex `< 2,500` methods.
  3. `scripts/check-single-source-sync.py`: zero `<uses-permission>`, exact `<queries>` parity, xorshift32 byte-exact `DetectionLists.java` verification, and doc version alignment.
  4. `scripts/check-public-api.py` (`:riskengine-sdk:apiCheck` / `apiDump`): zero-plugin JDK 17 `javap` Public ABI lock (`riskengine-sdk/api/riskengine-sdk.api`), AAR `classes.jar` purity, and 0-dep POM check.
  5. `scripts/check-boundary-guards.py`: reflection allowlist audit (zero D66 blocked hidden-API reflection) and ban on UI display-text branching in core Java/C++.
  6. `.github/workflows/refresh-attestation-roots.yml` (`scripts/refresh_google_attestation_roots.py`): weekly scheduled + manual drift check for Google Hardware Attestation Roots & monotonic CRL floor.
- **L1 Pure-JVM Unit Tests**: core `:riskengine-sdk` covers all 16 converged Detection Domains (fast + postponed, incl. `ThreatAppDetector`, `HmaUidVisibilityProbe`, `HmaBehaviorProbesTest`, `tee_integrity`, `SignedRiskEnvelope` `v=2`), the `0–100` four-dimensional `RiskScoringEngine` and local `RiskPolicy` engine, all 24 collectors (`CrashFreedomMockTest`), cross-language golden vectors (`EnvelopeOfflineVerifierTest` driving `scripts/verify_risk_envelope.py`), V1/V2 golden vectors, hardware binding & DirectBoot migration, push-pull orchestration, `NativePayloadCodec`, `EvidenceItem` merge, and additive JSON v2. `:demo` runs JVM unit tests (`ReportFormatterScoringTest`) verifying `0–100` formatting, 4-dimension display, `RiskAction`, `ScoreBreakdown`, and 16-domain labels.
- **L2 Offline C++ Host Unit Tests**: `riskengine-sdk/src/test/cpp/` (`./scripts/run-cpp-tests.sh`, CMake + CTest with offline `mini_gtest.h` / optional system GTest) directly exercises production `maps_parser` (>4 MiB), `raw_dir` fuzzing, `DiskElf` 16KB/PT_LOAD, `bionic_prop_area`, `payload_codec`, 64-bit `looks_like_trampoline`, and `crypto_mini`.
- **L3 Binary-AAR Instrumentation**: `:integration-test` consumes standalone `riskengine-sdk-release.aar` and executes `SmokeActivity` + `RiskEngineInstrumentationTest` across GitHub Actions Linux KVM API 30 / 34 / 36 emulators.
