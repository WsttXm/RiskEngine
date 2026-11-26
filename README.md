# RiskEngine

[中文](./README_zh.md)

An Android SDK for local device fingerprinting, hardware-rooted attestation, and runtime risk detection (RASP). Built as a single zero-dependency pure Java 11 + C++17 JNI core (`:riskengine-sdk`, zero 3rd-party runtime dependencies, zero `<uses-permission>`), it collects device signals, runs **16 converged Detection Domains** across latency tiers, scores risk on a deterministic **0–100 four-dimensional local scoring engine** (`RiskScoringEngine` + immutable local `RiskPolicy`), and returns an explainable `RiskReport` / additive JSON v2 / offline-verifiable `SignedRiskEnvelope` (`v=2`) in pull mode or streams tiered updates and runtime alerts in push mode.

Core `:riskengine-sdk` has **no server, no reporting channel, and no Play Integrity or SafetyNet dependency**. Results stay on the device (with optional offline 6-step server verification via `SignedRiskEnvelope` `v=2`). The repository ships a clean 3-module single-core layout: `:riskengine-sdk`, `:demo`, and `:integration-test`.

The current development version is `2.0.1-SNAPSHOT` (64-bit native ABIs only; see [ADR-0003](./docs/adr/0003-drop-32bit-abi-support.md)).

## What it does and does not do

| Does | Does not |
| --- | --- |
| Collect non-sensitive device attributes and app-scoped identifier hashes | Collect raw IMEI / IMSI / MAC / SSID / BSSID or GPS coordinates |
| Detect root, mount tampering, hooks & native self-integrity, debugging, app integrity/repackaging, multi-instance/containers, network MitM/CA/VPN, location spoofing, screen sharing/vishing/time spoofing, emulators, cloud phones, ADB, custom ROMs, TEE/KeyMint tampering, threat apps/HMA hiding, and cross-source inconsistencies | Replace server-side risk analysis, remote policy orchestration, or Play Integrity |
| Separate active threats (`RiskReport` / `ThreatListener`) from device security hygiene (`DevicePosture` / `DeviceStateListener`) and decouple tiered Assessment Confidence (`confidencePercent`) from risk score | Silently treat a failed check as safe or degrade a clean device over unsupported hardware or a single non-critical probe timeout |
| Score risk deterministically on a `0–100` scale across 4 orthogonal `RiskDimension`s (`TAMPERING`, `PRIVILEGE`, `ENVIRONMENT`, `FRAUD_CONTEXT`) with auditable `ScoreBreakdown`, recommended `RiskAction`, and host-configurable local `RiskPolicy` | Require a backend service to customize thresholds, dimension weights, or family allowlists |
| Support non-blocking `init()` (`< 5 ms` caller thread), tiered push monitoring (`CRITICAL -> FAST -> POSTPONED`), and pull `collect()` / `collectSync()` | Block the Android main thread on `SharedPreferences`, Keystore, or `System.loadLibrary()` during `init()` |
| Change how signals are scored and acted upon per `CollectScene` / `RiskPolicy` | Disable detectors per scene |
| Show and copy a redacted report (with `0–100` score, 4-dimension bars, `RiskAction`, and `ScoreBreakdown`) in the Demo | Upload results or back them up to the cloud |

A capable adversary can tamper with userspace signals. Kernel mount-namespace hiding (a complete DenyList) cannot be proven from userspace without hardware attestation. Host apps should treat this SDK as one input among several.

## Capabilities (16 Converged Core Detectors + 22 Default Collectors)

| Area | Detectors | Tier | Primary signals |
| --- | --- | :---: | --- |
| Hardware TEE & KeyMint trust root | `tee_integrity` | `POSTPONED` | Zero-dependency root-first OID `.17` & canonical CBOR RKP OID `.30` parser, embedded Google Hardware Attestation Roots + monotonic offline CRL floor, StrongBox→TEE `AttestationCapability`, 5-vector native TrickyStore/Binder probe (`tee_binder_probe.cpp`: maps, `libbinder` `ioctl` GOT/16B inline via `PipeMemoryReader`, 3-way `BINDER_VERSION`, rotating-order Binder Honeypot, Leaf DER), Keystore2 `Domain.APP` vs `Domain.GRANT` isolated-UID chain-split (`bindIsolatedService`), API 31+ `generateKey` reply `TAG_USER_ID`, API 35+ Post-Processing parity, overwrite anti-cache trap, StrongBox constraints & VINTF KeyMint HAL / `OperationErrorPath` (with Samsung/Xiaomi MTK quirks) |
| Threat apps & HMA hiding | `threat_apps` | `POSTPONED` | Immutable host `ThreatAppPolicy` + curated official release cert SHA-256 library (KernelSU, KSU-Next, SukiSU, Magisk, APatch, HideMyApplist, HMA-OSS, LSPosed, GameGuardian, LuckyPatcher, Shizuku), v2/v3/v3.1 cert lineage, `nativeLibraryDir` daemon payload (`libksud.so`/`libapd.so`/`libmagisk.so`), public manifest XML `android:zygotePreloadName`, plus full-generation HMA/Thanox side-channels: disposable-child `getpriority(PRIO_USER)` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`, cross-user `MATCH_ANY_USER` exception suppression, ordered broadcast `resultTo` / `isOrderedBroadcast` self-control pair, API 35+ `PermissionService` diff (1s budget -> `PARTIAL`), and exact `Thanox` `IThanos` `dropbox` Binder check (`root_fw` dedupe + orthogonal `hma_hiding` family) |
| App integrity & provenance | `app_integrity` | `CRITICAL` | Hardcoded expected package name, Java APK v2/v3/v3.1 signing lineage + Native raw-syscall `base.apk` ZIP/APK Signing Block SHA-256 cross-check, API 30+ `getInstallSourceInfo()` unofficial installer check, release `ObfuscationSentinel` self-check |
| Hook & Native self-integrity | `hook_framework` | `CRITICAL` + `POSTPONED` | Xposed/Frida (maps/FD `linjector` & `frida-gadget`/35ms-bounded D-Bus ports `27042–27045`/dual `comm`+`status` threads/Unix sockets/anon `r-xp` ELF/`dl_iterate_phdr` vs `maps` diff/read-only `sigaction`), `memfd` private ELF, W+X mappings, ART reflection/JNI slots, event-driven periodic monitor `late_*` latches, COW-safe `SelfIntegrityProbe`, plus Stage 3 `ZygiskProbe` (Bionic `libc.so` `SHT_SYMTAB` `g_array` `atexit` audit, LLVM SRA & API 30–37 safe) & `LsposedProbe` (Binder `0x5F4C5350`, Zygote GID audit, full thread stacks) |
| Anti-debug | `debug` | `CRITICAL` | Native `OBF`-protected dual-path `TracerPid` (`/proc/self/status`, `/proc/<pid>/task/<pid>/status`, `/proc/self/task/*/status` + mismatch), `/proc/self/task/*/stat` field-3 `'t'` (last-`')'` safe), `wchan` `ptrace_stop`, JDWP threads & `@jdwp-control` socket, debugger connection, maps paths, IDA port, `debuggable` (informational across all scenes), optional `PR_SET_DUMPABLE(0)` |
| Root & mounts | `root`, `mount_analysis` | `FAST` + `POSTPONED` | Root paths with `EACCES`/`ENOENT` parent-reachability control, KernelPatch `sys_truncate`, KSU `reboot`/ioctl/timing side-channels (isolated via `disposable_child`), SUSFS probes, Netlink cap leak, SELinux enforce/status/ABI/dirty policy, `getdents64` cross-checks; `mount_analysis` adds `statx(STATX_MNT_ID)` vs `mountinfo`, RO partition `rw`, 3-way `fstatat` `st_mtime`, `statfs` `overlayfs`/`tmpfs`, and opt-out `RiskIsolatedProbeService` (`isolatedProcess="true"`) cross-process mount diff (`C9:stealth_root_with_unmount`) |
| Multi-instance & containers | `multi_instance` | `FAST` + `POSTPONED` | Zero hidden reflection; canonical path depth & `uid / 100000` user separation (primary `0` / Work Profile `10..89` vs OEM dual-app `999`/`>=900`/`95`/`128..150` vs nested VirtualApp/ParallelSpace/BlackBox), `st_uid` mismatch, multi-APK maps, dynamic `Proxy$` Binder check, `InstallTokenSanitizer`, plus Stage 3 `disposable_child` `sacrificial_syscall_pack` (`openat2`/`statx`/`memfd_create`/`pidfd_open`/`renameat2` libc vs raw syscall) |
| Network & MitM | `network_risk` | `FAST` | Zero `<uses-permission>`: `AndroidCAStore` `user:` certs + `cacerts-added` (Charles/Fiddler/mitmproxy/Burp), runtime-guarded `TRANSPORT_VPN` with `/sys/class/net` (`tun*`/`ppp*`/`wg*`/`utun*`) fallback, proxy source tag (credentials never logged), official proxy tool cert SHA-256 & read-only `/data/adb/modules/{box4,box_for_root}` |
| Location spoofing | `location_risk` | `FAST` | Zero location permissions, zero coordinate PII: local `Location` contract canary (getter/setter/field-mask/`reset()`/API 31+ `setMock`/`isMock` round-trip defeating Xposed `LocationGetterHooker`), plus optional host-permitted cached `Location.isMock()` & `AppOpsManager` mock-location check |
| Screen control, vishing & time | `screen_and_fraud` | `FAST` | Virtual/presentation displays (`scrcpy`/`MediaProjection`/AnyDesk/TeamViewer), non-system 3rd-party accessibility services, non-builtin virtual inputs, API 34/35 screen capture/recording hooks (permission-gated), `AudioManager` `ongoing_call` (`C10:vishing_fraud_combo` in `PAYMENT`), `Build.TIME`/`AUTO_TIME`/monotonic `time_spoofing`; paired with opt-in `RiskWindowGuard` |
| Emulator / cloud phone / ROM | `emulator`, `cloud_phone`, `custom_rom` | `FAST` + `POSTPONED` | QEMU/ranchu + modern catalog (Waydroid/Cuttlefish/WSA/Corellium/LDPlayer 9/MuMu 12 & AVF `>= 2` joint-marker guard), Native Bridge (`houdini`/`libnb`/`libndk_translation`), virtual GPUs (ANGLE-on-Vulkan exempt), zero-SoC-HW `MediaCodec`, Stage 3 `SensorNoiseProbe` (`<= 200ms` joint-only), `sched_yield` CV (INFO-only) & ARM64 `cntvct_el0` clock drift; `custom_rom` adds `libstagefright.so` symbol & `framework-res.apk` multi-dev checks with Pixel/HarmonyOS FP guards |
| Debug bridge | `adb` | `FAST` | Conditional 1.5s 2-sample debounce (0 sleep on clean devices), `/dev/socket/adbd` 3-way `fstatat` + `@jdwp-control` + `init.svc.adbd=stopped` hidden-ADB contradiction (`HIGH`/7 actionable in all scenes); normal USB/Wi-Fi ADB stays informational until `PAYMENT`/`DIAGNOSTIC` |
| Consistency & correlation | `consistency`, `signal_correlation` | `FAST` + `POSTPONED` / Aggregator | Treble partition/Build properties, upgraded `BootloaderProbe` (hardware `RootOfTrust` first, `/proc/bootconfig`, 21 Boot/AVB/Samsung Knox props, VBMeta empty-input SHA-256/512 trap), Bionic `prop_area` hole/serial/tail forensics, PlayIntegrityFix side-channels, ARM64 `MIDR_EL1`, 3-source kernel consistency, Widevine Java vs NDK `AMediaDrm` (`dlopen("libmediandk.so")`) dual-source parity, and cross-detector rules (`C1`–`C8:spoofed_verified_boot`, `C9:stealth_root_with_unmount`, `C10:vishing_fraud_combo`) |
| Device fingerprint v2, posture & envelopes | 22 default collectors (24 in `DIAGNOSTIC`) | `POSTPONED` | `FingerprintVersion` (`V1` frozen / `V2`), `FingerprintStability` (`STABLE`/`OPTIMAL`/`UNIQUE`), pluggable `FingerprintHasher`, zero-permission `codec_info` / `input_devices` / `security_posture` collectors, structured `CpuInfoParser`, AndroidKeyStore `AES-256-GCM` hardware binding (`device_binding_broken`), DirectBoot DE storage, `DevicePosture`, `RiskReport.TrustTier` (`STRONG_HARDWARE`), and dual-mode `SignedRiskEnvelope` (`PERSISTENT_KEY` `<10ms` & `FRESH_ATTESTATION`) |

Artifact paths are sourced from `riskengine-sdk/src/main/resources/lists/artifact_paths.ini`. Java `DetectionLists` and native `detection_lists.h` (including a compile-time FNV-1a 64-bit hashed property whitelist) are generated from that file.

The SDK declares **zero** `<uses-permission>` entries and **zero** third-party runtime dependencies. Its manifest contains `<queries>` package-visibility entries only for curated emulator, cloud-phone, official proxy tool, and official threat/root/HMA packages (enforced 1:1 with `artifact_paths.ini` by Gate 3).

## Requirements

- JDK 17+ (Java 11 source/target bytecode)
- Android Gradle Plugin 8.13.1
- Compile SDK 36 / Target SDK 36 / Min SDK 30
- NDK `27.0.12077973`, CMake `3.22.1+`, C++17 (`-fno-exceptions -fno-rtti`)
- Native ABIs: `arm64-v8a`, `x86_64` (64-bit only, 16KB ELF `LOAD` alignment; see [ADR-0003](./docs/adr/0003-drop-32bit-abi-support.md). Host apps bundling other native SDKs should configure `ndk { abiFilters += listOf("arm64-v8a") }` or `listOf("arm64-v8a", "x86_64")` so Android does not launch the app in 32-bit mode)

## Quick start

### Build

```bash
./build.sh sdk      # SDK AAR only
./build.sh demo     # Demo Debug APK
./build.sh install  # build and install the Demo on a connected device
./build.sh all      # SDK + Demo
./build.sh clean    # clean
```

Or Gradle directly:

```bash
./scripts/ci-verify.sh                             # Full CI pipeline: Core SDK + Demo + Integration Test + Gates 1–6 + L2 C++
./gradlew :riskengine-sdk:apiCheck --no-daemon     # Zero-plugin JDK 17 javap Public ABI lock & AAR purity check
./gradlew :demo:testDebugUnitTest --no-daemon      # Demo UI 0–100 scoring & formatter unit tests
python3 -B scripts/test_verify_risk_envelope.py -v # Cross-language SignedRiskEnvelope v=2 offline verifier tests
./scripts/run-cpp-tests.sh                         # 100% offline L2 C++ host unit tests (CMake + CTest)
```

| Artifact | Path | Notes |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | Host-app integration (2 64-bit ABIs stripped, no `.comment`, 2 exported JNI symbols, 16KB aligned, single-ABI `.so <= 2000 KiB`, AAR `<= 4 MiB`, R8 Dex `< 2,500` methods) |
| SDK sources | `riskengine-sdk/build/intermediates/source_jar/release/release-sources.jar` | Source archive for distribution |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | Temporarily debug-signed; sideload only |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | Minified; sign with a release key before distribution |

Tag releases (`v*.*.*`) automatically attach the core `:riskengine-sdk` release bundle (AAR + sources JAR + POM), the temporary Demo Debug APK, and `SHA256SUMS`. The temporary APK is not for production or stores. Later tags may use a different temporary key; uninstall the older Demo if Android reports a signature mismatch.

### Initialize, pull collect, and push monitoring

```java
// Optional: customize an immutable local RiskPolicy on top of a CollectScene preset
RiskPolicy paymentPolicy = RiskPolicy.builder(CollectScene.PAYMENT)
        .dimensionWeight(RiskDimension.FRAUD_CONTEXT, 1.3)
        .actionThresholds(25, 55, 80)          // CHALLENGE / RESTRICT / BLOCK
        .highAction(RiskAction.BLOCK)
        .informationalOnlyFamily("adb")        // keep visible at 0 score / ALLOW
        .build();

RiskEngineConfig config = new RiskEngineConfig.Builder()
        .privacyProfile(PrivacyProfile.BALANCED)
        .collectTimeout(15000)
        .collectScene(CollectScene.STANDARD)
        .riskPolicy(paymentPolicy)                          // optional local policy override
        .fingerprintVersion(FingerprintVersion.V2)          // pin V1 for bit-exact v1.x compatibility
        .fingerprintStability(FingerprintStability.OPTIMAL)
        .expectedPackageName("com.example.hostapp")
        .expectedSigningCertSha256Base64("<BASE64_SHA256_FROM_RELEASE_KEY>")
        .enableAntiDumpable(false)                          // opt-in; see crash-reporter note below
        .enableIsolatedProcessProbe(true)                   // ephemeral isolatedProcess mount diff; host may strip via tools:node="remove"
        .enablePeriodicMonitor(true)
        .build();

// Non-blocking (< 5 ms on caller thread): native .so load, PR_SET_DUMPABLE,
// periodic monitor, and FingerprintStore warm-up all run asynchronously.
RiskEngine.initIfNeeded(context, config);

// 1) Push mode (recommended for real-time RASP & tiered startup checks):
RiskEngine.startMonitoring(
        new ThreatListener() {
            @Override
            public void onThreatDetected(ThreatEvent event) {
                Log.w("RiskEngine", "Threat [" + event.getScanTier() + "]: "
                        + event.getDetectorName() + " -> " + event.getRiskLevel());
            }

            @Override
            public void onRuntimeTamperDetected(ThreatEvent event) {
                Log.e("RiskEngine", "Runtime tamper: " + event.getDetails());
            }
        },
        new DeviceStateListener() {
            @Override
            public void onDeviceStateEvaluated(DevicePosture posture) {
                Log.i("RiskEngine", "Posture: keystore=" + posture.getKeystoreSecurityLevel()
                        + ", encrypted=" + posture.isStorageEncrypted());
            }
        },
        new ExecutionStateListener() {
            @Override
            public void onCriticalChecksFinished(TierReport critical) { /* app_integrity, debug, hook_framework (0–100 scale) */ }
            @Override
            public void onFastChecksFinished(TierReport fast) { /* remaining 11 FAST domains (0–100 scale) */ }
            @Override
            public void onPostponedChecksFinished(RiskReport fullReport) { /* collectors + tee_integrity + threat_apps + full aggregation */ }
        });

// 2) Pull mode (on-demand full collection, e.g. before payment):
RiskEngine.collect(CollectScene.PAYMENT, new RiskEngineCallback() {
    @Override
    public void onSuccess(RiskReport report) {
        Log.d("RiskEngine", "Risk: " + report.getOverallRiskLevel()
                + ", Action: " + report.getRecommendedAction()
                + ", TrustTier: " + report.getTrustTier()
                + ", Score: " + report.getRiskScore() + " / " + report.getMaxRiskScore()
                + ", Confidence: " + report.getConfidencePercent() + "%"
                + ", Dims: " + report.getDimensionScores());
    }

    @Override
    public void onError(Throwable error) {
        Log.e("RiskEngine", "Collect failed", error);
    }
});
```

Callbacks run on an SDK background thread; switch to the main thread before updating UI. `collectTimeout` is one deadline shared by the complete request, including serialized queue wait, collectors, and detectors. The default is 10 seconds; the legal range is 1–120,000 ms.

Synchronous APIs reject the Android main thread:

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.reportToJson(report);       // no second collection
String freshJson = RiskEngine.collectReportJson();   // collect then serialize
```

Optional host-controlled window hardening (never enabled automatically):

```java
// Call on sensitive Activities (e.g. login / payment / PIN entry)
RiskWindowGuard.enableScreenCaptureProtection(activity, true);   // WindowManager.LayoutParams.FLAG_SECURE
RiskWindowGuard.enableOverlayProtection(activity, true);         // API 31+ setHideOverlayWindows(true)
RiskWindowGuard.enableTouchObscuredFilter(rootView, true);       // View.setFilterTouchesWhenObscured(true)
```

> **Note on `enableAntiDumpable(true)`**: calls `prctl(PR_SET_DUMPABLE, 0)` on the native worker thread to block non-root `ptrace` attachment. Defaults to `false` because `dumpable=0` can interfere with ptrace-based third-party crash reporters (such as legacy Breakpad or Bugly). Enable only after validating your crash reporting stack.

`init` rejects duplicate initialization; multi-entry applications should use atomic `initIfNeeded`. Call `RiskEngine.stopMonitoring()` to unregister push listeners, or `RiskEngine.shutdown()` when the SDK is no longer needed: it advances the lifecycle generation, cancels work, unregisters `AppLifecycleObserver`, clears lifecycle state, releases `lifecycleLock` before joining the native periodic monitor, and prevents older-generation deliveries.

The SDK AAR itself is not minified. Host R8 uses the bundled `consumer-rules.pro` (keeping all public APIs, `RiskPolicy`, `RiskDimension`, `RiskAction`, `ScoreBreakdown`, `EvidenceItem`, `DevicePosture`, `ThreatEvent`, `TierReport`, `SignedRiskEnvelope`, and `NativeMonitorDispatcher.onNativeThreatDetected`, while intentionally **not** keeping `ObfuscationSentinel` so `AppIntegrityDetector` can verify R8 obfuscation in release builds).

## Host Backup Exclusion, Isolated Probe Opt-Out & DirectBoot

`RiskEngine` ships an on-demand `android:isolatedProcess="true"` helper (`RiskIsolatedProbeService`) used during Stage 3 (`POSTPONED`) by `mount_analysis` to detect Shamiko/DenyList selective unmounts (`C9:stealth_root_with_unmount`) and unbinds immediately in `finally`. If a host app prefers a single-process footprint, disable it via `.enableIsolatedProcessProbe(false)` and/or strip the service in the host `AndroidManifest.xml` — `IsolatedProbeClient` degrades cleanly to `UNAVAILABLE`:

```xml
<service
    android:name="com.wsttxm.riskenginesdk.process.RiskIsolatedProbeService"
    tools:node="remove" />
```

`FingerprintStore` stores encrypted continuity state in device-protected (DE) `riskengine_fp` SharedPreferences so `directBootAware` hosts can initialize safely before first unlock (one-time CE→DE migration runs only when `UserManager.isUserUnlocked()` is `true`).

Host apps **must** exclude `riskengine_fp.xml` from cloud backup and device-to-device transfer to prevent false `device_binding_broken` signals after restoring onto a new device:

**`res/xml/data_extraction_rules.xml` (Android 12 / API 31+):**

```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="riskengine_fp.xml" />
        <exclude domain="device_sharedpref" path="riskengine_fp.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="riskengine_fp.xml" />
        <exclude domain="device_sharedpref" path="riskengine_fp.xml" />
    </device-transfer>
</data-extraction-rules>
```

**`res/xml/backup_rules.xml` (Android 11 / API 30):**

```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <exclude domain="sharedpref" path="riskengine_fp.xml" />
    <exclude domain="device_sharedpref" path="riskengine_fp.xml" />
</full-backup-content>
```

## Release Signing & Google Android Developer Verification (ADI) Checklist

Before publishing a production release with `AppIntegrityDetector` enabled:

1. **Extract every production signing certificate SHA-256 in Base64** (include Play App Signing key, upload/sideload key if distributed outside Play, and both old + new keys during APK v3/v3.1 key rotation):
   ```bash
   # From a signed release APK (recommended: inspects the exact APK signing certificate)
   apksigner verify --print-certs app-release.apk \
     | awk -F': ' '/certificate SHA-256 digest/ {print $2}' \
     | xxd -r -p | openssl base64

   # Or from a DER certificate downloaded from Play Console -> App Integrity -> App signing key certificate
   openssl x509 -in deployment_cert.der -inform DER -outform DER \
     | openssl dgst -sha256 -binary | openssl base64
   ```
2. **Pin package name, certificates, and trusted stores** in `RiskEngineConfig.Builder`:
   - `.expectedPackageName("com.example.hostapp")` (hardcode a literal; do not pass `context.getPackageName()`).
   - `.expectedSigningCertSha256Base64("<play_cert_b64>", "<direct_channel_cert_b64>")`.
   - `.trustedInstallerPackages(...)` if distributing through custom OEM or enterprise channels beyond the built-in presets (Google Play, Huawei AppGallery, Xiaomi, OPPO, vivo, Samsung, Honor).
3. **Google Android Developer Verification (ADI) ownership registration**: if your release participates in Google ADI verification, package your signed ownership file at `assets/adi-registration.properties` in the host app module and verify that the signing certificate in the Play App Signing / direct distribution APK matches the registered key and `expectedSigningCertSha256Base64`.
4. **Verify R8 obfuscation**: enable `isMinifyEnabled = true` on the host release build and do **not** add `-keep class com.wsttxm.riskenginesdk.detector.ObfuscationSentinel` (or wildcard `-keep class com.wsttxm.riskenginesdk.**`), otherwise `AppIntegrityDetector` flags `release_unobfuscated`.

## Collection scenes & local `RiskPolicy`

Every enabled Detection Domain always executes. Aggregation applies the active `RiskPolicy` (initialized from a built-in `CollectScene` preset plus any host overrides) **before** order-independent family-max deduplication and cross-domain correlation (`applyPolicy -> dedupeFamilies -> correlate -> RiskScoringEngine`).

| Scene | Behavior | Default `HIGH` Action |
| --- | --- | :---: |
| `STANDARD` | Default split. ADB, weak emulator, community ROM, bootloader-only warning, OEM dual-app, mock-location appop/cached mock, `ongoing_call`, proxy tool cert/module, and `debuggable`-only stay informational (`0` score, `ALLOW`) | `RESTRICT` |
| `LOGIN` | Emulator, cloud-phone, OEM dual-app, cached/appop mock location, and confirmed bootloader-unlocked / orange verified-boot hits become actionable (`MEDIUM`/`HIGH`); activates `C7` | `RESTRICT` |
| `PAYMENT` | `LOGIN`, plus ADB, unofficial installer, and proxy tool cert/module become actionable; screen sharing/3rd-party accessibility elevates to `HIGH`; `ongoing_call` + screen control triggers `C10:vishing_fraud_combo`; dual bootloader/orange or hardware-confirmed boot warnings elevate to `HIGH` | `BLOCK` |
| `DIAGNOSTIC` | Every non-coverage signal is actionable except a `debuggable`-only debug result | `RESTRICT` |

Customize local enforcement without a backend via `RiskPolicy.builder(CollectScene)` and attach it with `RiskEngineConfig.Builder.riskPolicy(RiskPolicy)`:

- **`dimensionWeight(RiskDimension, double)`**: scale any of the 4 Risk Dimensions (`>= 0.0`, finite; `0.0` mutes that dimension in the overall score).
- **`actionThresholds(challenge, restrict, block)`**: override the `0–100` score thresholds (`1 <= challenge < restrict < block <= 100`, default `30 / 60 / 85`).
- **`highAction(RiskAction)`**: override the recommended disposition for `HIGH` risk (e.g. `RESTRICT` vs `BLOCK`).
- **`allowlistFamily(family)` / `informationalOnlyFamily(family)` / `familyMultiplier(family, double)`**: allowlist a family (0 score, no correlation rules, no Hard Triggers), downgrade it to informational-only (visible at 0 score / `ALLOW`), or apply a custom strength multiplier.
- **`suppressHardTrigger(codeOrPrefix)`**: selectively suppress a Hard Trigger token by exact code or prefix (e.g. `"inline_hook:"`).

Set the default scene with `RiskEngineConfig.Builder.collectScene(...)` (or override per call via `collect(scene, callback)` / `collectSync(scene)`).

## Enterprise 0–100 four-dimensional scoring & result semantics

Individual collector or detector failures never become silent safe results. At the same time, legitimate hardware/platform absence (`UNSUPPORTED` / `EMPTY`) is tracked in `unsupportedCheckCount` and never degrades a clean device from `SAFE` to `UNKNOWN`.

| State | Meaning |
| --- | --- |
| `CollectorResult.Status.SUCCESS` | At least one usable value was collected (partial SELinux property reads retain `SUCCESS` with `partial_errors` when `>= 1` property succeeds) |
| `CollectorResult.Status.EMPTY` | Collection completed cleanly with no value; counted in `unsupportedCheckCount`, not as a failure |
| `CollectorResult.Status.ERROR` | The collector failed or exceeded the available request time; lowers coverage and confidence |
| `CollectorResult.Status.UNSUPPORTED` | The current device or platform does not expose this signal; counted in `unsupportedCheckCount`, not as a failure |
| `DetectionStatus` | Risk presentation: `NORMAL` / `WARNING` / `DANGER` / `UNKNOWN` |
| `DetectionExecutionStatus` | Execution: `SAFE` / `RISK` / `PARTIAL` / `UNAVAILABLE` / `DISABLED` / `TIMEOUT` / `ERROR` |

### Four orthogonal Risk Dimensions (21 Evidence Families)

`RiskScoringEngine` evaluates both `RiskReport` and staged `TierReport` on one unified `0–100` scale across 4 orthogonal `RiskDimension`s:

| `RiskDimension` | Mapped Evidence Families (21 total) |
| --- | --- |
| `TAMPERING` (6) | `app_tamper`, `hook_integrity`, `frida`, `xposed`, `debugger`, `tee_tamper` |
| `PRIVILEGE` (8) | `root_fw`, `boot_integrity`, `prop_tamper`, `hw_spoof`, `hma_hiding`, `device_binding`, `custom_rom`, `adb` |
| `ENVIRONMENT` (3) | `emulator`, `virtual_container`, `threat_app` |
| `FRAUD_CONTEXT` (4) | `network_mitm`, `location_spoof`, `screen_control`, `fraud_context` |

### Deterministic three-stage scoring pipeline

1. **Order-independent family-max aggregation**: Actionable detections are grouped by Evidence Family independent of detector registration order, taking each family's strongest single-source internal intensity (`1..10` smoothly mapped to probability `0.10..0.92`). Duplicate hits in the same family stay visible as corroborating evidence (`deduped:corroborating_evidence`) instead of double-counting or suppressing stronger detectors.
2. **Bounded Corroboration Lift**: When an actionable Evidence Family is confirmed across `>= 2` independent inspection layers (e.g. `JAVA + NATIVE`, `NATIVE + ISOLATED`, or `HARDWARE`) or `>= 2` distinct Detection Domains, it receives a bounded `+0.06` lift (clamped at `0.95`).
3. **Per-dimension Noisy-OR, pure-LOW cap & Hard Trigger floor**:
   - Independent families within each dimension combine via Noisy-OR (`1 - product(1 - p_i)`) scaled to `0–100`. If every actionable hit in a dimension is `LOW` severity (no `MEDIUM` or higher), that dimension is capped at `<= 35`.
   - The 4 weighted dimensions and cross-domain Correlation Rules (`C1`–`C10`) combine via weighted Noisy-OR into the overall `0–100` score.
   - Authoritative Hard Triggers are resolved once via `RiskScoringEngine.extractHardTriggers(...)` and exposed on `RiskReport.getHardTriggers()`. Any active (non-suppressed) Hard Trigger forces `RiskLevel.DEADLY`, `RiskAction.BLOCK`, and floors `riskScore` at `95–100` (`min(100, 95 + 2 * (count - 1))`).

### Risk levels, `RiskAction`, and tiered Assessment Confidence

| Level | Default Score Band (`0–100`) | Default `RiskAction` | Rule |
| --- | :---: | :---: | --- |
| `SAFE` | `0` | `ALLOW` | Score `0`, no informational/risk signal, no `CRITICAL` failure, `confidencePercent >= 70` |
| `LOW` | `1–29` (or `0` info-only) | `ALLOW` | Score `1–29`, or pure informational findings (`score = 0`) |
| `MEDIUM` | `30–59` | `CHALLENGE` | Score `>= challengeThreshold` (default `30`) |
| `HIGH` | `60–84` | `RESTRICT` (`BLOCK` in `PAYMENT`) | Score `>= restrictThreshold` (default `60`) |
| `DEADLY` | `85–100` | `BLOCK` | Score `>= blockThreshold` (default `85`), or any active Hard Trigger (floored at `95–100`) |
| `UNKNOWN` | `0` | `REVIEW` | Zero score AND (`CRITICAL` domain failed/timed out, weighted `confidencePercent < 70`, or all detectors unavailable) |

**Tiered Assessment Confidence (`confidencePercent`, `0–100%`)** weights completed versus attempted checks by execution tier (`CRITICAL = 3`, `FAST = 2`, `POSTPONED = 1`, collectors = `1`) and is decoupled from `riskScore`. A single non-critical (`FAST`/`POSTPONED`) probe timeout keeps a clean device at `SAFE` (with honest `ReportStatus.PARTIAL` and reduced `confidencePercent`), whereas a `CRITICAL` failure or `confidencePercent < 70%` transitions a zero-risk report to `UNKNOWN` (`RiskAction.REVIEW`).

Authoritative Hard Triggers include: GOT/inline hooks and self-integrity tamper (`inline_hook:`, `got_hook:`, `text_mismatch`, `late_text_mismatch`, `jni_self_hook:`, `fn_prologue_hook:`, `late_wx_self`, `memfd_private_elf:`, `late_memfd_elf`, `art_native_cleared:`), high-confidence Frida PID/port/maps/FD (`frida_pid_port`, `maps:frida`, `maps:gadget`, `fd:linjector`, `late_frida_fd`), app repackaging (`apk_sig_mismatch`, `pkg_name_mismatch`, `apk_native_java_sig_conflict`), VBMeta empty-input digest (`vbmeta_empty_input_digest`), TEE tampering (`tee_grant_chain_split`, `tee_binder_ioctl_hook`, `tee_keybox_revoked`), and correlation rules `C3:`, `C6:`, and `C8:`.

`RiskReport.getTrustTier()` summarizes overall posture as `STRONG_HARDWARE` (`SAFE` + hardware Keystore + encrypted storage + lockscreen), `LOCAL_VERIFIED` (`SAFE`/`LOW` + complete coverage), `DEGRADED` (`MEDIUM`/`UNKNOWN`/incomplete), or `COMPROMISED` (`HIGH`/`DEADLY`).

Both `maxRiskScore` and `displayThresholdMaximum` are `100`, matching the unified `0–100` scale used by `RiskReport`, `TierReport`, and the Demo UI gauge.

## Output, Additive JSON v2 & Signed Envelope `v=2`

`RiskReport` is frozen after aggregation. Principal fields:

| Field | Description |
| --- | --- |
| `fingerprint` | Aggregated device fingerprint (collector results, including `fingerprint_id`) |
| `fingerprintId` | Layered hardware/system/volatile/composite IDs, `version` (`V1`/`V2`), `stability`, `anchorDriftCount`, and bucket digests; `null` if composition fails |
| `devicePosture` | Non-threat security hygiene (`hasPasscode`, `storageEncrypted`, `storageEncryptionStatus`, `keystoreLevel`, `biometricStatus`, `devMode`, `adbEnabled`, `systemVpn`, `unofficialStore`, `lockscreenOrBiometricReset`) |
| `trustTier` | `STRONG_HARDWARE` / `LOCAL_VERIFIED` / `DEGRADED` / `COMPROMISED` |
| `detections` | Detector results (`scanTier`, legacy `details[]` tokens, `evidenceFamilies[]`, and structured immutable `List<EvidenceItem>` via `getEvidenceItems()`) |
| `overallRiskLevel` | Final `RiskLevel` (`SAFE` / `LOW` / `MEDIUM` / `HIGH` / `DEADLY` / `UNKNOWN`) |
| `recommendedAction` | Recommended local `RiskAction` (`ALLOW` / `CHALLENGE` / `RESTRICT` / `BLOCK` / `REVIEW`) |
| `riskScore` / `maxRiskScore` / `displayThresholdMaximum` | Normalized `0–100` risk score (`maxRiskScore = 100`, `displayThresholdMaximum = 100`) |
| `dimensionScores` | `Map<RiskDimension, Integer>` (`0–100` sub-scores for `TAMPERING`, `PRIVILEGE`, `ENVIRONMENT`, `FRAUD_CONTEXT`) |
| `scoreBreakdown` | Auditable `ScoreBreakdown` (`preFloorScore`, `finalScore`, and structured `Entry` list for `FAMILY`, `CORROBORATION_LIFT`, `CORRELATION_RULE`, `HARD_TRIGGER_FLOOR`) |
| `hardTriggers` | Deterministic sorted list of active authoritative Hard Triggers (shared 1:1 with `SignedRiskEnvelope` `v=2`) |
| `confidencePercent` | Tier-weighted Assessment Confidence (`0–100%`) decoupled from `riskScore` |
| `warningCount` / `dangerCount` / `unknownCount` | Status counts (including informational) |
| `reportStatus` | `COMPLETE` / `PARTIAL` / `UNAVAILABLE` |
| `checkCount` / `completedCheckCount` / `unsupportedCheckCount` / `coveragePercent` | Detector + collector coverage; `UNSUPPORTED`/`EMPTY` collectors are tracked separately in `unsupportedCheckCount` |
| `collectScene` / `riskPolicy` | Scene and effective immutable `RiskPolicy` used to evaluate this report |
| `timestampMs` / `sdkVersion` | Collection time and SDK version |

`EvidenceItem` carries `code`, `primarySource`, `mergedSources`, `location`, `value`, `evidenceFamily`, and `rank`. `DataAggregator` automatically merges identical `(code, location)` items across `JAVA` and `NATIVE` sources into `mergedSources = {JAVA, NATIVE}` while keeping the highest `Rank`.

`RiskReportJsonSerializer` emits strictly **additive JSON v2** (`schemaVersion: 2`, `riskScore`, `maxRiskScore: 100`, `displayThresholdMaximum: 100`, `confidencePercent`, `recommendedAction`, `hardTriggers[]`, `dimensionScores{}`, `scoreBreakdown[]`, `trustTier`, `devicePosture`, `unsupportedCheckCount`, `fingerprintId`, and per-detection `scanTier`, `evidenceFamilies[]`, `evidenceItems[]`) with zero extra runtime dependencies while preserving backward compatibility.

`SignedRiskEnvelope` uses canonical payload protocol **`v=2`** (`SignedRiskEnvelope.PROTOCOL_VERSION = 2`), binding 17 recursively key-sorted UTF-8 fields—including `score` (`0–100`), `action`, `confidence`, `dimensions` (`TAMPERING`/`PRIVILEGE`/`ENVIRONMENT`/`FRAUD_CONTEXT`), and authoritative `hardTriggers`—under an ECDSA P-256 hardware-attested signature. See [docs/Signed_Envelope_Verification.md](./docs/Signed_Envelope_Verification.md) for the 6-step offline server verification contract and zero-dependency Python verifier (`scripts/verify_risk_envelope.py`).

## Layered fingerprints v2, hardware binding & local storage

`report.getFingerprintId()` returns a `FingerprintId` governed by explicit contracts:

- **`FingerprintVersion`**: `V1` (bit-exact frozen 13-field hardware + 11-field system algorithm, locked by golden-vector tests) and `V2` (default: adds `codec_info`, `input_devices`, `security_posture`, and structured `CpuInfoParser` stripping volatile `BogoMIPS`/`cpu MHz`). `LATEST` is `@Deprecated` so hosts consciously pin their version.
- **`FingerprintStability`**: `STABLE` (physical hardware buckets only), `OPTIMAL` (default: hardware + system + new zero-permission dimensions), `UNIQUE` (adds enabled volatile identifiers).
- **`FingerprintHasher`**: pluggable hash function (defaults to UTF-8 + SHA-256).

Each layer uses a random 32-byte installation salt persisted in private DE `riskengine_fp` SharedPreferences and wrapped with a non-exportable `AndroidKeyStore` `AES-256-GCM` key (`StrongBox` preferred, automatic fallback to `TEE`). `FingerprintStore` separates the **immutable initial anchor baseline** (`anchor_hw` / `anchor_hw_buckets`, auto-migrated from v1 `last_hw`) from mutable recent observations (`last_hw` / `last_sys` + `drift_count`):

- Tampered hardware increments `drift_count` and continues reporting `HARDWARE_CHANGED` (`fingerprint_continuity`, `MEDIUM`/4) without overwriting the anchor.
- If persisted ciphertext exists while its `AndroidKeyStore` wrapping key is missing or GCM authentication (`AEADBadTagException`) fails, `FingerprintStore` reports **`device_binding_broken`** (`HIGH`/7 actionable in `fingerprint_continuity`), detecting rooted data cloning across physical devices or XML tampering.
- A hardware sentinel key detects `KeyPermanentlyInvalidatedException` and surfaces `devicePosture.lockscreenOrBiometricReset = true`.
- Host apps can explicitly re-anchor via `RiskEngine.resetFingerprintBaseline()` (preserving the installation salt).

`isHardwareLayerReliable()` returns `true` when `hardwareId` is non-empty, `getHardwareCoveragePercent() >= 50`, and at least 2 core physical buckets (`gpu`, `cpu`, `sensor`) are populated.

## Privacy

| Profile | Default identifier collection |
| --- | --- |
| `MINIMAL` | No Android ID, boot ID, or Widevine |
| `BALANCED` | App-scoped Android ID SHA-256 hash only (default) |
| `DIAGNOSTIC` | Adds app-scoped boot ID and Widevine hashes |

`collectAndroidId` / `collectBootId` / `collectDrmId` override a profile. Hashes include the host package name, so they are deterministic app-scoped pseudonyms — **not** encryption, anonymization, or an absolute non-reversibility guarantee. Reports never expose raw Android ID, DRM ID, boot ID, IMEI, IMSI, Wi-Fi/Bluetooth MAC, SSID, BSSID, HTTP proxy credentials, or latitude/longitude coordinates.

The hardware collectors and layered-ID composition run in every privacy profile. `MINIMAL` disables only the three identifiers above, not hardware fingerprinting or local continuity storage. If storage is unavailable, the implementation falls back to a process-ephemeral random salt (never a fixed constant salt), valid for the current process lifetime only.

## Demo

The `demo` module is a local diagnostic console built on the Fluid Design language with v2.0 incremental scoring upgrades:

- **Privacy Consent Gate**: Presents a privacy notice before the first `RiskEngine.initIfNeeded()` call and persists consent in Demo `SharedPreferences`; declining keeps the SDK cleanly uninitialized.
- **0–100 3-Tier Progressive `RiskGaugeView` & Hero Card**: Drives scans via `RiskEngine.startMonitoring(...)`, animating a 3-segment progressive tier ring (`CRITICAL -> FAST -> POSTPONED`) calibrated to `0–100`, paired with the recommended `RiskAction` disposition pill, Assessment Confidence (`confidencePercent`), four orthogonal `RiskDimension` sub-score bars (`TAMPERING`, `PRIVILEGE`, `ENVIRONMENT`, `FRAUD_CONTEXT`), Hard Trigger badge, and an expandable `ScoreBreakdown` detail sheet.
- **16/16 Converged Detection Domains**: `ReportFormatter` consumes SDK `EvidenceItem`, `DevicePosture`, and `ScoreBreakdown` directly, displaying all 16 RASP domains (including `tee_integrity`, `threat_apps` + HMA side-channels, `C8`–`C10`, and Widevine parity) and 22/24 collectors.
- **Fingerprint Continuity & Hardware Bucket Card**: Displays layered IDs, `FingerprintVersion` (`V1`/`V2`), `FingerprintStability` (`STABLE`/`OPTIMAL`/`UNIQUE`), `anchorDriftCount`, `device_binding` status, 5 physical hardware bucket digests (`gpu`/`cpu`/`sensor`/`camera`/`memory_battery`), and a confirmed `RiskEngine.resetFingerprintBaseline()` action.
- **Live Threat & Posture Stream Drawer (`ThreatStreamDrawer`)**: Accessible from the top-bar live pill, streaming `ThreatListener` alerts (highlighting post-init runtime tamper events) and `DeviceStateListener` posture snapshots in real time.
- Environment detections sort risk first; "Needs attention" counts actionable warning/danger only; `UNKNOWN` is never styled as safe; copied reports are strictly redacted (including `0–100` score, `RiskAction`, confidence, and 4-dimension sub-scores); cloud backup and device-transfer extraction are disabled.

## Public API

| API | Description |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | Non-blocking initialization; duplicate calls throw |
| `RiskEngine.initIfNeeded(Context, RiskEngineConfig)` | Atomically initialize when needed; returns whether this call did it |
| `RiskEngine.startMonitoring(ThreatListener, DeviceStateListener, ExecutionStateListener)` | Start tiered push monitoring (`CRITICAL -> FAST -> POSTPONED`) & real-time native/screen alerts |
| `RiskEngine.stopMonitoring()` | Unregister push listeners without shutting down the SDK |
| `RiskEngine.collect(RiskEngineCallback)` | Asynchronous pull collection |
| `RiskEngine.collect(CollectScene, RiskEngineCallback)` | Asynchronous pull collection for one scene |
| `RiskEngine.collectSync()` / `collectSync(CollectScene)` | Synchronous pull collection; forbidden on the main thread |
| `RiskEngine.collectSignedEnvelopeSync(CollectScene, byte[], EnvelopeMode)` | Collect report + sign hardware-attested `SignedRiskEnvelope` `v=2` (`PERSISTENT_KEY` `<10ms` or `FRESH_ATTESTATION`, explicit `SOFTWARE_FALLBACK` when hardware unavailable) |
| `RiskEngine.collectReportJson()` | Collect then serialize additive JSON v2 |
| `RiskEngine.reportToJson(RiskReport)` | Serialize an existing report without collecting again |
| `RiskEngine.resetFingerprintBaseline()` | Explicitly clear/re-anchor the immutable hardware baseline while keeping the installation salt |
| `RiskEngine.getReportJson()` | Deprecated alias for `collectReportJson()` |
| `RiskEngine.shutdown()` | Cancel work, unregister lifecycle observer, and join native monitor outside `lifecycleLock` |
| `RiskPolicy` / `RiskPolicy.Builder` | Immutable local risk policy layered on a `CollectScene` preset: dimension weights, action score thresholds, `highAction`, per-family modes/multipliers (`ALLOWLIST` / `INFORMATIONAL_ONLY`), and Hard Trigger suppressions |
| `RiskDimension` / `RiskAction` / `ScoreBreakdown` | Four orthogonal risk dimensions (`TAMPERING`, `PRIVILEGE`, `ENVIRONMENT`, `FRAUD_CONTEXT`), five recommended business actions (`ALLOW`, `CHALLENGE`, `RESTRICT`, `BLOCK`, `REVIEW`), and item-by-item score attribution |
| `ThreatAppPolicy.Builder` | Immutable host policy for custom threat packages, custom cert SHA-256s, dangerous permission combinations, and HMA probe toggles |
| `RiskWindowGuard.enableScreenCaptureProtection` / `enableOverlayProtection` / `enableTouchObscuredFilter` | Explicit host opt-in window/touch protection helpers |
| `RiskEngineConfig.Builder` | `debugLog`, `collectTimeout`, `privacyProfile`, `collectScene`, `riskPolicy`, `collectAndroidId`/`BootId`/`DrmId`, `fingerprintVersion`, `fingerprintStability`, `fingerprintHasher`, `expectedPackageName`, `expectedSigningCertSha256Base64`, `trustedInstallerPackages`, `additionalThreatPackages`, `threatAppPolicy`, `enableAntiDumpable`, `enablePeriodicMonitor`, `enableIsolatedProcessProbe`, `enableTeeAttestation`, `enableThreatAppDetection`, and per-domain `enable*` switches (`consistency` is always registered) |

## Repository Modules (Single-Core 3-Module Layout)

RiskEngine v2.0.0 consolidates around a single zero-dependency core SDK (see [ADR-0001](./docs/adr/0001-single-core-sdk-without-extension-submodules.md)):

| Module | Stack | Purpose |
| --- | --- | --- |
| `:riskengine-sdk` | Pure Java 11 + C++17 (0 3rd-party deps, 0 `<uses-permission>`) | Publishable core AAR housing all 16 converged Detection Domains, 22/24 collectors, `0–100` four-dimensional `RiskScoringEngine`, immutable `RiskPolicy`, layered fingerprints v2, and `SignedRiskEnvelope` `v=2` |
| `:demo` | Java + AndroidX Material | Local Fluid Design diagnostic console visualizing `0–100` gauge, 4-dimension bars, `RiskAction`, `ScoreBreakdown`, fingerprint continuity, and live `ThreatStreamDrawer` |
| `:integration-test` | Android Instrumentation | Consumes the standalone `riskengine-sdk-release.aar` binary for L3 end-to-end verification across API 30 / 34 / 36 KVM emulators |

## Executable Governance, Limits & Hardening

- **6 Automated CI Static Governance Gates** (enforced by `scripts/ci-verify.sh` and `.github/workflows/ci.yml`):
  1. **Gate 1 (`scripts/check-evidence-records.py`)**: Dynamic `DetectorRegistry` 1:1 parity against `docs/evidence/*.md` (16/16 domains, 7 mandatory headings each).
  2. **Gate 2 (`scripts/check-elf-hardening.sh` + `scripts/check-jni-and-dex.py`)**: 64-bit 2-ABI (`arm64-v8a`, `x86_64`) ELF hardening (2 JNI exports only, 16KB `LOAD` align, stripped, no `.comment`, `.so <= 2000 KiB`, AAR `<= 4 MiB`), exact 41/41 JNI name+signature parity, and Release R8 Dex `< 2,500` methods.
  3. **Gate 3 (`scripts/check-single-source-sync.py`)**: Zero `<uses-permission>`, exact 52-entry `<queries>` parity with `artifact_paths.ini` + `NetworkRiskDetector`, xorshift32 byte-exact `DetectionLists.java` verification, and version sync.
  4. **Gate 4 (`scripts/check-public-api.py` / `:riskengine-sdk:apiCheck`)**: Zero-plugin JDK 17 `javap` Public ABI lock (`riskengine-sdk/api/riskengine-sdk.api`), AAR `classes.jar` purity, and 0-dependency POM check.
  5. **Gate 5 (`scripts/check-boundary-guards.py`)**: Reflection allowlist audit (every reflection site documented with degradation strategy, zero D66 blocked hidden-API reflection) and ban on UI display-text branching in core SDK.
  6. **Gate 6 (`.github/workflows/refresh-attestation-roots.yml`)**: Scheduled weekly + manual dry-run drift check for Google Hardware Attestation Roots & monotonic CRL floor.
- **L1 + L2 + L3 Testing Pyramid**:
  - **L1 (JVM)**: Core `:riskengine-sdk` (all 16 domains fast+postponed, `0–100` scoring & `RiskPolicy`, all 24 collectors in `CrashFreedomMockTest`, Java↔Python 6-step `v=2` offline envelope parity, V1/V2 golden vectors) + `:demo` scoring & formatter unit tests.
  - **L2 (Offline Native C++ Host)**: CMake/CTest suite under `riskengine-sdk/src/test/cpp/` (`./scripts/run-cpp-tests.sh`) testing production `maps_parser` (>4 MiB), `raw_dir` fuzzing, `DiskElf` 16KB/PT_LOAD, `bionic_prop_area`, `payload_codec`, 64-bit `looks_like_trampoline`, and `crypto_mini` 100% offline.
  - **L3 (Binary-AAR Instrumentation)**: `:integration-test` consumes standalone `riskengine-sdk-release.aar` and runs on GitHub Actions Linux KVM emulators across API 30, 34, and 36.
- Native I/O uses per-ABI inline syscalls, `getdents64`, streaming `/proc/self/maps`, `pipe2(O_CLOEXEC)` `safe_mem_read`, `disposable_child` isolation for hazardous syscalls, `-fno-exceptions -fno-rtti`, ThinLTO, and polymorphic `ScopedObfString` + `secure_zero`.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/Implementation_Details.md](./docs/Implementation_Details.md) | Source-level contract: 3-module single-core layout, 16 domains, `0–100` four-dimensional scoring & `RiskPolicy`, TEE trust root, HMA side-channels, `SignedRiskEnvelope` `v=2`, 6 CI gates, L1–L3 tests, JSON v2 |
| [docs/evidence/](./docs/evidence/) | 16 per-domain Evidence Contract Records (`root.md` .. `threat_apps.md`) |
| [docs/Signed_Envelope_Verification.md](./docs/Signed_Envelope_Verification.md) | Offline 6-step server verification contract (`v=2`), rejection codes & Python/Java reference usage |
| [docs/Adversarial_Matrix.md](./docs/Adversarial_Matrix.md) | Stock OEM compatibility, adversarial stack expectations & SLA sign-off budgets |
| [docs/validation/TEMPLATE.md](./docs/validation/TEMPLATE.md) | Repeatable device validation & release sign-off report template |
| [GLOSSARY.md](./GLOSSARY.md) & [docs/adr/](./docs/adr/) | Domain vocabulary and architectural decision records (`ADR-0001`, `ADR-0002`) |

## License

MIT. See [LICENSE](./LICENSE).
