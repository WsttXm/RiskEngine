# RiskEngine

[中文](./README_zh.md)

An Android SDK for local device fingerprinting and runtime risk detection. Built as a Java + C++17 JNI stack, it collects device signals, runs environment detectors, and returns a structured `RiskReport` / JSON to the host app.

RiskEngine has **no server, no reporting channel, and no Play Integrity or SafetyNet dependency**. Results stay on the device. It produces explainable local risk signals for the host to act on; it is not a hosted risk-control product.

The current development version is `1.1.0-SNAPSHOT`.

## What it does and does not do

| Does | Does not |
| --- | --- |
| Collect non-sensitive device attributes and app-scoped identifier hashes | Collect raw IMEI / IMSI / MAC / SSID / BSSID |
| Detect root, hooks, emulators, debugging, sandboxes, cloud phones, custom ROMs | Replace server-side risk analysis, hardware attestation, or Play Integrity |
| Represent failure, timeout, and unavailability as explicit execution states | Silently treat a failed check as safe |
| Change whether a signal is scored, per collection scene | Disable detectors per scene |
| Show and copy a redacted report in the Demo | Upload results or back them up to the cloud |

A capable adversary can tamper with userspace signals. Kernel mount-namespace hiding (a complete DenyList) cannot be proven from userspace without attestation. Host apps should treat this SDK as one input among several.

## Capabilities

| Area | Detectors | Primary signals |
| --- | --- | --- |
| Root | `root`, `mount_analysis` | `su` / Magisk / KernelSU / APatch paths, `syscall_mismatch`, Magisk/module mounts, SELinux |
| Hook | `hook_framework`, `process_scan` | Xposed/LSPosed, Frida maps/ports/threads, GOT/inline hooks, JNI table, process comm |
| Native integrity | `native_tamper` | RX vs file CRC of `libriskengine.so`; anonymous mappings are actionable |
| Emulator | `emulator` | QEMU/ranchu artifacts, emulator files and packages, runtime arch, hypervisor; hardware noise is down-ranked |
| Debug | `debug` | TracerPid, debugger connection, executable maps paths, debuggable (informational by default) |
| Sandbox / cloud phone / ROM | `sandbox`, `cloud_phone`, `custom_rom` | Parallel-space packages, cloud-phone packages, community ROM props, fingerprint vs `build.prop` mismatch |
| Debug bridge | `adb` | USB/Wi-Fi ADB; informational by default, scored in the payment scene |
| Correlation | `signal_correlation` | Hidden-root, inline hook + Frida, weak emulator + hypervisor, and similar upgrades |
| Device fingerprint | A dozen collectors | Build, screen, signing cert, telephony/Wi-Fi/BT capability, ADB, containers, CPU/disk/kernel |

Artifact paths are sourced from `riskengine-sdk/src/main/resources/lists/artifact_paths.ini`. Java `DetectionLists` and native `detection_lists.h` are generated from that file.

The SDK declares no Android permissions. Its manifest contains `<queries>` package-visibility entries only for known emulator, cloud-phone, and parallel-space packages.

## Requirements

- JDK 17+
- Android Gradle Plugin 8.13.1
- Compile SDK 36 / Min SDK 30
- CMake 3.22.1+, C++17
- Native ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`

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
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug :demo:assembleRelease
```

| Artifact | Path | Notes |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | Host-app integration |
| SDK sources | `riskengine-sdk/build/intermediates/source_jar/release/release-sources.jar` | Source archive for distribution |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | Temporarily debug-signed; sideload only |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | Minified; sign with a release key before distribution |

Tag releases attach the AAR, sources JAR, POM, temporary Debug APK, and `SHA256SUMS`. The temporary APK is not for production or stores. Later tags may use a different temporary key; uninstall the older Demo if Android reports a signature mismatch.

### Initialize and collect

```java
RiskEngineConfig config = new RiskEngineConfig.Builder()
        .privacyProfile(PrivacyProfile.BALANCED)
        .collectTimeout(15000)
        .collectScene(CollectScene.STANDARD)
        .build();

RiskEngine.initIfNeeded(context, config);

RiskEngine.collect(new RiskEngineCallback() {
    @Override
    public void onSuccess(RiskReport report) {
        Log.d("RiskEngine", "Risk: " + report.getOverallRiskLevel());
        Log.d("RiskEngine", "Score: " + report.getRiskScore()
                + " / " + report.getDisplayThresholdMaximum());
        Log.d("RiskEngine", "Coverage: " + report.getCoveragePercent() + "%");
    }

    @Override
    public void onError(Throwable error) {
        Log.e("RiskEngine", "Collect failed", error);
    }
});
```

Callbacks run on an SDK background thread; switch to the main thread before updating UI. `collectTimeout` is one deadline shared by the complete request, including serialized queue wait, collectors, and detectors. The default is 10 seconds; the legal range is 1–120,000 ms.

Collect for a scene (scoring weights only; every enabled detector still runs):

```java
RiskEngine.collect(CollectScene.PAYMENT, callback);
```

Synchronous APIs reject the Android main thread:

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.reportToJson(report);       // no second collection
String freshJson = RiskEngine.collectReportJson();  // collect then serialize
```

`init` rejects duplicate initialization; multi-entry applications should use atomic `initIfNeeded`. Call `RiskEngine.shutdown()` when the SDK is no longer needed: it advances the lifecycle generation, cancels work, and clears registries. Results from older generations are not delivered.

The SDK AAR itself is not minified. Host R8 uses the bundled `consumer-rules.pro`; no extra keep rules are required for the public API.

## Collection scenes

`CollectScene` only changes the informational / actionable split. Every enabled detector still runs.

| Scene | Behavior |
| --- | --- |
| `STANDARD` | Default split. ADB, weak emulator, community ROM, and debuggable-only stay informational |
| `LOGIN` | Emulator, cloud-phone, and sandbox hits become actionable |
| `PAYMENT` | LOGIN, plus ADB becomes actionable |
| `DIAGNOSTIC` | Every non-coverage signal is actionable except a debuggable-only debug result |

Set the default with `RiskEngineConfig.Builder.collectScene(...)`. A single call can override it via `collect(scene, callback)` / `collectSync(scene)`.

## Result semantics

Individual collector or detector failures never become silent safe results. The SDK keeps completed data and represents missing coverage explicitly.

| State | Meaning |
| --- | --- |
| `CollectorResult.Status.SUCCESS` | At least one usable value was collected |
| `CollectorResult.Status.EMPTY` | Collection completed but returned no usable value |
| `CollectorResult.Status.ERROR` | The collector failed or exceeded the available request time |
| `CollectorResult.Status.UNSUPPORTED` | The current device or platform does not expose this signal |
| `DetectionStatus` | Risk presentation: `NORMAL` / `WARNING` / `DANGER` / `UNKNOWN` |
| `DetectionExecutionStatus` | Execution: `SAFE` / `RISK` / `PARTIAL` / `UNAVAILABLE` / `DISABLED` / `TIMEOUT` / `ERROR` |

`UNKNOWN` means insufficient coverage, not “no risk.” When no warning or danger exists but one or more checks are unknown, report risk is `UNKNOWN`. `PARTIAL` lowers coverage even when completed subchecks found no issue.

Only actionable (non-informational) results contribute to `riskScore`. Informational results add no score but can raise an otherwise safe presentation to `LOW`.

| Level | Rule |
| --- | --- |
| `SAFE` | Score 0, no informational/risk result, complete coverage |
| `LOW` | Score 1–3, or informational signals only |
| `MEDIUM` | Score ≥ 4, or at least two actionable warnings |
| `HIGH` | Score ≥ 10, or at least one actionable danger |
| `DEADLY` | Score ≥ 18, at least three actionable dangers, or a hard trigger |
| `UNKNOWN` | No known risk, but key coverage is unavailable |

Hard triggers include GOT/inline hooks, high-confidence Frida PID/port or maps Frida/Gadget, and correlation rule `C3` (inline hook + Frida). Multi-source field inconsistency raises an otherwise lower known result to at least `MEDIUM`.

`maxRiskScore` is technical capacity, not a UI percentage denominator. Demo progress uses the severe threshold `displayThresholdMaximum` (fixed at 18).

## Output

`RiskReport` is frozen after aggregation. Principal fields:

| Field | Description |
| --- | --- |
| `fingerprint` | Aggregated device fingerprint (collector results) |
| `detections` | Detector results and evidence tokens |
| `overallRiskLevel` | Final risk level |
| `riskScore` / `maxRiskScore` | Actionable score / technical capacity |
| `displayThresholdMaximum` | Severe threshold, fixed at 18 |
| `warningCount` / `dangerCount` / `unknownCount` | Status counts (including informational) |
| `reportStatus` | `COMPLETE` / `PARTIAL` / `UNAVAILABLE` |
| `checkCount` / `completedCheckCount` / `coveragePercent` | Detector + raw-collector coverage; excludes `collector:*` duplicates and synthesized SDK fields |
| `collectScene` | Scene actually used for this report |
| `timestampMs` / `sdkVersion` | Collection time and SDK version |

JSON is produced by `RiskReportJsonSerializer` with no extra runtime dependency. Fields match the Java model, including `informational`, `executionStatus`, `details`, and `failureReasons`.

## Privacy

| Profile | Default identifier collection |
| --- | --- |
| `MINIMAL` | No Android ID, boot ID, or Widevine |
| `BALANCED` | App-scoped Android ID SHA-256 hash only (default) |
| `DIAGNOSTIC` | Adds app-scoped boot ID and Widevine hashes |

`collectAndroidId` / `collectBootId` / `collectDrmId` override a profile. Hashes include the host package name, so they are deterministic app-scoped pseudonyms — **not** encryption, anonymization, or an absolute non-reversibility guarantee. Reports never expose raw Android ID, DRM ID, boot ID, IMEI, IMSI, Wi-Fi/Bluetooth MAC, SSID, or BSSID.

## Demo

The `demo` module is a local diagnostic console, not an automatic collector:

- It starts ready and collects only after an explicit tap; results are never uploaded.
- The status card shows a localized conclusion, primary reason, score against 18, coverage, and elapsed time. Copy-report lives in that card.
- Environment detections sort risk first. Collapsed rows show a localized title and summary only; `snake_case` detector ids and raw tokens appear in expanded details, without duplicating the Chinese/English summary.
- “Needs attention” counts actionable warning/danger only, not informational items.
- `UNKNOWN` is shown as insufficient coverage and is never styled as safe.
- Copied text is a redacted summary without identifier hashes, raw properties, paths, or PIDs.
- In-flight and completed UI state survives Activity recreation. Haptics fire only when a new result arrives.
- Cloud backup and device-transfer extraction are disabled. On a debug-signed build, “app is debuggable” is an expected informational hint and does not add to the score.

## Public API

| API | Description |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | Initialize; duplicate calls throw |
| `RiskEngine.initIfNeeded(Context, RiskEngineConfig)` | Atomically initialize when needed; returns whether this call did it |
| `RiskEngine.collect(RiskEngineCallback)` | Asynchronous collection |
| `RiskEngine.collect(CollectScene, RiskEngineCallback)` | Asynchronous collection for one scene |
| `RiskEngine.collectSync()` / `collectSync(CollectScene)` | Synchronous collection; forbidden on the main thread |
| `RiskEngine.collectReportJson()` | Collect then serialize JSON |
| `RiskEngine.reportToJson(RiskReport)` | Serialize an existing report without collecting again |
| `RiskEngine.getReportJson()` | Deprecated alias for `collectReportJson()` |
| `RiskEngine.shutdown()` | Cancel work and release resources |
| `RiskEngineConfig.Builder.debugLog(boolean)` | SDK logs |
| `RiskEngineConfig.Builder.collectTimeout(long)` | Shared deadline (1–120,000 ms) |
| `RiskEngineConfig.Builder.privacyProfile(PrivacyProfile)` | `MINIMAL` / `BALANCED` / `DIAGNOSTIC` |
| `RiskEngineConfig.Builder.collectScene(CollectScene)` | Default scene |
| `collectAndroidId` / `collectBootId` / `collectDrmId` | Override individual identifier collection |
| `enableRoot` / `enableHookDetection` / `enableEmulatorDetection` / … | Enable or disable detector groups; `native_tamper` always runs |

## Limits

- Native I/O uses per-ABI inline syscalls (not libc `syscall()`); directory walks use `getdents64`. This reduces libc-hook blind spots; it does not defeat kernel-level hiding.
- `native_tamper` treats `text_mismatch` and anonymous mappings as actionable. `missing_map` / unreadable file / bad ELF become `UNAVAILABLE`, so a Magisk-hide missing map is not reported as safe.
- x86/i386 has no ARM trampoline heuristics; the in-memory vs file CRC still runs.
- An x86_64 emulator matrix does not replace ARM64 OEM hardware. Expected evidence families are in [doc/Adversarial_Matrix.md](./doc/Adversarial_Matrix.md).

## Documentation

| Document | Contents |
| --- | --- |
| [doc/Implementation_Details.md](./doc/Implementation_Details.md) | Source-level contract: flow, detector scoring, native layer, correlation, JSON |
| [doc/Adversarial_Matrix.md](./doc/Adversarial_Matrix.md) | Expected evidence families on typical fixtures (not a bypass guide) |

## License

MIT. See [LICENSE](./LICENSE).
