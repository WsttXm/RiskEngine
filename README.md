# RiskEngine

[中文](./README_zh.md)

An Android SDK for local device fingerprinting and runtime risk detection. Built on a Java + C++17 dual-layer architecture, RiskEngine collects device signals, runs environment detectors, and returns a structured `RiskReport` to the host app.

## What Changed

This revision focuses on reliable failure semantics, privacy-safe collection, and a redesigned Demo:

- Collector outcomes are explicit: `SUCCESS`, `EMPTY`, `ERROR`, or `UNSUPPORTED`.
- Detectors report risk presentation separately from `DetectionExecutionStatus`; failures, timeouts, unavailable checks, and partial execution are never treated as safe.
- Reports expose the fixed severe threshold (18), next threshold, complete/partial coverage, and status counts, and become immutable after aggregation.
- Collection uses one bounded deadline, serializes concurrent requests, rejects main-thread synchronous calls, and cancels cleanly across `shutdown()`.
- The default `BALANCED` privacy profile keeps only an app-scoped pseudonymous Android ID hash. Boot ID and Widevine hashes require `DIAGNOSTIC` or explicit opt-in.
- The Demo uses localized semantic states, evidence-based summaries, consistent coverage, redacted report copy, expandable raw evidence, dark mode, accessible interaction, and reduced-motion behavior.

## Requirements

- JDK 17+
- Android Gradle Plugin 8.13.1
- Compile SDK 36 / Min SDK 30
- CMake 3.22.1+, C++17

## Quick Start

Build the SDK and demo:

```bash
./build.sh sdk      # build SDK only
./build.sh demo     # build demo app
./build.sh install  # explicitly install demo on a connected device
./build.sh all      # build both
./build.sh clean    # clean
```

Or use Gradle directly:

```bash
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug :demo:assembleRelease
```

Build artifacts:

| Artifact | Path | Notes |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | Ready for host-app integration |
| SDK sources | `riskengine-sdk/build/intermediates/source_jar/release/release-sources.jar` | Source archive for distribution |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | Temporarily debug-signed for sideload testing only |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | Minified; sign with your release key before distribution |

The SDK packages native libraries for `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`.

Tag releases attach the AAR, sources JAR, POM, temporary Debug APK, and `SHA256SUMS`. The temporary APK is not for production or stores. A later release can use a different temporary key; uninstall the older Demo first if Android reports a signature mismatch.

Initialize and collect:

```java
RiskEngineConfig config = new RiskEngineConfig.Builder()
        .privacyProfile(PrivacyProfile.BALANCED)
        .collectTimeout(15000)
        .build();

RiskEngine.initIfNeeded(context, config);

RiskEngine.collect(new RiskEngineCallback() {
    @Override
    public void onSuccess(RiskReport report) {
        Log.d("RiskEngine", "Risk: " + report.getOverallRiskLevel());
        Log.d("RiskEngine", "Score: " + report.getRiskScore());
    }

    @Override
    public void onError(Throwable error) {
        Log.e("RiskEngine", "Collect failed", error);
    }
});
```

Callbacks run on an SDK background thread; switch to the main thread before updating UI. `collectTimeout` is one deadline shared by the complete request, including serialized queue wait, collectors, and detectors.

Synchronous collection:

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.reportToJson(report);       // no second collection
String freshJson = RiskEngine.collectReportJson();  // collect then serialize
```

Synchronous APIs reject calls from the Android main thread to prevent ANRs.

Call `RiskEngine.shutdown()` when the SDK is no longer needed. `init` rejects duplicate initialization; multi-entry applications can use atomic `initIfNeeded`.

## Core Detections

| Area | Examples |
| --- | --- |
| Root | `su`/Magisk artifacts, SELinux and build-context signals |
| Hook | Xposed/LSPosed, Frida, suspicious maps and processes |
| Emulator | Build props, QEMU artifacts, native emulator markers |
| Debugging | Debug flags, tracer pid, gdb/lldb/IDA artifacts |
| Sandbox / container | Container files, cgroup markers, virtualized paths |
| Device fingerprint | App-scoped Android ID hash, build props, non-sensitive telephony/Wi-Fi/Bluetooth capabilities, screen, APK signature |

The SDK declares no Android permissions. Its manifest contains package-visibility queries only for three known emulator packages.

## Result Semantics

Individual collector or detector failures do not silently become safe results. The SDK keeps the completed data and represents missing coverage explicitly:

| State | Meaning |
| --- | --- |
| `CollectorResult.Status.SUCCESS` | At least one usable value was collected |
| `CollectorResult.Status.EMPTY` | Collection completed but returned no usable value |
| `CollectorResult.Status.ERROR` | The collector failed or exceeded the available request time |
| `CollectorResult.Status.UNSUPPORTED` | The current device or platform does not expose this signal |
| `DetectionStatus` | Risk presentation: `NORMAL` / `WARNING` / `DANGER` / `UNKNOWN` |
| `DetectionExecutionStatus` | Execution: `SAFE` / `RISK` / `PARTIAL` / `UNAVAILABLE` / `DISABLED` / `TIMEOUT` / `ERROR` |

`UNKNOWN` means insufficient coverage, not “no risk.” `PARTIAL` lowers report coverage even when completed subchecks found no issue. When no warning or danger exists but one or more checks are unknown, report risk is `UNKNOWN`. Multi-source inconsistency raises an otherwise lower result to at least `MEDIUM`.

Only actionable results contribute to `riskScore`. Informational results (the deprecated compatibility name is `warnOnly`) contribute no score but can raise an otherwise safe presentation to `LOW`. Thresholds are `MEDIUM >= 4`, `HIGH >= 10`, and `DEADLY >= 18`; hard triggers can enter `DEADLY` directly. `maxRiskScore` is diagnostic capacity, not the Demo progress denominator.

## Output

`RiskReport` includes:

| Field | Description |
| --- | --- |
| `fingerprint` | Aggregated device fingerprint values |
| `detections` | Detector results and evidence |
| `overallRiskLevel` | Final risk level; `UNKNOWN` when coverage is incomplete and no warning or danger is present |
| `riskScore` / `maxRiskScore` | Actionable score and the maximum score represented by the report |
| `warningCount` / `dangerCount` | Number of warning and danger detection results |
| `unknownCount` | Number of unavailable, timed-out, or unsupported checks |
| `reportStatus` | `COMPLETE` / `PARTIAL` / `UNAVAILABLE` |
| `checkCount` / `completedCheckCount` / `coveragePercent` | Unified detector + raw-collector coverage without double-counting synthesized SDK fields |
| `timestampMs` | Collection timestamp |
| `sdkVersion` | SDK version string |

## Demo UI

The Demo is designed as a local diagnostic console rather than an automatic collector:

- It starts in a localized ready state and collects only after an explicit tap; results are never uploaded automatically.
- The top card uses localized semantic status and risk color. Progress uses the severe threshold of 18; collection errors use gray and 0%.
- Risk items are sorted first. Rows explain the actual reason before showing raw evidence, score, and subcheck coverage. Collector fields use localized labels and units, with synthesized SDK fields in a separate section.
- `UNKNOWN` is displayed as insufficient coverage and is never styled or described as safe.
- In-flight and completed UI state survives Activity recreation. Haptics fire only when a new result arrives, not after rotation or foreground return.
- A redacted summary can be copied without identifier hashes, raw system properties, paths, or PIDs.
- Semantic light/dark palettes, readable type sizes, accessibility click behavior, and meaningful completion/error haptics are included.

## Public API

| API | Description |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | Initialize the SDK |
| `RiskEngine.initIfNeeded(Context, RiskEngineConfig)` | Atomically initialize when needed and report whether this call did it |
| `RiskEngine.collect(RiskEngineCallback)` | Run collection asynchronously |
| `RiskEngine.collectSync()` | Run collection synchronously |
| `RiskEngine.collectReportJson()` | Collect a fresh report and return JSON |
| `RiskEngine.reportToJson(RiskReport)` | Serialize an existing report without collecting again |
| `RiskEngine.getReportJson()` | Deprecated compatibility alias for `collectReportJson()` |
| `RiskEngine.shutdown()` | Release SDK resources |
| `RiskEngineConfig.Builder.debugLog(boolean)` | Toggle SDK logs |
| `RiskEngineConfig.Builder.collectTimeout(long)` | Set collection timeout (1-120,000 ms) |
| `RiskEngineConfig.Builder.privacyProfile(PrivacyProfile)` | Select `MINIMAL`, `BALANCED`, or `DIAGNOSTIC` |
| `collectAndroidId/collectBootId/collectDrmId(boolean)` | Override individual identifier collection |
| `RiskEngineConfig.Builder.enableRoot/enableHookDetection/...` | Enable or disable individual detector groups |

The SDK ships with `consumer-rules.pro`; host apps need no extra ProGuard rules for the public API.

The report never exposes raw Android ID, DRM ID, boot ID, IMEI, IMSI, Wi-Fi/Bluetooth MAC, SSID, or BSSID. Deterministic package-scoped SHA-256 values are pseudonyms, not encryption, anonymization, or an absolute non-reversibility guarantee. The Demo also disables cloud backup and device-transfer extraction.

## Documentation

See [doc/Implementation_Details.md](./doc/Implementation_Details.md) for implementation details and [doc/Pending_Items.md](./doc/Pending_Items.md) for validation work that requires external devices or deployment infrastructure.

## License

See [LICENSE](./LICENSE).
