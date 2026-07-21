# RiskEngine

[中文](./README_zh.md)

An Android SDK for local device fingerprinting and runtime risk detection. Built on a Java + C++17 dual-layer architecture, RiskEngine collects device signals, runs environment detectors, and returns a structured `RiskReport` to the host app.

## What Changed

This revision focuses on reliable failure semantics, privacy-safe collection, and a redesigned Demo:

- Collector outcomes are explicit: `SUCCESS`, `EMPTY`, `ERROR`, or `UNSUPPORTED`.
- Failed, timed-out, or unavailable detectors return `DetectionStatus.UNKNOWN` and `RiskLevel.UNKNOWN` instead of being treated as safe.
- Reports expose risk score capacity and status counts, preserve partial coverage, and become immutable after aggregation.
- Collection uses one bounded deadline, serializes concurrent requests, rejects main-thread synchronous calls, and cancels cleanly across `shutdown()`.
- Raw persistent identifiers are not returned. Values used for correlation are converted to package-scoped SHA-256 hashes.
- The Demo now presents a Chinese-first risk summary, coverage, elapsed time, collector status, expandable English technical evidence, dark mode, accessible touch feedback, and reduced-motion behavior.

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
./gradlew :riskengine-sdk:testDebugUnitTest :riskengine-sdk:lintDebug
./gradlew :riskengine-sdk:assembleRelease
./gradlew :demo:lintDebug :demo:assembleDebug :demo:assembleRelease
```

Build artifacts:

| Artifact | Path | Notes |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | Ready for host-app integration |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | Debug-signed and directly installable |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | Minified; sign with your release key before distribution |

The SDK packages native libraries for `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`.

Initialize and collect:

```java
RiskEngineConfig config = new RiskEngineConfig.Builder()
        .collectTimeout(15000)
        .build();

RiskEngine.init(context, config);

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
String json = RiskEngine.getReportJson();
```

Synchronous APIs reject calls from the Android main thread to prevent ANRs.

Call `RiskEngine.shutdown()` when the SDK is no longer needed. A second `init` call is rejected until the previous instance has been shut down.

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
| `DetectionStatus.UNKNOWN` / `RiskLevel.UNKNOWN` | A detector could not produce a reliable conclusion |

`UNKNOWN` means insufficient coverage, not “no risk.” When no warning or danger signal exists but one or more checks are unknown, the report-level risk is `UNKNOWN`. Multi-source inconsistency is emitted as a detection signal and raises an otherwise lower result to at least `MEDIUM`.

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
| `timestampMs` | Collection timestamp |
| `sdkVersion` | SDK version string |

## Demo UI

The Demo is designed as a local diagnostic console rather than an automatic collector:

- It starts in `READY` and collects only after an explicit tap; results are never uploaded automatically.
- The top card shows the Chinese risk conclusion, English enum code, risk score, coverage percentage, and elapsed time.
- Risk items are sorted first. Detection rows expand to English technical evidence, while collector rows expose source values and `SUCCESS` / `EMPTY` / `ERROR` / `UNSUPPORTED` status.
- `UNKNOWN` is displayed as insufficient coverage and is never styled or described as safe.
- In-flight and completed UI state survives Activity recreation. Press feedback and detail transitions are interruptible, and system reduced-motion settings are respected.
- Semantic light/dark palettes, readable type sizes, accessibility click behavior, and meaningful completion/error haptics are included.

## Public API

| API | Description |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | Initialize the SDK |
| `RiskEngine.collect(RiskEngineCallback)` | Run collection asynchronously |
| `RiskEngine.collectSync()` | Run collection synchronously |
| `RiskEngine.getReportJson()` | Collect and return the report as JSON |
| `RiskEngine.shutdown()` | Release SDK resources |
| `RiskEngineConfig.Builder.debugLog(boolean)` | Toggle SDK logs |
| `RiskEngineConfig.Builder.collectTimeout(long)` | Set collection timeout (1-120,000 ms) |
| `RiskEngineConfig.Builder.enableRoot/enableHookDetection/...` | Enable or disable individual detector groups |

The SDK ships with `consumer-rules.pro`; host apps need no extra ProGuard rules for the public API.

The report never exposes raw Android ID, DRM ID, boot ID, IMEI, IMSI, Wi-Fi/Bluetooth MAC, SSID, or BSSID. Identifiers needed for stable correlation are converted to package-scoped SHA-256 values first. The Demo also disables cloud backup and device-transfer extraction.

## Documentation

See [doc/Implementation_Details.md](./doc/Implementation_Details.md) for the full implementation details.

## License

See [LICENSE](./LICENSE).
