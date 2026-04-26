# RiskEngine

[中文](./README_zh.md)

An Android SDK for local device fingerprinting and runtime risk detection. Built on a Java + C++17 dual-layer architecture, RiskEngine collects device signals, runs environment detectors, and returns a structured `RiskReport` to the host app.

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
./build.sh all      # build both
./build.sh clean    # clean
```

Or use Gradle directly:

```bash
./gradlew :riskengine-sdk:assembleRelease
./gradlew :demo:assembleDebug
```

Initialize and collect:

```java
RiskEngineConfig config = new RiskEngineConfig.Builder()
        .debugLog(true)
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

Synchronous collection:

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.getReportJson();
```

Call `RiskEngine.shutdown()` when the SDK is no longer needed.

## Core Detections

| Area | Examples |
| --- | --- |
| Root | `su`, Magisk, dangerous props, writable system paths |
| Hook | Xposed/LSPosed, Frida, suspicious maps and processes |
| Emulator | Build props, QEMU artifacts, native emulator markers |
| Debugging | Debug flags, tracer pid, gdb/lldb/IDA artifacts |
| Sandbox / container | Container files, cgroup markers, virtualized paths |
| Device fingerprint | Android ID, build props, telephony, Wi-Fi, Bluetooth, screen, APK signature |

## Output

`RiskReport` includes:

| Field | Description |
| --- | --- |
| `fingerprint` | Aggregated device fingerprint values |
| `detections` | Detector results and evidence |
| `overallRiskLevel` | Final risk level |
| `riskScore` | Numeric score derived from detector results |
| `timestampMs` | Collection timestamp |
| `sdkVersion` | SDK version string |

## Public API

| API | Description |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | Initialize the SDK |
| `RiskEngine.collect(RiskEngineCallback)` | Run collection asynchronously |
| `RiskEngine.collectSync()` | Run collection synchronously |
| `RiskEngine.getReportJson()` | Collect and return the report as JSON |
| `RiskEngine.shutdown()` | Release SDK resources |
| `RiskEngineConfig.Builder.debugLog(boolean)` | Toggle SDK logs |
| `RiskEngineConfig.Builder.collectTimeout(long)` | Set collection timeout (ms) |

The SDK ships with `consumer-rules.pro`; host apps need no extra ProGuard rules for the public API.

## Documentation

See [doc/Implementation_Details.md](./doc/Implementation_Details.md) for the full implementation details.

## License

See [LICENSE](./LICENSE).
