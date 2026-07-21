# RiskEngine SDK

RiskEngine is an Android SDK for local device fingerprint collection and runtime risk detection. It uses a Java and C++17 dual-layer implementation to collect device signals, run environment detectors, and return a `RiskReport` to the host app.

## Project Layout

```text
.
├── build.sh
├── LICENSE
├── build.gradle.kts
├── settings.gradle.kts
├── gradle/
├── demo/
│   └── src/main/
├── riskengine-sdk/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── java/com/wsttxm/riskenginesdk/
│       │   ├── collector/
│       │   ├── core/
│       │   ├── detector/
│       │   ├── model/
│       │   └── util/
│       └── cpp/
└── doc/
    ├── Implementation_Details.md
    └── Implementation_Details_zh.md
```

## Requirements

| Item | Version |
| --- | --- |
| JDK | 17+ |
| Android Gradle Plugin | 8.13.1 |
| Compile SDK | 36 |
| Min SDK | 30 |
| CMake | 3.22.1+ |
| C++ | C++17 |

## Build

```bash
./build.sh sdk
./build.sh demo
./build.sh install
./build.sh all
./build.sh clean
```

Equivalent Gradle commands:

```bash
./gradlew :riskengine-sdk:assembleRelease
./gradlew :demo:assembleDebug
./gradlew clean
```

## Usage

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

Callbacks run on an SDK background thread. `collectTimeout` is shared by the complete request, including serialized queue wait and the collector/detector pipeline.

Synchronous collection is also available:

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.getReportJson();
```

Synchronous APIs must not be called from the Android main thread.

Call `RiskEngine.shutdown()` when the host app no longer needs the SDK. Reinitialization requires shutting down the existing instance first.

## Public API

| API | Description |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | Initialize the SDK. |
| `RiskEngine.collect(RiskEngineCallback)` | Run collection asynchronously. |
| `RiskEngine.collectSync()` | Run collection synchronously. |
| `RiskEngine.getReportJson()` | Collect and return the report as JSON. |
| `RiskEngine.shutdown()` | Release SDK resources. |
| `RiskEngineConfig.Builder.debugLog(boolean)` | Enable or disable SDK logs. |
| `RiskEngineConfig.Builder.collectTimeout(long)` | Set collection timeout from 1 to 120,000 milliseconds. |
| `RiskEngineConfig.Builder.enableRoot/enableHookDetection/...` | Enable or disable individual detector groups. |

## Detection Scope

The SDK includes Java and native checks for common Android runtime risks:

| Area | Examples |
| --- | --- |
| Root | `su`/Magisk artifacts, SELinux and build-context signals |
| Hooking | Xposed/LSPosed, Frida, suspicious maps and processes |
| Emulator | Build props, QEMU artifacts, native emulator markers |
| Debugging | Debug flags, tracer pid, gdb/lldb/IDA artifacts |
| Sandbox/container | Container files, cgroup markers, virtualized paths |
| Device fingerprint | App-scoped Android ID hash, build props, non-sensitive telephony/Wi-Fi/Bluetooth capabilities, screen, APK signature |

The library manifest declares no Android permissions and limits package-visibility queries to three known emulator packages.

## Output Model

`RiskReport` contains:

| Field | Description |
| --- | --- |
| `fingerprint` | Aggregated device fingerprint values. |
| `detections` | Detector results and evidence. |
| `overallRiskLevel` | Final risk level; `UNKNOWN` when coverage failed and no other risk is present. |
| `riskScore` | Numeric score derived from detector results. |
| `unknownCount` | Number of unavailable, timed-out, or unsupported checks. |
| `timestampMs` | Collection timestamp. |
| `sdkVersion` | SDK version string. |

## ProGuard

The SDK ships with `consumer-rules.pro`. Host apps do not need extra keep rules for the public API.

Raw Android ID, DRM ID, boot ID, IMEI, IMSI, MAC, SSID, and BSSID values are never included in reports. Stable values are converted to package-scoped SHA-256 values first.
