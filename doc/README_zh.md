# RiskEngine SDK

RiskEngine 是一个 Android 本地设备指纹采集与运行环境风险检测 SDK。SDK 采用 Java + C++17 双层实现，负责采集设备信号、执行风险检测，并向宿主应用返回 `RiskReport`。

## 项目结构

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
    ├── README.md
    └── README_zh.md
```

## 环境要求

| 项目 | 版本 |
| --- | --- |
| JDK | 17+ |
| Android Gradle Plugin | 8.13.1 |
| Compile SDK | 36 |
| Min SDK | 30 |
| CMake | 3.22.1+ |
| C++ | C++17 |

## 构建

```bash
./build.sh sdk
./build.sh demo
./build.sh all
./build.sh clean
```

等价 Gradle 命令：

```bash
./gradlew :riskengine-sdk:assembleRelease
./gradlew :demo:assembleDebug
./gradlew clean
```

## 使用方式

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

也可以同步采集：

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.getReportJson();
```

宿主应用不再使用 SDK 时调用 `RiskEngine.shutdown()` 释放资源。

## 公开 API

| API | 说明 |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | 初始化 SDK。 |
| `RiskEngine.collect(RiskEngineCallback)` | 异步采集。 |
| `RiskEngine.collectSync()` | 同步采集。 |
| `RiskEngine.getReportJson()` | 采集并返回 JSON 结果。 |
| `RiskEngine.shutdown()` | 释放 SDK 资源。 |
| `RiskEngineConfig.Builder.debugLog(boolean)` | 开关 SDK 日志。 |
| `RiskEngineConfig.Builder.collectTimeout(long)` | 设置采集超时时间，单位毫秒。 |

## 检测范围

SDK 内置 Java 与 Native 检测能力，覆盖常见 Android 运行环境风险：

| 方向 | 示例 |
| --- | --- |
| Root | `su`、Magisk、危险属性、可写系统路径 |
| Hook | Xposed/LSPosed、Frida、可疑 maps 与进程 |
| 模拟器 | Build 属性、QEMU 特征、Native 模拟器痕迹 |
| 调试 | Debug 标记、TracerPid、gdb/lldb/IDA 痕迹 |
| 沙箱/容器 | 容器文件、cgroup 标记、虚拟化路径 |
| 设备指纹 | Android ID、Build 属性、Telephony、Wi-Fi、Bluetooth、屏幕、APK 签名 |

## 输出模型

`RiskReport` 包含：

| 字段 | 说明 |
| --- | --- |
| `fingerprint` | 聚合后的设备指纹值。 |
| `detections` | 检测结果与证据。 |
| `overallRiskLevel` | 综合风险等级。 |
| `riskScore` | 根据检测结果计算出的风险分。 |
| `timestampMs` | 采集时间戳。 |
| `sdkVersion` | SDK 版本号。 |

## ProGuard

SDK 已提供 `consumer-rules.pro`，宿主应用无需为公开 API 额外配置 keep 规则。
