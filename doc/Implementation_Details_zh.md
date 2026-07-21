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
    ├── Implementation_Details.md
    └── Implementation_Details_zh.md
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
./build.sh install
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

回调运行在 SDK 后台线程。`collectTimeout` 覆盖串行排队等待以及 Collector/Detector 管线，是整次请求共享的总时限。

也可以同步采集：

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.getReportJson();
```

同步接口不得在 Android 主线程调用。

宿主应用不再使用 SDK 时调用 `RiskEngine.shutdown()` 释放资源；如需重新初始化，必须先关闭已有实例。

## 公开 API

| API | 说明 |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | 初始化 SDK。 |
| `RiskEngine.collect(RiskEngineCallback)` | 异步采集。 |
| `RiskEngine.collectSync()` | 同步采集。 |
| `RiskEngine.getReportJson()` | 采集并返回 JSON 结果。 |
| `RiskEngine.shutdown()` | 释放 SDK 资源。 |
| `RiskEngineConfig.Builder.debugLog(boolean)` | 开关 SDK 日志。 |
| `RiskEngineConfig.Builder.collectTimeout(long)` | 设置 1 至 120,000 毫秒的采集超时时间。 |
| `RiskEngineConfig.Builder.enableRoot/enableHookDetection/...` | 分项启用或关闭检测器。 |

## 检测范围

SDK 内置 Java 与 Native 检测能力，覆盖常见 Android 运行环境风险：

| 方向 | 示例 |
| --- | --- |
| Root | `su`/Magisk 痕迹、SELinux 与构建环境信号 |
| Hook | Xposed/LSPosed、Frida、可疑 maps 与进程 |
| 模拟器 | Build 属性、QEMU 特征、Native 模拟器痕迹 |
| 调试 | Debug 标记、TracerPid、gdb/lldb/IDA 痕迹 |
| 沙箱/容器 | 容器文件、cgroup 标记、虚拟化路径 |
| 设备指纹 | Android ID 应用级哈希、Build 属性、非敏感 Telephony/Wi-Fi/Bluetooth 能力、屏幕、APK 签名 |

SDK Manifest 不声明 Android 权限，包可见性查询仅限 3 个已知模拟器包。

## 输出模型

`RiskReport` 包含：

| 字段 | 说明 |
| --- | --- |
| `fingerprint` | 聚合后的设备指纹值。 |
| `detections` | 检测结果与证据。 |
| `overallRiskLevel` | 综合风险等级；覆盖不足且无其他风险时为 `UNKNOWN`。 |
| `riskScore` | 根据检测结果计算出的风险分。 |
| `unknownCount` | 未执行、超时或不支持的检测数量。 |
| `timestampMs` | 采集时间戳。 |
| `sdkVersion` | SDK 版本号。 |

## ProGuard

SDK 已提供 `consumer-rules.pro`，宿主应用无需为公开 API 额外配置 keep 规则。

原始 Android ID、DRM ID、Boot ID、IMEI、IMSI、MAC、SSID 和 BSSID 不进入报告；确需稳定关联的值先转换为包名作用域的 SHA-256。
