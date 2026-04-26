# RiskEngine

[English](./README.md)

Android 本地设备指纹采集与运行环境风险检测 SDK。采用 Java + C++17 双层架构，负责采集设备信号、执行环境检测，并向宿主应用返回结构化的 `RiskReport`。

## 环境要求

- JDK 17+
- Android Gradle Plugin 8.13.1
- Compile SDK 36 / Min SDK 30
- CMake 3.22.1+，C++17

## 快速开始

构建 SDK 与 Demo：

```bash
./build.sh sdk      # 仅构建 SDK
./build.sh demo     # 构建 Demo
./build.sh all      # 全部构建
./build.sh clean    # 清理
```

或直接使用 Gradle：

```bash
./gradlew :riskengine-sdk:assembleRelease
./gradlew :demo:assembleDebug
```

初始化并采集：

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

同步采集：

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.getReportJson();
```

不再使用 SDK 时调用 `RiskEngine.shutdown()` 释放资源。

## 核心检测项

| 方向 | 示例 |
| --- | --- |
| Root | `su`、Magisk、危险属性、可写系统路径 |
| Hook | Xposed/LSPosed、Frida、可疑 maps 与进程 |
| 模拟器 | Build 属性、QEMU 特征、Native 模拟器痕迹 |
| 调试 | Debug 标记、TracerPid、gdb/lldb/IDA 痕迹 |
| 沙箱 / 容器 | 容器文件、cgroup 标记、虚拟化路径 |
| 设备指纹 | Android ID、Build 属性、Telephony、Wi-Fi、Bluetooth、屏幕、APK 签名 |

## 输出

`RiskReport` 包含：

| 字段 | 说明 |
| --- | --- |
| `fingerprint` | 聚合后的设备指纹值 |
| `detections` | 检测结果与证据 |
| `overallRiskLevel` | 综合风险等级 |
| `riskScore` | 根据检测结果计算出的风险分 |
| `timestampMs` | 采集时间戳 |
| `sdkVersion` | SDK 版本号 |

## 公开 API

| API | 说明 |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | 初始化 SDK |
| `RiskEngine.collect(RiskEngineCallback)` | 异步采集 |
| `RiskEngine.collectSync()` | 同步采集 |
| `RiskEngine.getReportJson()` | 采集并返回 JSON 结果 |
| `RiskEngine.shutdown()` | 释放 SDK 资源 |
| `RiskEngineConfig.Builder.debugLog(boolean)` | 开关 SDK 日志 |
| `RiskEngineConfig.Builder.collectTimeout(long)` | 设置采集超时时间（毫秒） |

SDK 已提供 `consumer-rules.pro`，宿主应用无需为公开 API 额外配置 ProGuard 规则。

## 文档

完整实现细节见 [doc/Implementation_Details_zh.md](./doc/Implementation_Details_zh.md)。

## 许可证

见 [LICENSE](./LICENSE)。
