# RiskEngine

[English](./README.md)

Android 本地设备指纹采集与运行环境风险检测 SDK。采用 Java + C++17 双层架构，负责采集设备信号、执行环境检测，并向宿主应用返回结构化的 `RiskReport`。

## 本次更新

本次修改重点完善了失败语义、隐私安全与 Demo 界面：

- Collector 结果明确区分 `SUCCESS`、`EMPTY`、`ERROR` 与 `UNSUPPORTED`。
- Detector 失败、超时或不可用时返回 `DetectionStatus.UNKNOWN` 和 `RiskLevel.UNKNOWN`，不再被误判为安全。
- 报告增加风险分容量与各状态计数，允许保留部分覆盖结果，并在聚合完成后保持不可变。
- 采集任务共享一个有界总时限；并发请求串行执行；同步接口禁止主线程调用；`shutdown()` 可安全取消进行中的任务。
- 不返回原始持久标识；需要关联的值统一转换为包名作用域的 SHA-256 哈希。
- Demo 改为中文结论优先，展示覆盖率、耗时和采集状态，支持展开英文技术证据、深色模式、无障碍触控反馈与减少动态效果。

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
./build.sh install  # 显式安装 Demo 到已连接设备
./build.sh all      # 全部构建
./build.sh clean    # 清理
```

或直接使用 Gradle：

```bash
./gradlew :riskengine-sdk:testDebugUnitTest :riskengine-sdk:lintDebug
./gradlew :riskengine-sdk:assembleRelease
./gradlew :demo:lintDebug :demo:assembleDebug :demo:assembleRelease
```

构建产物：

| 产物 | 路径 | 说明 |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | 可集成到宿主应用 |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | 已使用 Debug 证书签名，可直接安装 |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | 已混淆压缩，分发前需使用正式证书签名 |

SDK 内置 `arm64-v8a`、`armeabi-v7a`、`x86_64` 与 `x86` 四种 ABI 的 Native 库。

初始化并采集：

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

回调在 SDK 后台线程执行；更新 UI 时需切换到主线程。`collectTimeout` 是整次请求共享的总时限，覆盖串行排队等待、Collector 与 Detector，而不是每个任务各自计时。

同步采集：

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.getReportJson();
```

同步接口禁止在 Android 主线程调用，以避免 ANR。

不再使用 SDK 时调用 `RiskEngine.shutdown()` 释放资源。再次初始化前必须先关闭已有实例，否则重复 `init` 会被拒绝。

## 核心检测项

| 方向 | 示例 |
| --- | --- |
| Root | `su`/Magisk 痕迹、SELinux 与构建环境信号 |
| Hook | Xposed/LSPosed、Frida、可疑 maps 与进程 |
| 模拟器 | Build 属性、QEMU 特征、Native 模拟器痕迹 |
| 调试 | Debug 标记、TracerPid、gdb/lldb/IDA 痕迹 |
| 沙箱 / 容器 | 容器文件、cgroup 标记、虚拟化路径 |
| 设备指纹 | Android ID 应用级哈希、Build 属性、非敏感 Telephony/Wi-Fi/Bluetooth 能力、屏幕、APK 签名 |

SDK 不声明任何 Android 权限；Manifest 仅为 3 个已知模拟器包声明了包可见性查询。

## 结果语义

单个 Collector 或 Detector 失败时不会被静默转换为安全结果。SDK 会保留已完成的数据，并明确表达缺失的检测覆盖：

| 状态 | 含义 |
| --- | --- |
| `CollectorResult.Status.SUCCESS` | 至少采集到一个可用值 |
| `CollectorResult.Status.EMPTY` | 采集正常结束，但没有可用值 |
| `CollectorResult.Status.ERROR` | Collector 执行失败或超出本次请求的可用时间 |
| `CollectorResult.Status.UNSUPPORTED` | 当前设备或平台不提供该信号 |
| `DetectionStatus.UNKNOWN` / `RiskLevel.UNKNOWN` | Detector 无法给出可靠结论 |

`UNKNOWN` 表示覆盖不足，不表示“没有风险”。没有 Warning 或 Danger 信号但存在未知检测项时，报告级风险为 `UNKNOWN`。多来源结果不一致会生成检测信号，并将原本更低的综合结果至少提升至 `MEDIUM`。

## 输出

`RiskReport` 包含：

| 字段 | 说明 |
| --- | --- |
| `fingerprint` | 聚合后的设备指纹值 |
| `detections` | 检测结果与证据 |
| `overallRiskLevel` | 综合风险等级；覆盖不足且没有 Warning 或 Danger 时为 `UNKNOWN` |
| `riskScore` / `maxRiskScore` | 可执行风险分与本报告所代表的最大风险分 |
| `warningCount` / `dangerCount` | Warning 与 Danger 检测结果数量 |
| `unknownCount` | 未执行、超时或不支持的检测数量 |
| `timestampMs` | 采集时间戳 |
| `sdkVersion` | SDK 版本号 |

## Demo 界面

Demo 被设计为本地诊断控制台，不会自动开始采集：

- 初始状态为 `READY`，仅在用户主动点击后执行检测，结果不会自动上传。
- 顶部卡片优先显示中文风险结论，同时展示英文枚举值、风险分、覆盖率和耗时。
- 风险项优先排列；检测条目可展开英文技术证据，采集条目可查看来源值及 `SUCCESS` / `EMPTY` / `ERROR` / `UNSUPPORTED` 状态。
- `UNKNOWN` 会被解释为“覆盖不足”，不会使用安全样式或安全描述。
- 检测进行中及已完成的界面状态可跨 Activity 重建保留；按压反馈和详情动效可以中断，并遵循系统的减少动态效果设置。
- 提供语义化深浅色主题、可读字号、无障碍点击行为，以及有意义的完成/失败触觉反馈。

## 公开 API

| API | 说明 |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | 初始化 SDK |
| `RiskEngine.collect(RiskEngineCallback)` | 异步采集 |
| `RiskEngine.collectSync()` | 同步采集 |
| `RiskEngine.getReportJson()` | 采集并返回 JSON 结果 |
| `RiskEngine.shutdown()` | 释放 SDK 资源 |
| `RiskEngineConfig.Builder.debugLog(boolean)` | 开关 SDK 日志 |
| `RiskEngineConfig.Builder.collectTimeout(long)` | 设置采集超时时间（1-120,000 毫秒） |
| `RiskEngineConfig.Builder.enableRoot/enableHookDetection/...` | 分项启用或关闭检测器 |

SDK 已提供 `consumer-rules.pro`，宿主应用无需为公开 API 额外配置 ProGuard 规则。

SDK 不输出原始 Android ID、DRM ID、Boot ID、IMEI、IMSI、Wi-Fi/Bluetooth MAC、SSID 或 BSSID。需要稳定关联的标识会先转换为包名作用域的 SHA-256 值。Demo 同时禁止云备份和设备迁移数据导出。

## 文档

完整实现细节见 [doc/Implementation_Details_zh.md](./doc/Implementation_Details_zh.md)。

## 许可证

见 [LICENSE](./LICENSE)。
