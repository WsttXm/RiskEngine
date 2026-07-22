# RiskEngine

[English](./README.md)

Android 本地设备指纹采集与运行环境风险检测 SDK。采用 Java + C++17 双层架构，负责采集设备信号、执行环境检测，并向宿主应用返回结构化的 `RiskReport`。

## 本次更新

本次修改重点完善了失败语义、隐私安全与 Demo 界面：

- Collector 结果明确区分 `SUCCESS`、`EMPTY`、`ERROR` 与 `UNSUPPORTED`。
- Detector 同时报告风险状态与独立的 `DetectionExecutionStatus`；失败、超时、不可用、部分完成不再被误判为安全。
- 报告增加统一的严重阈值（18）、下一阈值、完整/部分覆盖状态与各状态计数，并在聚合完成后保持不可变。
- 采集任务共享一个有界总时限；并发请求串行执行；同步接口禁止主线程调用；`shutdown()` 可安全取消进行中的任务。
- 默认 `BALANCED` 隐私档位只保留应用范围的 Android ID 假名化哈希；Boot ID 与 Widevine 仅在 `DIAGNOSTIC` 档位或显式开启时采集。
- Demo 统一使用中文语义状态，展示真实风险依据、覆盖率和耗时，支持脱敏报告复制、原始证据展开、深色模式、无障碍点击与减少动态效果。

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
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug :demo:assembleRelease
```

构建产物：

| 产物 | 路径 | 说明 |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | 可集成到宿主应用 |
| SDK Sources | `riskengine-sdk/build/intermediates/source_jar/release/release-sources.jar` | 发布用源码包 |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | 临时 Debug 证书签名，仅供侧载测试 |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | 已混淆压缩，分发前需使用正式证书签名 |

SDK 内置 `arm64-v8a`、`armeabi-v7a`、`x86_64` 与 `x86` 四种 ABI 的 Native 库。

Tag 发布会附带 AAR、sources JAR、POM、临时 Debug APK 与 `SHA256SUMS`。临时 Debug APK 不用于生产或应用商店；不同发布的临时证书可能不同，如升级安装提示签名不一致，请先卸载旧 Demo。

初始化并采集：

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

回调在 SDK 后台线程执行；更新 UI 时需切换到主线程。`collectTimeout` 是整次请求共享的总时限，覆盖串行排队等待、Collector 与 Detector，而不是每个任务各自计时。

同步采集：

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.reportToJson(report);       // 不重复采集
String freshJson = RiskEngine.collectReportJson();  // 重新采集并序列化
```

同步接口禁止在 Android 主线程调用，以避免 ANR。

不再使用 SDK 时调用 `RiskEngine.shutdown()` 释放资源。`init` 会拒绝重复初始化；多入口应用可使用原子的 `initIfNeeded`。

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
| `DetectionStatus` | 风险展示状态：`NORMAL` / `WARNING` / `DANGER` / `UNKNOWN` |
| `DetectionExecutionStatus` | 执行状态：`SAFE` / `RISK` / `PARTIAL` / `UNAVAILABLE` / `DISABLED` / `TIMEOUT` / `ERROR` |

`UNKNOWN` 表示覆盖不足，不表示“没有风险”。没有 Warning 或 Danger 信号但存在未知检测项时，报告级风险为 `UNKNOWN`。`PARTIAL` 会降低报告覆盖率，即使已完成部分没有发现异常，也不能解释为全部安全。多来源结果不一致会生成检测信号，并将原本更低的综合结果至少提升至 `MEDIUM`。

`riskScore` 只累加可处置信号；提示性（`informational`，旧接口名 `warnOnly`）信号不加分，但可将完全安全的结果展示为 `LOW`。分数阈值为：`MEDIUM >= 4`、`HIGH >= 10`、`DEADLY >= 18`；硬触发信号可直接进入 `DEADLY`。`maxRiskScore` 仅用于技术诊断，不作为 Demo 进度条分母。

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
| `reportStatus` | `COMPLETE` / `PARTIAL` / `UNAVAILABLE` |
| `checkCount` / `completedCheckCount` / `coveragePercent` | 统一的 Detector + 原始 Collector 覆盖口径；不重复计算 SDK 合成项 |
| `timestampMs` | 采集时间戳 |
| `sdkVersion` | SDK 版本号 |

## Demo 界面

Demo 被设计为本地诊断控制台，不会自动开始采集：

- 初始状态为“就绪”，仅在用户主动点击后执行检测，结果不会自动上传。
- 顶部卡片使用中文语义状态和风险着色，风险进度以严重阈值 18 为分母；错误状态使用灰色和 0% 进度。
- 风险项优先排列；检测条目先解释真实依据，再展示原始证据、评分和子检查覆盖；采集字段使用中文名称和单位，SDK 合成项独立分区。
- `UNKNOWN` 会被解释为“覆盖不足”，不会使用安全样式或安全描述。
- 检测进行中及已完成的界面状态可跨 Activity 重建保留；触觉反馈只在新结果到达时触发，不会因旋转或切回前台重放。
- 可复制不含设备标识哈希、原始属性、文件路径与 PID 的脱敏摘要。
- 提供语义化深浅色主题、可读字号、无障碍点击行为，以及有意义的完成/失败触觉反馈。

## 公开 API

| API | 说明 |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | 初始化 SDK |
| `RiskEngine.initIfNeeded(Context, RiskEngineConfig)` | 原子地按需初始化；返回本次是否执行了初始化 |
| `RiskEngine.collect(RiskEngineCallback)` | 异步采集 |
| `RiskEngine.collectSync()` | 同步采集 |
| `RiskEngine.collectReportJson()` | 完整采集并返回 JSON 结果 |
| `RiskEngine.reportToJson(RiskReport)` | 序列化已有报告，不重复采集 |
| `RiskEngine.getReportJson()` | 已弃用的兼容接口；等价于 `collectReportJson()` |
| `RiskEngine.shutdown()` | 释放 SDK 资源 |
| `RiskEngineConfig.Builder.debugLog(boolean)` | 开关 SDK 日志 |
| `RiskEngineConfig.Builder.collectTimeout(long)` | 设置采集超时时间（1-120,000 毫秒） |
| `RiskEngineConfig.Builder.privacyProfile(PrivacyProfile)` | 设置 `MINIMAL` / `BALANCED` / `DIAGNOSTIC` 隐私档位 |
| `collectAndroidId/collectBootId/collectDrmId(boolean)` | 覆盖档位中的单项标识采集开关 |
| `RiskEngineConfig.Builder.enableRoot/enableHookDetection/...` | 分项启用或关闭检测器 |

SDK 已提供 `consumer-rules.pro`，宿主应用无需为公开 API 额外配置 ProGuard 规则。

SDK 不输出原始 Android ID、DRM ID、Boot ID、IMEI、IMSI、Wi-Fi/Bluetooth MAC、SSID 或 BSSID。所用 SHA-256 值是确定性的应用范围假名，不是加密、匿名化或不可逆性的绝对保证。Demo 同时禁止云备份和设备迁移数据导出。

## 文档

完整实现细节见 [doc/Implementation_Details_zh.md](./doc/Implementation_Details_zh.md)；需要外部设备或发布基础设施才能闭环的事项见 [doc/Pending_Items_zh.md](./doc/Pending_Items_zh.md)。

## 许可证

见 [LICENSE](./LICENSE)。
