# RiskEngine

[English](./README.md)

Android 本地设备指纹采集与运行环境风险检测 SDK。采用 Java + C++17 JNI 双层架构：在设备上采集信号、执行环境检测，并向宿主返回结构化的 `RiskReport` / JSON。

RiskEngine **没有服务端、没有上报通道、不依赖 Play Integrity 或 SafetyNet**。结果只在本机产出。它提供的是可解释的本地风险信号，供宿主自行决策，而不是一套托管风控产品。

当前开发版本为 `1.1.0-SNAPSHOT`。本文已同步提交 `15c55ef` 的指纹与检测架构改动。

## 它做什么，不做什么

| 会做 | 不会做 |
| --- | --- |
| 采集非敏感设备属性与应用范围标识哈希 | 采集原始 IMEI / IMSI / MAC / SSID / BSSID |
| 检测 Root、Hook、模拟器、调试、沙箱、云真机、自定义 ROM | 替代服务端风控、硬件证明或 Play Integrity |
| 用独立执行状态表达失败、超时、不可用 | 把检查失败静默当成“安全” |
| 按采集场景调整分数是否计入 | 按场景关闭 Detector |
| 在 Demo 中本地展示与复制脱敏报告 | 自动上传或云备份结果 |

高级对手可以篡改用户态信号。内核级 mount namespace 隐藏（例如完整 DenyList）无法在无 attestation 的用户态保证识破。宿主应把本 SDK 作为多源决策的一部分。

## 能力概览

| 方向 | 检测器 | 主要信号 |
| --- | --- | --- |
| Root | `root`、`mount_analysis` | Root 路径、KernelSU prctl、SELinux 上下文、目录枚举交叉检查、与 PID 1 的挂载命名空间差异 |
| Hook | `hook_framework`、`process_scan` | Xposed/Frida、18 个 libc 符号的 GOT/inline 检查、ART 反射/JNI 槽位、Unix socket、W+X 映射、周期复检 |
| Native 完整性 | `native_tamper`、`sealed_verdict` | 自身可执行段分窗 FNV-1a 比对、JNI 注册指针范围检查、Native 密封分数验证 |
| 模拟器 | `emulator` | QEMU/ranchu、文件/包名、运行时架构、hypervisor、虚拟 GPU、`ro.build.characteristics` |
| 调试 | `debug` | TracerPid、调试器连接、maps 可执行路径、debuggable（默认仅提示） |
| 沙箱 / 云真机 / ROM | `sandbox`、`cloud_phone`、`custom_rom` | dexElements/UID 一致性、双开包、云厂商属性、虚拟 GPU、有线网卡、社区 ROM 属性 |
| 调试桥 | `adb` | USB/Wi-Fi ADB；默认提示性，支付场景可计入分数 |
| 一致性与交叉规则 | `consistency`、`signal_correlation` | 分区/Build 属性、CPU 核数、ABI、系统版本、验证启动状态，以及多信号组合升级 |
| 设备指纹 | 19 个默认 Collector | 新增 GPU、传感器集合、CPU 拓扑、摄像头/显示/内存/电池规格、分区指纹；生成分层 ID 与跨次连续性状态 |

清单路径以 `riskengine-sdk/src/main/resources/lists/artifact_paths.ini` 为单源，Java `DetectionLists` 与 Native `detection_lists.h` 由其生成。

SDK 不声明任何 Android 权限。Manifest 仅为已知模拟器、云真机与双开包声明了 `<queries>` 包可见性。

## 环境要求

- JDK 17+
- Android Gradle Plugin 8.13.1
- Compile SDK 36 / Min SDK 30
- CMake 3.22.1+，C++17
- Native ABI：`arm64-v8a`、`armeabi-v7a`、`x86_64`、`x86`

## 快速开始

### 构建

```bash
./build.sh sdk      # 仅构建 SDK AAR
./build.sh demo     # 构建 Demo Debug APK
./build.sh install  # 构建并安装 Demo 到已连接设备
./build.sh all      # SDK + Demo
./build.sh clean    # 清理
```

或直接使用 Gradle：

```bash
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug :demo:assembleRelease
```

| 产物 | 路径 | 说明 |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | 宿主集成 |
| SDK Sources | `riskengine-sdk/build/intermediates/source_jar/release/release-sources.jar` | 发布用源码包 |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | 临时 Debug 证书，仅供侧载 |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | 已混淆；分发前需正式证书签名 |

Tag 发布会附带 AAR、sources JAR、POM、临时 Debug APK 与 `SHA256SUMS`。临时 APK 不用于生产或应用商店；不同 Tag 的临时证书可能不同，签名冲突时请先卸载旧 Demo。

### 初始化并采集

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

回调运行在 SDK 后台线程；更新 UI 时需切回主线程。`collectTimeout` 是整次请求共享的总时限，覆盖排队等待、Collector 与 Detector，而不是每个任务各自计时。默认超时 10 秒，合法范围 1–120,000 毫秒。

按场景采集（只改分数是否计入，不关闭检测器）：

```java
RiskEngine.collect(CollectScene.PAYMENT, callback);
```

同步接口禁止在 Android 主线程调用：

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.reportToJson(report);       // 不重复采集
String freshJson = RiskEngine.collectReportJson();  // 重新采集并序列化
```

`init` 拒绝重复初始化；多入口应用使用原子的 `initIfNeeded`。不再使用时调用 `RiskEngine.shutdown()`：会推进生命周期代次、取消任务、清空生命周期状态，并唤醒、等待 Native 周期复检线程退出；旧代次结果不会交付。

SDK AAR 自身不 minify；宿主 R8 使用附带的 `consumer-rules.pro`，无需为公开 API 再写 keep 规则。

## 采集场景

场景调整 informational / actionable 划分，每次采集仍运行全部已启用的 Detector。另有 `native_tamper` 的场景策略：本次采集为 `LOGIN` / `PAYMENT` 时，映射缺失、文件不可读或可执行段全不可读会记为 `MEDIUM`/4；`STANDARD` / `DIAGNOSTIC` 下仍为 `UNAVAILABLE`。单次 `collect(scene, ...)` / `collectSync(scene)` 覆盖同样会应用于该策略与最终聚合。

| 场景 | 行为 |
| --- | --- |
| `STANDARD` | 默认划分。ADB、弱模拟器、社区 ROM、仅 `debuggable` 等为提示性，不加分 |
| `LOGIN` | 模拟器、云真机、沙箱命中改为可处置 |
| `PAYMENT` | 在 LOGIN 基础上，ADB 也改为可处置 |
| `DIAGNOSTIC` | 除「仅 debuggable 标志」外，全部非覆盖信号可处置，便于本地诊断 |

配置默认场景：`RiskEngineConfig.Builder.collectScene(...)`。单次调用可通过 `collect(scene, callback)` / `collectSync(scene)` 覆盖。

## 结果语义

单个 Collector 或 Detector 失败时不会被静默转换为安全结果。SDK 保留已完成的数据，并明确表达缺失覆盖。

| 状态 | 含义 |
| --- | --- |
| `CollectorResult.Status.SUCCESS` | 至少采集到一个可用值 |
| `CollectorResult.Status.EMPTY` | 采集正常结束，但没有可用值 |
| `CollectorResult.Status.ERROR` | Collector 执行失败或超出本次请求可用时间 |
| `CollectorResult.Status.UNSUPPORTED` | 当前设备或平台不提供该信号 |
| `DetectionStatus` | 风险展示：`NORMAL` / `WARNING` / `DANGER` / `UNKNOWN` |
| `DetectionExecutionStatus` | 执行：`SAFE` / `RISK` / `PARTIAL` / `UNAVAILABLE` / `DISABLED` / `TIMEOUT` / `ERROR` |

`UNKNOWN` 表示覆盖不足，不表示“没有风险”。没有 Warning/Danger 但存在未知检测项时，报告级风险为 `UNKNOWN`。`PARTIAL` 会降低覆盖率，即使已完成部分没有发现异常，也不能解释为全部安全。

`riskScore` 只累加可处置（非 informational）信号。提示性信号不加分，但可将完全安全的展示提升为 `LOW`。

| 综合等级 | 条件 |
| --- | --- |
| `SAFE` | 分数 0、无提示/风险、覆盖完整 |
| `LOW` | 分数 1–3，或仅有提示性信号 |
| `MEDIUM` | 分数 ≥ 4，或至少 2 个可处置 Warning |
| `HIGH` | 分数 ≥ 10，或至少 1 个可处置 Danger |
| `DEADLY` | 分数 ≥ 18、至少 3 个可处置 Danger，或硬触发 |
| `UNKNOWN` | 没有已知风险，但关键覆盖不足 |

硬触发包括：GOT/inline hook，高置信度 Frida PID/端口或 maps Frida/Gadget，以及交叉规则 `C3`（inline hook + Frida）。多来源字段不一致会把更低的已知结果至少提升到 `MEDIUM`。

`maxRiskScore` 是本报告技术容量，不是 UI 进度条分母。Demo 进度以严重阈值 `displayThresholdMaximum`（固定 18）为分母。

## 输出

`RiskReport` 在聚合后不可变，主要字段：

| 字段 | 说明 |
| --- | --- |
| `fingerprint` | 聚合后的设备指纹（各 Collector 结果，含 `fingerprint_id`） |
| `fingerprintId`（Java getter） | 硬件/系统/易变层 ID、复合 ID 与字段覆盖；构建失败时为 `null` |
| `detections` | 检测结果与证据 token |
| `overallRiskLevel` | 综合风险等级 |
| `riskScore` / `maxRiskScore` | 可处置分数 / 技术容量 |
| `displayThresholdMaximum` | 严重阈值，固定 18 |
| `warningCount` / `dangerCount` / `unknownCount` | 各状态计数（含提示性） |
| `reportStatus` | `COMPLETE` / `PARTIAL` / `UNAVAILABLE` |
| `checkCount` / `completedCheckCount` / `coveragePercent` | Detector + Collector 覆盖；排除 `collector:*` 重复项及原有两项合成字段，但当前仍计入 `fingerprint_id` |
| `collectScene` | 本次实际使用的场景 |
| `timestampMs` / `sdkVersion` | 采集时间与 SDK 版本 |

JSON 由 `RiskReportJsonSerializer` 生成，不引入额外运行时依赖，包含 `informational`、`executionStatus`、`details`、`failureReasons`。当前没有顶层 `fingerprintId`；分层 ID 与连续性位于 `fingerprint.fingerprint_id.values`。

## 分层指纹与本地存储

`report.getFingerprintId()` 返回 `FingerprintId`。硬件层使用 GPU、传感器、摄像头、CPU 等输入；系统层使用固件、分区与内核信息；易变层使用已启用的 Android ID / Boot ID 哈希。复合 ID 只组合硬件层和系统层，不包含易变层。

各层使用 SHA-256，并混入保存在应用私有 `riskengine_fp` SharedPreferences 中的 32 字节随机安装盐。存储还保留上次可靠的硬件/系统摘要、首次观察时间与观察次数。正常清除应用数据或卸载会清除这些记录；未实现跨重装关联，宿主的备份/恢复策略会影响记录是否保留。

硬件层至少采到 17 项候选输入中的 9 项，`isHardwareLayerReliable()` 才返回 `true`。连续性状态包括 `FIRST_OBSERVATION`、`STABLE`、`SYSTEM_CHANGED`、`HARDWARE_CHANGED`、`INCONCLUSIVE`、`UNKNOWN`。`HARDWARE_CHANGED` 追加 `fingerprint_continuity`（`MEDIUM`/4）。硬件层是测量摘要，驱动、配置或可用字段变化也会改变它，不保证唯一识别物理设备。

## 隐私

| 档位 | 默认标识采集 |
| --- | --- |
| `MINIMAL` | 不采 Android ID、Boot ID、Widevine |
| `BALANCED` | 仅 Android ID 的应用范围 SHA-256 哈希（默认） |
| `DIAGNOSTIC` | 另加 Boot ID、Widevine 的应用范围哈希 |

`collectAndroidId` / `collectBootId` / `collectDrmId` 可覆盖档位。哈希输入包含宿主包名，因此是确定性的应用范围假名，**不是**加密、匿名化或不可逆性保证。报告从不输出原始 Android ID、DRM ID、Boot ID、IMEI、IMSI、Wi-Fi/Bluetooth MAC、SSID 或 BSSID。

五个新增硬件 Collector 和分层 ID 构建在所有隐私档位下运行；`MINIMAL` 仅关闭上述三类标识，不关闭硬件指纹或本地连续性存储。存储不可用时，当前实现可能回退到固定盐 `riskengine`，此时不能保证安装间隔离。

## Demo

`demo` 模块是本地诊断控制台，不是自动采集器：

- 启动后处于就绪状态，仅在用户点击后执行一次检测；结果不会自动上传。
- 顶部卡片给出中文风险结论、主要依据、风险分（分母 18）、覆盖率与耗时；「复制报告」位于状态卡内。
- 环境检测优先排列风险项。折叠行只显示中文标题与语义摘要；`snake_case` 检测器名与原始 token 只在展开详情中出现，且不与中文摘要重复。
- 「需关注」只统计可处置的 Warning/Danger，不含 informational。
- `UNKNOWN` 展示为覆盖不足，不用安全样式。
- 复制内容为脱敏摘要：不含标识哈希、原始属性、文件路径与 PID。
- 检测中与已完成状态可跨 Activity 重建保留。触觉反馈只在新结果到达时触发。
- 禁止云备份与设备迁移导出；Debug 构建的「应用允许调试」属于预期提示，不计入风险分。

## 公开 API

| API | 说明 |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | 初始化；重复调用抛出 |
| `RiskEngine.initIfNeeded(Context, RiskEngineConfig)` | 原子按需初始化；返回本次是否执行了初始化 |
| `RiskEngine.collect(RiskEngineCallback)` | 异步采集 |
| `RiskEngine.collect(CollectScene, RiskEngineCallback)` | 按场景异步采集 |
| `RiskEngine.collectSync()` / `collectSync(CollectScene)` | 同步采集；禁止主线程 |
| `RiskEngine.collectReportJson()` | 完整采集并返回 JSON |
| `RiskEngine.reportToJson(RiskReport)` | 序列化已有报告，不重复采集 |
| `RiskEngine.getReportJson()` | 已弃用，等价于 `collectReportJson()` |
| `RiskEngine.shutdown()` | 取消任务并释放资源 |
| `RiskEngineConfig.Builder.debugLog(boolean)` | SDK 日志 |
| `RiskEngineConfig.Builder.collectTimeout(long)` | 总时限（1–120,000 ms） |
| `RiskEngineConfig.Builder.privacyProfile(PrivacyProfile)` | `MINIMAL` / `BALANCED` / `DIAGNOSTIC` |
| `RiskEngineConfig.Builder.collectScene(CollectScene)` | 默认场景 |
| `collectAndroidId` / `collectBootId` / `collectDrmId` | 覆盖档位中的单项标识开关 |
| `enableRoot` / `enableHookDetection` / `enableEmulatorDetection` / … | 分项启用检测器组；`native_tamper`、`consistency`、`sealed_verdict` 始终注册 |

## 能力边界

- Native I/O 走各 ABI 内联 syscall（不经过 libc `syscall()`），目录遍历使用 `getdents64`。这降低 libc hook 盲区，但不能对抗内核级隐藏。
- `sealed_verdict` 独立扫描并计分，仍由 Java 聚合为最终报告；它不受 Root/Hook 等检测器组开关控制，关闭这些组不会停止其内部同类探测。当其他检测器已报告同一证据族时，密封结果仅作为可见的重复佐证，不再计为第二个高危项。
- 密封校验使用进程内密钥、带密钥的 FNV-1a 标签、随机 nonce 与 10 秒单调时钟新鲜度窗口，不是硬件证明或标准密码学 MAC；也不能保证防止 Java 验证路径被改写或进程内 Native 攻击。
- Native 监控在 SO 加载时启动，每 20–26 秒复检自身代码、TracerPid、W+X 与框架映射；命中保留到后续 `hook_framework` 采集读取，不自动回调。`shutdown()` 会唤醒并等待线程退出；同一进程再次初始化会启动干净的新一代监控。
- 命名空间不可读、自身完整性无法比对（包括 Native 库直接从 APK 加载）均属于覆盖缺口，不是风险命中。只有精确的 `text_mismatch` 标识参与 Native 篡改计分；`text_mismatch:missing_map`、`text_mismatch:apk_embedded` 等诊断后缀不计风险分。
- x86/i386 没有 ARM trampoline 启发式；GOT 与 FNV-1a 文件/内存比对仍执行。虚拟 GPU、有线网卡、分区差异等需要 OEM 真机回归，不能单独视为环境篡改的证明。
- [doc/Adversarial_Matrix.md](./doc/Adversarial_Matrix.md) 是预期证据说明，当前仓库没有自动设备矩阵工作流。历史构建与待修问题见 [Implementation_Status_2026-09.md](./doc/Implementation_Status_2026-09.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [doc/Implementation_Details_zh.md](./doc/Implementation_Details_zh.md) | 源码级契约：流程、检测器评分、Native 层、交叉规则、JSON |
| [doc/Adversarial_Matrix.md](./doc/Adversarial_Matrix.md) | 典型环境下的预期证据族（不是绕过指南） |

## 许可证

MIT。见 [LICENSE](./LICENSE)。
