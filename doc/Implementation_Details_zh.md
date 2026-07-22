# RiskEngine 实现说明

本文档描述当前源码中的实际契约。公开用法以 [README_zh.md](../README_zh.md) 为准。

## 1. 架构与采集流程

```text
宿主调用
  -> RiskEngine 生命周期快照
  -> coordinator 单线程串行请求
  -> collectionLock（总时限包含排队）
  -> SignalSnapshot.reset()
  -> worker 池并行 Collector
  -> worker 池并行 Detector
  -> DataAggregator
  -> 不可变 RiskReport
```

- `TaskScheduler` 使用独立 coordinator 与 4 线程 worker，避免等待批任务时占满 worker。
- coordinator 队列上限为 16；队列满或关闭时异步接口调用 `onError`。
- `collectTimeout` 是从请求入队开始计算的总期限。未在期限内返回的任务会生成明确的超时/错误覆盖项。
- 同步采集禁止在主线程执行。异步回调不自动切换到主线程。
- `shutdown()` 增加生命周期代次、取消任务并清空注册表；旧代次结果不会交付。

## 2. 生命周期 API

| API | 行为 |
| --- | --- |
| `init(context, config)` | 严格初始化；重复调用抛出 `IllegalStateException` |
| `initIfNeeded(context, config)` | 原子按需初始化；已初始化时返回 `false` |
| `collect(callback)` | 异步完整采集；回调运行在线程池线程 |
| `collectSync()` | 同步完整采集；主线程调用会被拒绝 |
| `collectReportJson()` | 完整采集后序列化 JSON |
| `reportToJson(report)` | 只序列化已有报告，不重复采集 |
| `getReportJson()` | 已弃用兼容入口，等价于 `collectReportJson()` |
| `shutdown()` | 取消任务并释放 SDK 资源 |

## 3. 结果语义

### 3.1 Collector

`CollectorResult.Status`：

- `SUCCESS`：至少一个值可用；
- `EMPTY`：执行完成但没有可用值；
- `ERROR`：执行失败或未能在总期限内返回；
- `UNSUPPORTED`：平台或 Native 库不支持该信号。

`compareSources=true` 仅用于“同一语义值的多个来源”。来源值不一致时，`DeviceFingerprint` 记录字段名，并由聚合器生成 `multi_source_validation` 信号。

### 3.2 Detector

风险表现与执行状态互相独立：

| 类型 | 枚举 |
| --- | --- |
| 风险表现 | `DetectionStatus.NORMAL / WARNING / DANGER / UNKNOWN` |
| 执行状态 | `SAFE / RISK / PARTIAL / UNAVAILABLE / DISABLED / TIMEOUT / ERROR` |

`DetectionResult` 还提供 `checksAttempted`、`checksSucceeded`、`checksFailed` 与 `failureReasons`。Root、Hook、Emulator、Debug 等多子检查 Detector 会记录实际覆盖；所有关键子检查都失败时不会返回安全。

`isInformational()` 表示提示性信号：它可以帮助解释环境，但不进入 `riskScore`。旧的 `isWarnOnly()` 保留兼容并已弃用。

### 3.3 报告与评分

可处置分数阈值固定为：

| 等级 | 条件 |
| --- | --- |
| `SAFE` | 分数 0、无提示/风险且覆盖完整 |
| `LOW` | 分数 1–3，或仅有提示性信号 |
| `MEDIUM` | 分数至少 4，或至少 2 个可处置 Warning |
| `HIGH` | 分数至少 10，或至少 1 个可处置 Danger |
| `DEADLY` | 分数至少 18、至少 3 个可处置 Danger，或硬触发 |
| `UNKNOWN` | 没有已知风险，但关键覆盖不足 |

Frida PID/端口、maps 中的 Frida/Gadget 等高置信度组合可硬触发 `DEADLY`。多来源不一致会把更低的已知结果至少提升到 `MEDIUM`。

- `riskScore`：只累加非 informational 分数；
- `maxRiskScore`：本报告技术容量，不是 UI 百分比分母；
- `displayThresholdMaximum`：固定为严重阈值 18；
- `reportStatus`：`COMPLETE / PARTIAL / UNAVAILABLE`；
- `checkCount` 与 `completedCheckCount`：Detector 加原始 Collector；不重复计算 `collector:*` 覆盖信号或 SDK 合成字段；
- `coveragePercent`：`completedCheckCount / checkCount`。

聚合后 `RiskReport`、`DeviceFingerprint` 与内部 `CollectorResult` 被冻结。

## 4. 隐私配置

| 档位 | 默认标识采集 |
| --- | --- |
| `MINIMAL` | 不采 Android ID、Boot ID、Widevine |
| `BALANCED` | 仅 Android ID 应用范围哈希；默认档位 |
| `DIAGNOSTIC` | Android ID、Boot ID、Widevine 的应用范围哈希 |

`collectAndroidId`、`collectBootId`、`collectDrmId` 可以覆盖档位默认值。SDK 不采集原始 IMEI、IMSI、MAC、SSID 或 BSSID。哈希输入包含宿主包名，因此结果是确定性的应用范围假名；这不等同于加密、匿名化或绝对不可逆。

## 5. 共享信号与性能

每次报告开始前重置一个 `SignalSnapshot`。它以 `SignalResult<T>` 保存成功、空值、不可用或错误状态，并在 Collector/Detector 之间共享：

- ADB 状态；
- 系统属性；
- `/proc/self/maps`；
- 本机监听端口；
- 进程快照、文本文件、路径存在性与容器信号；
- 同一命令的结构化 Shell 结果。

因此 ADB Collector 与 Detector 不再各执行一遍完整扫描，Hook 与 Debug 也复用 Java maps/端口快照。Native Hook maps 仍通过 raw-syscall 路径独立读取，以减少 libc hook 造成的盲区。

## 6. Shell 与 Native 边界

`ShellExecutor.Result` 区分：`SUCCESS`、`INVALID_COMMAND`、`TIMEOUT`、`NON_ZERO_EXIT`、`INTERRUPTED`、`EXECUTION_ERROR`，并包含 `stdout`、`stderr`、`exitCode`、`durationMs` 与 `failureReason`。兼容的字符串接口已弃用。

Native 检测公开结构化的 `SignalResult<T>` 包装，Java Detector 可以区分库不可用、JNI 错误与有效的否定结果。

JNI 字符串不会直接把不可信字节交给 `NewStringUTF`：实现会限制输入长度、校验 UTF-8、用替换字符处理非法序列，再通过 UTF-16 `NewString` 创建 Java 字符串；C++ 分配失败与 JNI 字符获取失败也不会跨边界遗留异常。JNI 注册失败会清理挂起异常并记录具体类名。Native 构建显式启用强栈保护、Release FORTIFY、格式检查、RELRO/NOW、不可执行栈、16 KiB page 对齐、隐藏符号及编译警告。

## 7. Demo 展示契约

Demo 按以下层次呈现：

1. 中文风险结论、主要依据与处置建议；
2. 风险分（以 18 为严重阈值）、覆盖率、耗时和状态计数；
3. Detector 条目：可读依据、风险/执行状态、评分与子检查覆盖；
4. Collector 条目：中文字段名、可读单位与来源详情；
5. SDK 合成字段独立分区。

错误状态使用灰色和 0% 进度，不与最高风险混淆。内部不可用 token 不直接展示。标识哈希在摘要中缩写，字节容量转换为 GB。复制功能只输出脱敏摘要，不包含标识哈希、原始系统属性、路径或 PID。触觉反馈只在新结果到达时触发，Activity 重建不会重放。

## 8. 构建、测试与发布

```bash
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug
```

- PR 与所有分支 Push 执行单测、Lint、AAR、POM、sources JAR 和 Demo Debug APK 构建及压缩包完整性检查。
- `integration-test` 只依赖生成的 Release AAR，用于验证独立宿主可以编译和链接公开 API。
- 每周/手动设备矩阵在 API 30、33、35、36 x86_64 模拟器执行 instrumentation test。
- `vMAJOR.MINOR.PATCH` Tag 发布 AAR、sources JAR、POM、临时 Debug APK 与 SHA-256 清单。
- Debug APK 明确只用于侧载测试。流水线不保存生产签名密钥；不同 Tag 的临时证书可能不同，签名冲突时需卸载旧 Demo。

## 9. 已知验证边界

- x86_64 模拟器矩阵不能替代真实 ARM64 厂商设备；Native 反 Hook 策略、匿名可执行区白名单和厂商 ROM 误报率仍需持续真实设备回归。
- 本地风险信号可被高级对手对抗，不能替代服务端风控、硬件证明或 Play Integrity；宿主应将本 SDK 作为多源决策的一部分。
- 具体待解决项与验收方法见 [Pending_Items_zh.md](./Pending_Items_zh.md)。
