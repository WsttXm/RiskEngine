# RiskEngine 实现说明

本文档是当前源码中的契约，而不是设计意向。宿主集成以 [README_zh.md](../README_zh.md) 为准。典型环境下的预期证据族见 [Adversarial_Matrix.md](./Adversarial_Matrix.md)。服务端离线 6 步验签说明见 [Signed_Envelope_Verification.md](./Signed_Envelope_Verification.md)。

本文已按 `2.0.0-SNAPSHOT`（v2.0.0 终态版）的实际实现同步。

## 1. 定位与模块

RiskEngine 是本地 Android 风险信号、硬件信任根认证与设备指纹 SDK：Java 负责非阻塞编排、推拉双模生命周期、隐私、标准化 `0–100` 四维评分引擎（`RiskScoringEngine`）、宿主可配置本地策略（`RiskPolicy`）、结构化证据模型（`EvidenceItem`）、安全卫生态势（`DevicePosture`）、版本化分层指纹（`FingerprintVersion` V1/V2）、硬件 Keystore 绑定、TEE/KeyMint/RKP X.509 证明与离线可验 `SignedRiskEnvelope`（`v=2`）、高危应用/HMA 行为探针（`ThreatAppPolicy`）及最终报告；C++17 JNI 负责抗 libc hook 的内联 syscall I/O、环境探测、原始 `base.apk` 签名解析、双路径反调试与可选 `PR_SET_DUMPABLE(0)`、COW 安全自完整性（内聚于 `hook_framework`）、Widevine NDK 一致性、TEE Binder `ioctl` 探测、一次性子进程 HMA UID/Seccomp-notif 侧信道、`NativePayloadCodec` 线协议及事件驱动周期监控。RiskEngine 以单一零依赖核心 SDK（`:riskengine-sdk`）交付，无服务端依赖、无上报、零 Play Integrity / Kotlin / 第三方运行时依赖（详见 [ADR-0001](./adr/0001-single-core-sdk-without-extension-submodules.md)）。

仓库模块：

| 模块 | 作用 |
| --- | --- |
| `riskengine-sdk` | 可发布核心 AAR。Java 11 字节码（JDK 17 构建），minSdk 30，compileSdk 36，targetSdk 36。零第三方运行时依赖、零 `<uses-permission>`、零 `useAppZygote`；通过 JDK 17 `javap` 锁定公开 ABI（`api/riskengine-sdk.api`）；AAR 自身不 minify |
| `demo` | 基于 Fluid Design v2 的本地诊断控制台（首次初始化前隐私同意弹窗、`0–100` 3 阶段渐进 `RiskGaugeView`、四维风险子分条、推荐 `RiskAction` 标签、评估置信度、可展开 `ScoreBreakdown` 归因抽屉、分层指纹分桶与连续性/绑定卡片 + `resetFingerprintBaseline()`、实时 `ThreatStreamDrawer` 与覆盖全部 16 大收敛检测域的 `ReportFormatter`）。Debug 临时签名；Release 混淆但未签正式证书 |
| `integration-test` | 严格消费独立 Release AAR 二进制（`riskengine-sdk-release.aar`），运行 L3 端到端仪器测试（`SmokeActivity` + `RiskEngineInstrumentationTest`），覆盖 GitHub Actions KVM API 30/34/36 模拟器矩阵 |

当前开发版本：`2.0.0-SNAPSHOT`（`gradle.properties` 的 `riskEngineVersion`）。Tag 发布工作流会覆盖 `releaseVersionName`。

## 2. 架构、延迟分层与采集流程

```text
宿主调用（拉取 collect/collectSync/collectSignedEnvelopeSync 或 推送 startMonitoring）
  -> RiskEngine 生命周期快照（generation、config、registries、lock）
  -> coordinator 单线程串行请求（队列上限 16）
  -> collectionLock（总时限包含排队等待）
  -> SignalSnapshot.reset()
  -> worker 池分级执行（TaskScheduler.submitAllWithSafeTimeout -> SafeExecutor.safeWithTimeout）
       Stage 1 CRITICAL: app_integrity、debug、hook_framework  -> onCriticalChecksFinished(TierReport, 0–100 标尺)
       Stage 2 FAST:     11 个快速检测域                       -> onFastChecksFinished(TierReport, 0–100 标尺)
       Stage 3 POSTPONED: 22/24 个 Collector + tee_integrity（TEE/KeyMint/RKP + Grant-Domain 切分）
                          + threat_apps（官方证书谱系 + HMA/Thanox 全代际侧信道）
                          + 7 个检测域双阶段延后探针
                          （consistency、root、mount_analysis、hook_framework、emulator、cloud_phone、multi_instance）
                          -> 完整 DataAggregator 聚合
  -> DataAggregator
       applyPolicy（CollectScene + RiskPolicy 策略覆盖）
       -> 顺序无关 family-max dedupeFamilies -> correlate (C1–C10)
       -> collector ERROR 覆盖信号 / 多来源不一致
       -> FingerprintIdBuilder (V1/V2 + Stability + Hasher) + FingerprintStore (AES-256-GCM DE + 不可变锚点 + device_binding)
       -> DevicePosture 闭环（systemVpn、unofficialStore、lockscreenOrBiometricReset）
       -> EvidenceItem 跨源自动合并（JAVA + NATIVE -> mergedSources）
       -> RiskScoringEngine（0–100 四维 Noisy-OR、Corroboration Lift、纯 LOW <= 35 封顶、
          Hard Trigger 95–100 保底、分层评估置信度、ScoreBreakdown、RiskAction 与 TrustTier）
       -> 合成字段（hook_memory_signals / runtime_integrity_score_inputs / fingerprint_id）
  -> 不可变 RiskReport / 可选 SignedRiskEnvelope (v=2, ECDSA P-256) / 增量 JSON v2
     / onPostponedChecksFinished + DeviceStateListener
```

- **主线程零同步 IO 初始化**：`NativeCollectorBridge` 移除阻塞式 `static {}` `System.loadLibrary()`，改为幂等懒加载 `ensureNativeLoaded()` / `isNativeLoaded()`。`RiskEngine.init()` / `initIfNeeded()` 在调用线程零 `SharedPreferences`、零 Keystore、零 `.so` 加载；后台异步启动任务负责加载 `libriskengine.so`、应用 `enableAntiDumpable`、按代次守卫启停 Native 周期监控（遇并发 `shutdown()` 锁外补偿停止）及预热 `FingerprintStore`。
- `TaskScheduler` 分离 coordinator 与 4 线程 worker 池，并通过 `SafeExecutor.safeWithTimeout` 落实 `TierBudgets`（`CRITICAL`/`FAST`/`POSTPONED`）；超时时捕获阻塞线程 `StackTraceElement[]` 诊断日志，并用 `ThreadLocal<Boolean>` 防止嵌套超时导致线程池饥饿。
- 异步请求在队列满或 SDK 关闭时调用 `onError`（`RejectedExecutionException` 包装为 `IllegalStateException`）。
- `collectTimeout` 从请求入队开始计算。未在期限内返回的任务由 `addMissingCollectorResults` / `addMissingDetectionResults` 补成明确的超时/错误覆盖项。
- 同步采集禁止 Android 主线程；异步与推送回调均运行在 SDK 后台线程。
- `shutdown()` 在持有 `lifecycleLock` 期间原子推进 `lifecycleGeneration`、清空推送监听、注销 `AppLifecycleObserver`、取消任务并清空注册表，随后**先释放 `lifecycleLock`** 再调用 `native_monitor_stop()`（内部在互斥锁外 `pthread_join`）。

## 3. 生命周期、推拉双模与主动窗口防护 API

| API | 行为 |
| --- | --- |
| `init(context, config)` | 非阻塞严格初始化；重复调用抛 `IllegalStateException` |
| `initIfNeeded(context, config)` | 原子按需初始化；已初始化时返回 `false` |
| `startMonitoring(threat, state, exec)` | 在 `lifecycleLock` 内原子绑定 `ThreatListener`、`DeviceStateListener`、`ExecutionStateListener`，按 `CRITICAL -> FAST -> POSTPONED` 顺序下发启动分层检测并接入实时 Native/截录屏推送 |
| `stopMonitoring()` | 原子解绑推送监听并推进 `monitoringGeneration`，不关闭 SDK |
| `collect(callback)` / `collect(scene, callback)` | 异步拉取采集 |
| `collectSync()` / `collectSync(scene)` | 同步完整拉取采集；主线程抛异常 |
| `collectSignedEnvelopeSync(scene, challenge, mode)` | 同步采集并生成 ECDSA P-256 硬件证明签名信封 `SignedRiskEnvelope`（`v=2`，默认 `EnvelopeMode.PERSISTENT_KEY` `< 10ms` 快路径，或 `EnvelopeMode.FRESH_ATTESTATION` 每次独立密钥对；无硬件能力时显式标记 `SOFTWARE_FALLBACK`） |
| `collectReportJson()` / `reportToJson(report)` | 采集并序列化，或仅序列化增量 JSON v2（`SignedRiskEnvelope.toJson()` / `RiskReportJsonSerializer.serialize(report, envelope)` 可附带可选 `signedEnvelope` 块） |
| `resetFingerprintBaseline()` | 显式清空/重锚不可变硬件指纹基线（保留安装盐） |
| `getReportJson()` | 已弃用，等价于 `collectReportJson()` |
| `shutdown()` | 取消任务、注销 `AppLifecycleObserver`、释放资源并在锁外等待 Native 周期监控退出；保留指纹存储 |
| `RiskPolicy` / `RiskPolicy.Builder` | 基于 `CollectScene` 预设的不可变本地策略引擎：支持 `dimensionWeight`、`actionThresholds`、`highAction`、`allowlistFamily`、`informationalOnlyFamily`、`familyMode`、`familyMultiplier`、`suppressHardTrigger`，通过 `RiskEngineConfig.Builder.riskPolicy(...)` 接入 |
| `RiskWindowGuard` | 宿主显式可选助手：`enableScreenCaptureProtection(Activity, boolean)`（`FLAG_SECURE`）、`enableOverlayProtection(Activity, boolean)`（API 31+ `setHideOverlayWindows`）、`enableTouchObscuredFilter(View, boolean)` |

配置默认值：全部 16 个收敛检测域开启（`enableTeeAttestation=true`、`enableThreatAppDetection=true`）、`debugLog=false`、超时 `10_000 ms`、`PrivacyProfile.BALANCED`、`CollectScene.STANDARD`、`RiskPolicy.forScene(CollectScene.STANDARD)`、`FingerprintVersion.V2`、`FingerprintStability.OPTIMAL`、`enableAntiDumpable=false`、`enableIsolatedProcessProbe=true`、`enablePeriodicMonitor=true`。`consistency` 始终注册。

- **双阶段延后分层（Dual-pass `POSTPONED`）**：`BaseDetector` 提供 `hasPostponedProbes()` / `detectPostponed(DetectionResult prior)` / `callPostponed(prior)`。在 `startMonitoring()` 与 `collectSync()` 中，Stage 1（`CRITICAL`）与 Stage 2（`FAST`）优先产出低延迟结论（通过 `RiskScoringEngine.evaluateTier` 对齐统一 `0–100` 标尺），Stage 3（`POSTPONED`）执行 `tee_integrity` 与重探针（`disposable_child` 隔离子进程陷阱、`RiskIsolatedProbeService` 跨进程挂载比对与 Keystore2 Grant-Domain 证书链校验、`ZygiskProbe`、`LsposedProbe`、`SensorNoiseProbe`）并与前置结果无损合并。
- **`RiskIsolatedProbeService`（`android:isolatedProcess="true"`）**：按需拉起的跨进程隔离助手，同时承担 `/proc/self/mountinfo` 视图差集采集与 Keystore2 Grant-Domain 跨 UID 证书链比对（`IsolatedProbeClient.probeGrantDomainChain`）。`onBind` 严格以 `Process.isIsolated()` 实行 fail-closed 守卫；`IsolatedProbeClient` 在限时预算内运行并在 `finally` 立即 `unbindService()` 绝不常驻。宿主可通过 `enableIsolatedProcessProbe(false)` 或在 Manifest 中用 `tools:node="remove"` 剥离。

## 4. Collector（默认 22 个 / `DIAGNOSTIC` 下 24 个）

`CollectorResult.Status`：`SUCCESS`、`EMPTY`、`ERROR`、`UNSUPPORTED`。`BaseCollector.call()` 与 `BaseDetector.call()` 均捕获 `Exception | LinkageError | OutOfMemoryError`。

`compareSources=true` 仅用于「同一语义值的多个来源」，不一致时生成 `multi_source_validation`（`MEDIUM` / `WARNING` / 分数 4 / 可处置）。

### 4.1 Java 层（18 个）

| `fieldName` | 类 | 内容 | 隐私约束 |
| --- | --- | --- | --- |
| `android_id` | `AndroidIdCollector` | 应用范围 SHA-256（包名加盐；`Uri.parse` 在 `try` 保护内） | `BALANCED`/`DIAGNOSTIC`，可被 `collectAndroidId` 覆盖 |
| `build_props` | `BuildPropsCollector` | `Build.*` 非敏感属性 | 始终 |
| `screen_info` | `ScreenInfoCollector` | 宽高、dpi、密度 | 始终；与 `SignalSnapshot` 共享 |
| `apk_signature` | `ApkSignatureCollector` | 签名证书哈希 | 始终 |
| `bluetooth_info` | `BluetoothCapabilityCollector` | 能力，不含 MAC | 始终 |
| `wifi_info` | `WifiInfoCollector` | 能力（如 Wi-Fi Direct），不含 SSID/BSSID/MAC | 始终 |
| `telephony` | `TelephonyCollector` | 电话类型、SIM 状态，不含 IMEI/IMSI | 始终 |
| `settings` | `SettingsCollector` | 开发者选项等 | 始终 |
| `adb_state` | `AdbStateCollector` | USB/Wi-Fi ADB | 始终；共享 `AdbInspector` |
| `container_signals` | `ContainerSignalCollector` | cgroup / 容器路径 | 始终 |
| `gpu_info` | `GpuInfoCollector` | 离屏 EGL pbuffer（`eglReleaseThread()`，绝不调 `eglTerminate(EGL_DEFAULT_DISPLAY)`）：vendor/renderer、GL/EGL 版本、扩展哈希与限制 | 始终 |
| `sensor_fingerprint` | `SensorFingerprintCollector` | 排序传感器元组与厂商集合哈希、数量与能力 | 始终 |
| `cpu_topology` | `CpuTopologyCollector` | Runtime/sysfs/procfs 核数、implementer/part 分布、频率范围、ABI、SoC（API 31+） | 始终 |
| `hardware_profile` | `HardwareProfileCollector` | 内存分桶、显示模式/HDR、摄像头规格与哈希、电池信息、系统共享库哈希 | 始终 |
| `partition_fingerprints` | `PartitionFingerprintCollector` | 分区指纹、构建日期、verified boot/vbmeta 等属性 | 始终；Native 属性白名单 |
| `codec_info` | `MediaCodecCollector` | 零权限 `MediaCodecList(ALL_CODECS)` 排序编解码器/硬解/软解矩阵摘要与计数 | 始终 |
| `input_devices` | `InputDeviceCollector` | 零权限 `InputManager` 排序 `(name, vendorId, productId, sources)` 摘要与虚拟输入计数 | 始终 |
| `security_posture` | `SecurityPostureCollector` | 零权限 `Security.getProviders()` 摘要、`KeyguardManager.isDeviceSecure()`、`DevicePolicyManager` 磁盘加密、Keystore 安全级别（`STRONGBOX`/`TEE`/`SOFTWARE`）、生物识别就绪与开发者选项状态 | 始终 |

### 4.2 Native 层（JNI bridge，默认 4 个 / `DIAGNOSTIC` 下 6 个）

| `fieldName` | 内容 | 隐私约束 |
| --- | --- | --- |
| `drm_id` | Widevine 应用范围哈希 | 仅 `DIAGNOSTIC` 或 `collectDrmId(true)` |
| `boot_id` | `/proc/sys/kernel/random/boot_id` 应用范围哈希 | 仅 `DIAGNOSTIC` 或 `collectBootId(true)` |
| `system_properties_native` | 白名单属性，见 ini `[properties]`；部分 SELinux 受限时记录 `partial_errors` 且 `>= 1` 成功即保持 `SUCCESS` | 始终 |
| `cpu_info` | 结构化 `CpuInfoParser` 解析 `/proc/cpuinfo`（`commonInfo` + `perCoreInfo`；保留 `flags` `hypervisor`/`vmx`/`svm` 与 `model name`；指纹哈希自动剔除易变 `BogoMIPS` 与 `cpu MHz`） | 始终 |
| `disk_size` | 数据分区大小（32 位 ARM/i386 使用 `__NR_statfs64`） | 始终 |
| `kernel_info` | `uname` 等 | 始终 |

系统属性查询经编译期排序的 64 位 FNV-1a 常量表 `kAllowedPropertyHashes` 校验（零运行期字符串解码与堆分配）。

### 4.3 合成字段与覆盖语义

聚合器追加且**不计入覆盖率**：`hook_memory_signals`、`runtime_integrity_score_inputs`、`fingerprint_id`。

仅 `Status.ERROR`（含超时）的 Collector 追加 `collector:<fieldName>` 并拉低覆盖率；`UNSUPPORTED` 与 `EMPTY` 独立计入 `RiskReport.getUnsupportedCheckCount()`，绝不把干净真机降级为 `UNKNOWN`。

### 4.4 版本化分层指纹（V1/V2）、硬件绑定与 DirectBoot

`FingerprintIdBuilder` 通过声明式 `FingerprintSignalSpec` 结合 `FingerprintVersion`、`FingerprintStability` 与可插拔 `FingerprintHasher`（默认 UTF-8 SHA-256）计算分层摘要：

- **`FingerprintVersion.V1`**（比特冻结，由 `FingerprintVersionGoldenTest` 锁定）：13 项硬件特征（5 物理桶：`gpu`/`sensor`/`camera`/`cpu`/`memory_battery`）、11 项系统字段、2 项易变字段；复合 ID = `hash(salt|composite|hw|sys)`。
- **`FingerprintVersion.V2`**（默认）：引入 `codec_info`、`input_devices`、`security_posture` provider 摘要及剔除 `BogoMIPS`/`cpu MHz` 的结构化 `CpuInfoParser`。`FingerprintVersion.LATEST` 已标 `@Deprecated`。
- **`FingerprintStability`**：`STABLE`（仅物理硬件桶）、`OPTIMAL`（默认：硬件 + 系统 + 新增零权限维度）、`UNIQUE`（叠加已授权易变标识）。
- **`isHardwareLayerReliable()`**：当且仅当 `!hardwareId.isEmpty() && getHardwareCoveragePercent() >= 50` 且至少命中 `gpu`/`cpu`/`sensor` 中的 2 个核心物理桶时为 `true`。

`FingerprintStore` 将状态存于设备保护（DE）私有 `riskengine_fp` SharedPreferences（`createDeviceProtectedStorageContext()`，仅在 `UserManager.isUserUnlocked() == true` 时执行一次性 CE→DE 迁移）：

- **硬件密钥加密封装**：使用 `AndroidKeyStore` 不可导出 `AES/GCM/NoPadding` 密钥 `riskengine_fp_wrap_key`（优先 StrongBox，自动降级 TEE，随机 12B IV + 128-bit Tag）保护安装盐与锚点载荷。
- **不可变锚点与漂移追踪**：`anchor_hw` / `anchor_hw_buckets`（自动迁移 v1 `last_hw`）在 `HARDWARE_CHANGED` 时绝不被覆盖，仅递增 `drift_count`；宿主可通过 `RiskEngine.resetFingerprintBaseline()` 显式重锚。
- **跨设备克隆/篡改检测**：密文存在但 Keystore 包装密钥缺失或 GCM 验签失败（`AEADBadTagException`）时，在 `fingerprint_continuity` 中产出 `device_binding_broken`（`HIGH`/7 可处置，家族 `device_binding`）。
- **锁屏/生物识别变更哨兵**：捕获 `KeyPermanentlyInvalidatedException` 后设置 `devicePosture.lockscreenOrBiometricReset = true`。
- **宿主备份排除**：宿主须在 `data_extraction_rules.xml`（API 31+）与 `backup_rules.xml`（API 30）中对 `sharedpref` 与 `device_sharedpref` 双域排除 `riskengine_fp.xml`。

## 5. 16 大收敛核心 Detector

`BaseDetector.result(..., CheckCoverage)` 将 `attempted == 0` / `succeeded == 0` 映射为 `UNAVAILABLE`，`failed > 0` 且有成功项映射为 `PARTIAL`，全部成功映射为 `SAFE` / `RISK`。每条结果附带 `ScanTier`、结构化 `List<EvidenceItem>` 与向后兼容的 `details[]`。

### 5.1 `app_integrity`（`CRITICAL`，家族 `app_tamper`）

- **硬编码包名校验**：比对 `Context.getPackageName()` 与 `config.expectedPackageName` → `pkg_name_mismatch`（`DEADLY`/10 硬触发）。
- **APK v2/v3/v3.1 签名谱系 + Native 原始 `base.apk` 交叉验证**：Java `GET_SIGNING_CERTIFICATES` 在 `hasMultipleSigners()` 时校验全部 `apkContentsSigners`，否则校验当前生效证书 + `signingCertificateHistory` 轮换谱系；Native `nVerifyApkSigningCertRaw` 经原始 syscall 直读 `base.apk`（从 `/proc/self/maps` 或 `sourceDir`），解析 ZIP EOCD / APK Signing Block v2/v3/v3.1（回退 v1 JAR）计算证书 SHA-256 并与 Java 交叉核对 → `apk_sig_mismatch` / `apk_native_java_sig_conflict`（`DEADLY`/10 硬触发）、`apk_signing_lineage_mismatch`（`HIGH`/8）。
- **安装来源校验**：API 30+ `getInstallSourceInfo()` 核对 `installingPackageName` / `initiatingPackageName` → `unofficial_installer:<pkg>`（`LOW`/2 提示，同步填充 `devicePosture.unofficialStore = true`）。
- **Release 混淆自检**：非 debuggable 构建检查 `ObfuscationSentinel` 类名是否未混淆 → `release_unobfuscated`（`LOW`/2 提示）；`consumer-rules.pro` 刻意不保留 `ObfuscationSentinel`。

### 5.2 `hook_framework`（`CRITICAL` + `POSTPONED`，家族 `hook_integrity` / `frida` / `xposed`）

- **快速阶段（`CRITICAL`）**：Java Xposed/Frida 探针（35ms 限时 `27042` 端口探测；Android 10+ `/proc/net/tcp` SELinux 拒绝返回 `UNAVAILABLE`，绝不把干净设备从 `SAFE` 降级为 `UNKNOWN`）+ Native `NativePayloadCodec` 探针（maps、`/proc/self/fd` `fd:linjector`/`fd:frida:` [`frida-gadget`/`libgadget`]、双源 `comm`+`status Name:` 线程 [`pool-frida`/`pool-spawner`/`frida-helper`/`gdbus`；`gmain` 仅协作 `IGNORE`]、Unix socket、W+X、`pipe2` 16B 校验 `memfd` 与匿名 `r-xp` ELF、`dl_iterate_phdr` vs `maps` 隐匿库差集 [4KB/16KB 半开区间重叠 + 实时复核]、只读 `sigaction` [`SIGSEGV`/`SIGTRAP`/`SIGILL`]、ART 反射/JNI 槽位、COW 安全 `SelfIntegrityProbe`）+ 周期监控 `late_*` 锁存（`late_frida_fd` 归 `STRONG`）。
- **延后阶段（`POSTPONED`）**：`ZygiskProbe`（`zygisk_atexit_probe.cpp` 解析磁盘 `libc.so` `SHT_SYMTAB` 获取 `_ZL7g_array` 含 LLVM SRA 拆分与 `_ZL13g_atexit_lock`，覆盖 API 30–37，严格非阻塞 `pthread_mutex_trylock` + `PipeMemoryReader` + 前后 maps 交集，检出匿名可执行回调 `STRONG` 与 `>= 3` 运行时锚定空洞 `MEDIUM`）、`LsposedProbe`（`activity`/`serial` Binder 魔数 `0x5F4C5350`、Zygote 授权权限 vs `/proc/self/status` `Groups:` AOSP `platform.xml` GID 审计、受保护 API 异常栈、`Thread.getAllStackTraces()`、`UncaughtExceptionHandler`）以及扩展 Frida D-Bus 端口 `27043–27045`。

评分：strong≥2 或 (strong≥1 且 medium≥2) → `DEADLY`/10；strong≥1 或 medium≥2 → `HIGH`/8；medium≥1 → `MEDIUM`/2/informational；其余弱信号 → `LOW`/1/informational。

### 5.3 `debug`（`CRITICAL`，家族 `debugger`）

Native `OBF` 保护的 `nGetDebugEvidenceRaw()`（走 `NativePayloadCodec`，同时保留 `nativeGetTracerPidRaw()` 兼容）：
- 双路径 `TracerPid`（`/proc/self/status`、`/proc/<pid>/task/<pid>/status`、`/proc/self/task/*/status` 及差异检测：`tracer_pid:`、`tracer_pid_mismatch:`）。
- `/proc/self/task/*/stat` 第 3 字段小写 `'t'`（定位最后一个 `')'` 规避进程名含空格/括号干扰，`stat_tracing_stop:`）。
- `/proc/self/task/*/wchan` `ptrace_stop`（`wchan_ptrace_stop:`）。
- JDWP 线程（`JDWP`/`ADB connection`）与抽象 Socket `@jdwp-control`（`jdwp_thread:`、`jdwp_socket:`）。

评分：活跃追踪/停顿/差异 → `HIGH`/`DANGER`/8；调试器连接 / JDWP / maps 调试路径 → `MEDIUM`/4；仅 `debuggable_flag` 或 IDA 端口 → `LOW`/1/informational（全 4 场景含 `DIAGNOSTIC` 均保持 informational）。

### 5.4 `root` 与 `mount_analysis`（`FAST` + `POSTPONED`，家族 `root_fw`）

- `root`：Java 路径探测 + 缓存 `SignalSnapshot.getNativeRootEvidence()` + `kernel_sidechannel_probe.cpp`（快速阶段 KernelPatch `sys_truncate`、KSU `reboot`/ioctl、SUSFS 路径/挂载探测、Netlink 权限泄漏，以及 Stage 3 `disposable_child` KSU 时序侧信道）+ `selinux_audit_probe.cpp`（enforce 冲突、状态页 ABI/头审计、受控上下文探测与零 PII Netlink 策略重载泄漏）。强 `HIGH`/8、中 `MEDIUM`/4、弱 `LOW`/1/info（`busybox` 绝不单独触发可处置风险）。
- `mount_analysis`：`/proc/mounts` 与 `/proc/self/mountinfo` + `mount_forensics.cpp`（`statx(STATX_MNT_ID)` 对比 `mountinfo`、系统只读分区精确逗号分词 `rw`、零初始化 3 次 `fstatat` `st_mtime`、`statfs` `overlayfs`/`tmpfs`）+ Stage 3 `RiskIsolatedProbeService` 跨进程挂载比对（`MountViewNormalizer` 抑制纯 Mount ID 空洞与 OEM 噪声）。强 `HIGH`/8、中 `MEDIUM`/4 可处置；与阴性 `root` 联动触发 `C9:stealth_root_with_unmount`。

### 5.5 `multi_instance`（`FAST` + `POSTPONED`，家族 `virtual_container`）

零隐藏反射。结合 `InstallTokenSanitizer`（剥离 16–32 字符 Base64 安装 Token 防随机 `ksu`/`Riru` 子串误报）：
- 规范 `filesDir`/`dataDir`/`sourceDir` 路径深度与 `uid / 100000` 区分：主用户 `0` 与 Work Profile `10..89` 判定干净；OEM 双开（`999`/`>=900`/`95`/`128..150`）→ `oem_dual_app:`（`STANDARD` 下 `LOW`/2 info，`LOGIN`/`PAYMENT` 转为可处置）。
- VirtualApp/ParallelSpace/BlackBox 嵌套容器路径、`user_id_path_mismatch:`、`dir_uid_mismatch:`（`st_uid` 与 `Process.myUid()` 矛盾）、`multi_apk_maps:`、`container_maps_artifact:` 与 `binder_dynamic_proxy:`（`ActivityManager`/`PackageManager` 动态 `Proxy$`）→ `MEDIUM`/5 可处置。
- 延后阶段（`POSTPONED`）：消费 `virtualization_traps.cpp` `sacrificial_syscall_pack`（`disposable_child` 对比 libc `syscall()` 与原始内联汇编 `statx`/`memfd_create`/`renameat2` 及 seccomp 隔离的 `openat2`/`pidfd_open`）→ `sacrificial_syscall_mismatch`（`MEDIUM`/5 可处置，`NATIVE`/`STRONG`）。

### 5.6 `network_risk`（`FAST`，家族 `network_mitm`）

零 `<uses-permission>`：
- `AndroidCAStore` `user:` 别名与 `/data/misc/user/<uid>/cacerts-added`（`user_ca_cert:`）→ `MEDIUM`/5 可处置。
- 运行时守卫 `ConnectivityManager` `TRANSPORT_VPN` 并回退 `/sys/class/net`（`tun*`/`ppp*`/`wg*`/`utun*`）（`vpn_active:`，填充 `devicePosture.systemVpn`）、无凭据代理来源标签（`http_proxy:`）、官方代理工具证书 SHA-256（`proxy_tool_cert:`）及只读 `/data/adb/modules/{box4,box_for_root}`（`proxy_module:`）→ `STANDARD` 下 `LOW`/2 info，`PAYMENT` 下 `proxy_tool_cert:`/`proxy_module:` 升为可处置 `MEDIUM`/4。

### 5.7 `location_risk`（`FAST`，家族 `location_spoof`）

零位置权限、零经纬度 PII：
- 本地 `Location` 契约金丝雀（可注入 `LocationCanaryAdapter`，兼容 JVM 默认桩）：测试 getter/setter 往返、`reset()`/field-mask 一致性与 API 31+ `setMock`/`isMock` → `location_canary_tamper:`（全场景 `HIGH`/7 可处置）。
- 宿主已授权限时的缓存 `Location.isMock()`（`cached_location_mock:`）与 `AppOpsManager` `OPSTR_MOCK_LOCATION`（`mock_location_appop_allowed`）→ `STANDARD` 下 `MEDIUM`/4 info，`LOGIN`/`PAYMENT` 转为可处置。

### 5.8 `screen_and_fraud`（`FAST`，家族 `screen_control` / `fraud_context`）

零额外权限：
- `virtual_display:`（虚拟/演示显示）、`third_party_a11y:`（排除系统无障碍服务）、`virtual_input:`（非内置虚拟输入），及由 `AppLifecycleObserver` 写入的截录屏状态（`screen_capture_observed`、`screen_recording_active`）→ `MEDIUM`/4 可处置（`PAYMENT` 下投屏/第三方无障碍升为 `HIGH`/7）。
- `ongoing_call:`（`AudioManager` 通话模式）→ 单独为 `LOW`/1 info；在 `PAYMENT` 下叠加投屏或第三方无障碍触发 `C10:vishing_fraud_combo`（`HIGH`/8）。
- `time_spoofing:`（`currentTimeMillis < Build.TIME`、`AUTO_TIME == 0`、墙钟相对 `elapsedRealtime` 倒退/跳变）→ 全场景 `MEDIUM`/4 可处置。

### 5.9 `adb`、`emulator`、`cloud_phone`、`custom_rom`、`consistency`（`FAST` / `POSTPONED`）

- `adb`：`AdbInspector` 具备 1.5s 条件双采样去抖（干净设备 0 sleep）与 `native_get_adb_protocol_evidence()`（`/dev/socket/adbd` 三态 `fstatat` + 兄弟 `ENOENT` 哨兵 + 非阻塞 `@jdwp-control` + `init.svc.adbd`）。持续隐藏 `adbd` 矛盾在全场景产出 `HIGH`/7 可处置；普通 USB（`LOW`/2）/ Wi-Fi（`MEDIUM`/4）默认提示性，`PAYMENT`/`DIAGNOSTIC` 可处置。
- `emulator`（`FAST` + `POSTPONED`，家族 `emulator`）：现代虚拟化特征库（Waydroid/Cuttlefish/WSA/Corellium/LDPlayer 9/MuMu 12 与 AVF `>= 2` 联合防误报）、Native Bridge（`houdini`/`libnb`/`libndk_translation` `STRONG`）、零 SoC 硬件 `MediaCodec`（`zero_hw_codec`），以及 Stage 3 `sched_yield_low_cv`（仅 `INFO`，绝不单独触发可处置风险）、ARM64 防溢出 `cntvct_el0` 时钟漂移与联合防误报 `SensorNoiseProbe`（`<= 200ms`）。保留 `GpuClassifier` 真机 ANGLE-on-Vulkan 豁免且绝不调用 `eglTerminate(EGL_DEFAULT_DISPLAY)`。
- `cloud_phone`（`FAST` + `POSTPONED`，家族 `emulator`）：强 `HIGH`/7、弱≥2 `MEDIUM`/4、1 弱 `LOW`/1/info；联合校验零 SoC 硬件 `MediaCodec` 与 Stage 3 `SensorNoiseProbe`（`stddev == 0.0` 仅与电池/摄像头/硬件异常联合生效）；原生输出 `EvidenceItem`。
- `custom_rom`（`FAST`，家族 `custom_rom`）：社区 ROM 属性、`custom_rom_probe.cpp`（`libstagefright.so` 符号与 `framework-res.apk` 多块设备映射），内置 Pixel 与 HarmonyOS 防误报豁免；恒为 `LOW`/1/info。
- `consistency`（`FAST` + `POSTPONED`，家族 `prop_tamper`/`boot_integrity`/`hw_spoof`）：始终注册；集成 `BootloaderProbe`（VBMeta 空摘要伪造陷阱 `vbmeta_empty_input_digest` 硬触发 + `ro.boot.flash.locked`/`ro.boot.verifiedbootstate`/`ro.boot.vbmeta.device_state` 交叉比对）、`bionic_prop_forensics.cpp`（`prop_area` trie 空洞/serial/尾字节残留 + PlayIntegrityFix 侧信道）、`hardware_consistency_probe.cpp`（`disposable_child` 读 ARM64 `MIDR_EL1`、3 源内核一致性）与 `WidevineParityProbe`（`widevine_ndk_probe.cpp` `AMediaDrm` 与 Java `MediaDrm` L1/L3 安全级别及 `systemId` 一致性、`widevine_l3_with_strongbox_locked`/`widevine_java_ndk_mismatch`）；强篡改 `HIGH`/8；确认 Bootloader 解锁/橙色启动 `MEDIUM`/4/info（`STANDARD`）→ 可处置 `MEDIUM`（`LOGIN`）→ `HIGH`/7（`PAYMENT`）。

### 5.10 `tee_integrity`（`POSTPONED`，家族 `tee_tamper`）

默认开启（`enableTeeAttestation=true`），零第三方密码库实现 ASN.1/DER X.509 硬件证明与 Keystore2 / Binder / VINTF 对抗审计：

- **ASN.1/DER 证明解析与根证书/CRL 核验**：`KeyAttestationCollector`（StrongBox/TEE EC P-256 证明链 + `AttestationCapability` + `RkpCapabilityProbe`）、`Asn1DerParser`（严格最小 DER、64 KiB 上限、最大深度 16）、`KeyAttestationParser`（OID `1.3.6.1.4.1.11129.2.1.17` 兼容 Keymaster v3/v4 与 KeyMint 100/200/300/400 Schema、`RootOfTrust`、`AttestationApplicationId`）、`GoogleAttestationRootStore`（内置 Google Hardware Root RSA-4096/ECDSA-P384 与 RKP ECDSA-P384 根锚点 + 单调 CRL 下界 + 离线吊销序列号核查）。
- **TrickyStore / TEE Hook 深度对抗**：
  - `GrantDomainSplitProbe`（借 `RiskIsolatedProbeService` 执行 Keystore2 `Domain.GRANT` 跨 UID 证书链比对 → `tee_grant_chain_split`，`DEADLY`/10 硬触发）。
  - `TeeNativeProbe`（`tee_binder_probe.cpp` 审计 `/dev/binder` `ioctl` trampoline 及 `libbinder`/`libkeystore2` hook → `tee_binder_ioctl_hook`，`DEADLY`/10 硬触发）。
  - `Keystore2DeepProbe` 与 `VintfHalAndErrorPathProbe`（OID `2.1.17` 双重注入、`osPatchLevel` vs `ro.build.version.security_patch` 矛盾、Keystore2 错误路径与 VINTF HAL 清单检查）。
  - 已吊销 keybox（`tee_keybox_revoked`）→ `DEADLY`/10 硬触发；非信任根/链签名无效/RoT 异常 → `HIGH`/8；纯软 Keystore 回退或 OEM 合法差异温和分级，确保干净国行/海外真机零误报。

### 5.11 `threat_apps`（`POSTPONED`，家族 `root_fw` / `hma_hiding` / `threat_app`）

第 16 个也是最终收敛的顶层检测域，默认开启（`enableThreatAppDetection=true`），支持通过不可变 `ThreatAppPolicy.Builder` 自定义高危包名（`additionalThreatPackages`）、自定义证书 SHA-256、高危权限组合与 HMA 探针开关：

- **`ThreatAppPackageProbe` 与 `ThreatAppSignatureLibrary`**：仅探测精选 `<queries>` 目标（与 `artifact_paths.ini` `[threat_app_packages]` 1:1 同步，零 `<uses-permission>`），校验完整 v2/v3/v3.1 证书轮换谱系（`apkContentsSigners` + `signingCertificateHistory`，内置 10+ 官方发布 SHA-256：KernelSU、KSU-Next、SukiSU、Magisk、APatch、HideMyApplist、HMA-OSS、LSPosed、GameGuardian、LuckyPatcher、Shizuku）、`Os.stat` 检查 `nativeLibraryDir` 原生守护载荷（`libksud.so`/`libapd.so`/`libmagisk.so`），并通过公开 Manifest XML 解析读取 `android:zygotePreloadName`（零受限隐藏 API 反射）。Root 管理器命中自动归入 `root_fw` 家族，与 `root`/`mount_analysis` 去重不叠分。
- **全代际 HMA 与 Thanox 行为侧信道（`hma_hiding` 家族，全场景 `HIGH`/7 可处置）**：
  - `HmaUidVisibilityProbe`（`hma_uid_probe.cpp` 严格运行于 `disposable_child`）：`__NR_getpriority(PRIO_USER, uid)` 活跃应用 UID 扫描对比未缓存 `getPackagesForUid`（宿主具备 `QUERY_ALL_PACKAGES` + 前后自检对照 + TOCTOU 二次复核），并始终执行零权限 Linux >= 5.0 `SECCOMP_FILTER_FLAG_NEW_LISTENER` 拦截检测。
  - `HmaCrossUserProbe`：跨用户 `MATCH_ANY_USER` 异常抑制探测（返回 `NameNotFoundException`/`null` 而非标准 `SecurityException`，配对前后自检对照）。
  - `HmaOrderedBroadcastProbe`：在后台 `HandlerThread` 通过初始及交错前后宿主自检对照，识别 HMA-OSS #164（`resultTo` 丢失）与 #173（`isOrderedBroadcast()==true` 泄漏）。
  - `HmaPermissionServiceProbe`：严格门控 API >= 35 + 宿主 `QUERY_ALL_PACKAGES` + 1000ms 硬预算（截断即标注 `PARTIAL`），使用公开 `Context.checkPermission` 与类型化 `IBinder.transact` + `Parcel` 线协议助手（遵循 `D66` 零受限反射）。
  - `ThanoxIpcProbe`：查询 `dropbox` Binder 并严格要求 `interfaceDescriptor == "github.tornaco.android.thanos.core.IThanos"`（对 OriginOS / 原生 Android 零误报）。
- 签名高危工具 / Root 管理器 / 自定义策略命中全场景 `MEDIUM`/5 可处置。

### 5.12 聚合追加的合成检测项

| 名称 | 来源 |
| --- | --- |
| `signal_correlation` | `CorrelationEngine.correlate`（`C1`–`C10`），见第 8 节 |
| `multi_source_validation` | 指纹多来源不一致 |
| `fingerprint_continuity` | 不可变锚点硬件漂移（`HARDWARE_CHANGED`，`MEDIUM`/4）及/或 Keystore `device_binding_broken`（`HIGH`/7） |
| `collector:<field>` | `ERROR`/超时的 Collector 覆盖占位（不含 `UNSUPPORTED`/`EMPTY`） |

## 6. Native 层

共享库 `libriskengine.so`，CMake 3.22.1，C++17，`-fno-exceptions -fno-rtti`，静态 libc++，符号隐藏（`exports.map` 仅导出 `JNI_OnLoad` 与 `JNI_OnUnload`）。

- **内联 syscall 与流式解析**：按 ABI 直接内联 syscall（`raw_syscall.h`、`syscall_wrapper.cpp` 带 `-EINTR` 重试、32 位 `__NR_statfs64`、3 参 `__NR_faccessat` / 4 参 `__NR_faccessat2`），`getdents64`（`raw_dir.cpp`），流式 `maps_parser.cpp`（无 2 MiB 截断）。
- **COW 安全读内存、`disposable_child` 与线协议**：`util/safe_mem_read.{h,cpp}`（`pipe2(O_CLOEXEC|O_NONBLOCK)` 4 KiB 内核 `copy_from_user` + `PagemapReader`）；`util/disposable_child.{h,cpp}`（`fork()` 前预解析原始 Bionic `sigaction`/`sigprocmask`、原始 `__NR_exit_group`、并发=1 互斥与双截断超时，安全隔离 `SIGSYS`/`SIGILL` 与内核侧信道）；`util/payload_codec.{h,cpp}` ↔ `NativePayloadCodec`。
- **多态 OBF 与编译期白名单**：`util/obf_str.h`（`ScopedObfString<N>` + `secure_zero`）；编译期 FNV-1a 哈希表 `kAllowedPropertyHashes`。
- **Phase 2–4 Native 深度取证模块**：`bionic_prop_forensics.cpp`、`hardware_consistency_probe.cpp`、`custom_rom_probe.cpp`、`kernel_sidechannel_probe.cpp`、`selinux_audit_probe.cpp`、`mount_forensics.cpp`、`zygisk_atexit_probe.cpp`、`virtualization_traps.cpp`、`widevine_ndk_probe.cpp`（`dlopen` 加载 `AMediaDrm` 一致性探测）、`tee_binder_probe.cpp`（Binder `ioctl` 与 `libkeystore2`/`libbinder` hook 审计）、`hma_uid_probe.cpp`（`disposable_child` 内 `getpriority(PRIO_USER)` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`），以及升级后的 `native_debug_detector.cpp`（ADB 协议取证）与 `native_hook_detector.cpp`（FD/线程/匿名 ELF/链接器差集/sigaction）。所有原生代码均内聚于核心 `libriskengine.so`。
- **APK 签名解析（`apk_sig_verifier.cpp`）**：原始 syscall 解析 ZIP EOCD 与 APK Signing Block v2/v3/v3.1 证书 SHA-256（回退 v1 JAR），由 `nVerifyApkSigningCertRaw` 暴露。
- **COW 安全自完整性（`native_integrity.cpp`）**：64 KiB 分窗 SHA-256（`dl_iterate_phdr` + `SHF_EXECINSTR`/`PT_LOAD`，支持 `extractNativeLibs=false` 与 16KB 页）、4 ABI trampoline（含 ARM32 Thumb-2 与 `branch_stays_in_image`）、XOR 掩码 JNI 表与核心序言基线、PLT + RELA/REL `STT_FUNC` GOT 与 `JNIEnv` 校验。
- **事件驱动周期监控（`periodic_monitor.cpp`）**：由 `RiskEngine.init()` 在 `enablePeriodicMonitor(true)` 时异步启动（**不再**在 `JNI_OnLoad` 中启动）。调度策略：2–4s 首轮复检、前台 20–26s 抖动轮询、后台 120s 退避、后台切前台超 10s 立即复检。复检项含双路径 `TracerPid`、W+X、`memfd`、`/proc/self/fd`（`late_frida_fd`）及 COW 安全 `.text`/序言（`late_text_mismatch`），新命中通过无锁 JNI 回调推送至 `JNI_OnLoad` 预缓存的 `NativeMonitorDispatcher.onNativeThreatDetected`（`NewGlobalRef`）。零依赖 `AppLifecycleObserver` 驱动前后台切换与权限守卫的 API 34/35 截录屏回调。
- **构建加固与 ELF 门禁**：`IS_RELEASE_LIKE`（`Release` 与 `RelWithDebInfo`）启用 `-Os`、`-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`、ThinLTO、`--gc-sections`、`--icf=safe`、`--wrap=__cxa_demangle`、`--strip-all`、`llvm-strip -R .comment`、`max-page-size=16384`。`scripts/check-elf-hardening.sh` 校验 4 ABI 全部满足 2 导出符号、已 strip、无 `.comment`、16KB `LOAD` 对齐、单 ABI `.so <= 2000 KiB`、AAR `<= 8 MiB`。

## 7. 共享信号（`SignalSnapshot`）

每份报告拥有独立缓存，覆盖 ADB 状态、系统属性、Java `/proc/self/maps`、本机监听端口、进程快照、文本文件、路径存在性、容器信号、SELinux、`build.prop` fingerprint、`/proc/cmdline` 启动属性、CPU/磁盘/内核、缓存 Native Root 证据、GPU 完整属性与网络接口名。

## 8. 场景、`RiskPolicy`、0–100 四维评分引擎与交叉规则

`DataAggregator.aggregate` 顺序：`CorrelationEngine.applyPolicy(detections, effectivePolicy)`（应用 `CollectScene` 场景规则及 `ALLOWLIST` / `INFORMATIONAL_ONLY` 家族覆盖）→ `CorrelationEngine.dedupeFamilies`（针对全部 21 个证据家族执行顺序无关的 family-max 胜者选取，同家族非胜出项以 `deduped:corroborating_evidence` 保留完整可见性）→ `CorrelationEngine.filterForCorrelation` 与 `correlate`（`C1`–`C10` 交叉规则，并经策略二次过滤）→ Collector `ERROR` 覆盖与多来源不一致 → 指纹 v1/v2 与 `FingerprintStore` 连续性/设备绑定 → `mergeMultiSourceEvidence` → 合成字段与 `DevicePosture` 闭环 → 调用 `RiskScoringEngine.evaluate(...)` 冻结 `RiskReport`（`TierReport` 通过 `RiskScoringEngine.evaluateTier(...)` 共用同一套引擎）并计算 `TrustTier`（硬件证明通过且 Verified Boot 锁定、运行时干净时升档为 `STRONG_HARDWARE`）。

### 8.1 标准化 0–100 四维评分引擎（`RiskScoringEngine`，ADR-0002）

- **四大正交 `RiskDimension`（`EvidenceFamily.dimensionOf` 确定性映射 21 个证据家族）**：
  - `TAMPERING`（6）：`app_tamper`、`hook_integrity`、`frida`、`xposed`、`debugger`、`tee_tamper`
  - `PRIVILEGE`（8）：`root_fw`、`boot_integrity`、`prop_tamper`、`hw_spoof`、`hma_hiding`、`device_binding`、`custom_rom`、`adb`
  - `ENVIRONMENT`（3）：`emulator`、`virtual_container`、`threat_app`
  - `FRAUD_CONTEXT`（4）：`network_mitm`、`location_spoof`、`screen_control`、`fraud_context`
- **阶段 1 — 顺序无关家族取最大值（Family-Max）**：检测器内部 `0..10` 强度单调平滑映射至概率区间（`0->0.00, 1->0.10, 2->0.18, 3->0.26, 4->0.38, 5->0.46, 6->0.54, 7->0.64, 8->0.72, 9->0.78, 10->0.92`）。每个证据家族取可处置单源最大值，彻底消除注册顺序依赖；`RiskPolicy` 自定义家族倍率通过加权 Noisy-OR（`1 - (1 - p)^m`）生效。
- **阶段 2 — 多源印证加权（Corroboration Lift）**：当同一可处置家族在 `>= 2` 个独立 `EvidenceItem.SourceLayer`（`JAVA`/`NATIVE`/`ISOLATED`/`HARDWARE`）或 `>= 2` 个不同 Detection Domain 均获得印证时，给予 `+0.06` 加权（上限封顶 `0.95`）并记录 `ScoreBreakdown.Category.CORROBORATION_LIFT`。
- **阶段 3 — 维度内 Noisy-OR、纯弱信号封顶与 Hard Trigger 保底**：
  - 各 `RiskDimension` 内多家族经 Noisy-OR（`1 - product(1 - p_i)`）融合至 `0–100`；若该维度内无 `MEDIUM` 及以上检出（纯 `LOW`），维度得分封顶于 `PURE_LOW_DIMENSION_CAP = 35`。
  - 四大加权维度（`1 - (1 - d)^w`）与活跃交叉规则 `C1`–`C10` 概率（`C1: 0.38`、`C2: 0.45`、`C3/C6/C8: 0.90`、`C4: 0.60`、`C5: 0.00`、`C7: 0.18`、`C9/C10: 0.64`）经 Noisy-OR 融合成 `preFloorScore`（`0–100`）。
  - 权威 Hard Trigger 由 `RiskScoringEngine.extractHardTriggers(...)` 单源提取（与 `SignedEnvelopeSigner` 1:1 共享）。除非被 `RiskPolicy` 抑制，任意有效 Hard Trigger 锁定 `overallRiskLevel = DEADLY`、`recommendedAction = BLOCK`，并将 `riskScore` 保底至 `min(100, 95 + 2 * (count - 1))`，同时写入 `ScoreBreakdown.Category.HARD_TRIGGER_FLOOR`。
- **阶段 4 — 分层评估置信度、`RiskLevel` 与 `RiskAction`**：
  - `confidencePercent`（`0–100`）按执行层级加权计算完成度（`CRITICAL = 3`、`FAST = 2`、`POSTPONED = 1`、Collector = `1`，排除 `UNSUPPORTED`/`EMPTY`）。
  - 默认分档：`0 SAFE`、`1–29 LOW`（纯提示性信号保持 `0` 分与 `ALLOW`）、`30–59 MEDIUM`（`CHALLENGE`）、`60–84 HIGH`（`RESTRICT`，`PAYMENT` 场景默认 `BLOCK`）、`85–100 DEADLY`（`BLOCK`）。
  - 零分报告**仅**在至少 1 个 `CRITICAL` 检测域失败/超时/不可用、加权 `confidencePercent < 70` 或全部检测器不可用时转为 `UNKNOWN`（推荐 `RiskAction.REVIEW`）；单个非关键域超时保持 `SAFE` 并诚实输出 `ReportStatus.PARTIAL` 与下降后的 `confidencePercent`。
- **不可变本地策略 `RiskPolicy`**：通过 `RiskPolicy.forScene(CollectScene)` 或 `RiskPolicy.builder(CollectScene)` 配置 `dimensionWeight`、`actionThresholds`（`1 <= challenge < restrict < block <= 100`）、`highAction`、家族模式 `FamilyMode`（`DEFAULT` / `ALLOWLIST` / `INFORMATIONAL_ONLY`）、`familyMultiplier` 与 `suppressHardTrigger`。当配置了自定义策略且单次调用 `RiskEngine.collect(sceneOverride, ...)` 时，通过 `withBaseScene(...)` 自动切换基础场景。

### 8.2 交叉规则（`C1`–`C10`）

| ID | 条件 | 内部强度 / 维度 |
| --- | --- | --- |
| C1 | 模拟器 ≤ `LOW`、`strong == 0`、有效弱信号（排除硬件噪声）≥ 3 | `MEDIUM` / `WARNING` / 4（`ENVIRONMENT`，`p=0.38`） |
| C2 | 恰好 1 个 STRONG + hypervisor/QEMU，且模拟器已是 `MEDIUM` | 升至 `HIGH` / `DANGER` / 4（`ENVIRONMENT`，`p=0.45`） |
| C3 | inline/GOT hook **且** Frida 族 | `DEADLY` / `DANGER` / 10，Hard Trigger（`TAMPERING`，`p=0.90`，保底 `95–100`） |
| C4 | `syscall_mismatch` **且** 模块/Magisk 挂载 | `HIGH` / `DANGER` / 8（`PRIVILEGE`，`p=0.60`） |
| C5 | `prop_mismatch:fingerprint`、无 `community_rom:`、模拟器 NORMAL | `LOW` / `WARNING` / 1 / informational（`PRIVILEGE`，`p=0.00`） |
| C6 | `C6:bridge_or_integrity_tamper`：Native 自完整性篡改且 Java 探针全绿，或 `UnsatisfiedLinkError` 伴随隐藏对抗信号 | `DEADLY` / `DANGER` / 10，Hard Trigger（`TAMPERING`，`p=0.90`，保底 `95–100`） |
| C7 | `LOGIN`/`PAYMENT` 下云真机 `cloudStrong == 0` 且仅弱云信号 ≥ 2 | `LOW` / `WARNING` / 2（`ENVIRONMENT`，`p=0.18`） |
| C8 | `C8:spoofed_verified_boot`：TEE `RootOfTrust` 报告 `deviceLocked=false` 或非 `VERIFIED` 启动状态，但 `ro.boot.*` 系统属性宣称已锁定/`green`（或 `vbmeta_empty_input_digest` 与硬件态矛盾） | `DEADLY` / `DANGER` / 10，Hard Trigger（家族 `boot_integrity`，`PRIVILEGE`，`p=0.90`，保底 `95–100`） |
| C9 | `C9:stealth_root_with_unmount`：隔离进程跨进程挂载差异或 Bionic `prop_area` 空洞/serial 篡改，且可运行的常规 `root` 路径检查全阴性 | `HIGH` / `DANGER` / 8（家族 `root_fw`，`PRIVILEGE`，`p=0.64`） |
| C10 | `C10:vishing_fraud_combo`（仅 `PAYMENT`）：`ongoing_call` **且** 屏幕共享/虚拟显示或第三方无障碍服务活跃 | `HIGH` / `DANGER` / 8（家族 `fraud_context`，`FRAUD_CONTEXT`，`p=0.64`） |

## 9. JSON v2（严格增量契约）与硬件签名信封（`v=2`）

`RiskReportJsonSerializer` 零额外依赖生成增量 JSON v2，保持向后兼容：

- **Root**：`schemaVersion`（固定 `2`）、`riskScore`（`0–100`）、`maxRiskScore`（`100`）、`displayThresholdMaximum`（`100`）、`confidencePercent`（`0–100`）、`recommendedAction`（`ALLOW`/`CHALLENGE`/`RESTRICT`/`BLOCK`/`REVIEW`）、`hardTriggers[]`、`dimensionScores`（`{TAMPERING, PRIVILEGE, ENVIRONMENT, FRAUD_CONTEXT}`）、`scoreBreakdown[]`（`{category, key, dimension?, points, source}`）、`unsupportedCheckCount`、`trustTier`、`devicePosture`（`hasPasscode`、`storageEncrypted`、`storageEncryptionStatus`、`keystoreLevel`、`biometricStatus`、`devMode`、`adbEnabled`、`systemVpn`、`unofficialStore`、`lockscreenOrBiometricReset`）、`fingerprintId`（`version`、`stability`、`anchorDriftCount`、`compositeId`、`hardwareId`、`systemId`、`volatileId`、覆盖统计、`contributingFields[]`、`hardwareBucketDigests{}`）。
- **`detections[]`**：`scanTier`、`evidenceFamilies[]`、`evidenceItems[]`（`{code, primarySource, mergedSources[], location, value, family?, rank}`）。
- **可选 `signedEnvelope`**（`SignedRiskEnvelope.PROTOCOL_VERSION = 2`，17 字段规范载荷）：`{payload, signatureBase64, certChainPem[], attestationMode, keySecurityLevel}`，其中 `payload` 为递归按键排序的 UTF-8 规范 JSON（`v=2`、`pkg`、`sdk`、`scene`、`ts`、`monoMs`、`challenge`、`riskLevel`、`score`、`action`、`confidence`、`dimensions`、`hardTriggers`、`coverage`、`fpComposite`、`fpHardware`、`reportSha256`），由 ECDSA P-256（`SHA256withECDSA`）签名。服务端可通过 `scripts/verify_risk_envelope.py`（默认 `reject_score_threshold = 60`、`min_confidence = 70`、`min_coverage = 80`）与 [Signed_Envelope_Verification.md](./Signed_Envelope_Verification.md) 离线 6 步验签。

## 10. ProGuard / R8

- SDK AAR `isMinifyEnabled = false`。
- `consumer-rules.pro` 保留：`RiskEngine`、`RiskEngineConfig`（含 `Builder`）、`ThreatAppPolicy`（含 `$*`）、`RiskPolicy`（含 `$*`）、`RiskEngineCallback`、`PrivacyProfile`、`CollectScene`、`ScanTier`、`EnvelopeMode`、`FingerprintVersion`、`FingerprintStability`、`FingerprintHasher`、`ThreatListener`、`DeviceStateListener`、`ExecutionStateListener`、`RiskWindowGuard`、`model.**`（含 `RiskDimension`、`RiskAction`、`ScoreBreakdown` + `$*`、`EvidenceItem` + `$*`、`DevicePosture` + `$*`、`ThreatEvent`、`TierReport`、`SignedRiskEnvelope` + `$*`）、`AttestationRecord$SecurityLevel`、`RiskIsolatedProbeService`、`IsolatedProbeClient`、`NativeCollectorBridge`、`NativeMonitorDispatcher.onNativeThreatDetected` 及全部 `native` 方法。
- `com.wsttxm.riskenginesdk.detector.ObfuscationSentinel` **刻意不保留**，以便 `AppIntegrityDetector` 在 Release 构建中验证 R8 混淆已开启。

## 11. 名单单源、可执行工程治理门禁与 L1–L3 测试基线

- 单源清单：`riskengine-sdk/src/main/resources/lists/artifact_paths.ini` -> `:riskengine-sdk:generateDetectionLists` -> `DetectionLists.java`（混淆零明文）与 `detection_lists.h`（含 `kAllowedPropertyHashes`），并与 `AndroidManifest.xml` `<queries>`（52 项）精确 1:1 同步。
- **6 大 CI 静态治理门禁**（集成于 `scripts/ci-verify.sh` 与 `.github/workflows/ci.yml`）：
  1. `scripts/check-evidence-records.py`：`DetectorRegistry` ↔ `docs/evidence/*.md` 1:1 校验（16/16 检测域，每份均含 7 项必填契约章节）。
  2. `scripts/check-elf-hardening.sh` + `scripts/check-jni-and-dex.py`：4-ABI ELF 加固（仅 2 个 JNI 导出符号、16KB 对齐、strip 无 `.comment`、`.so <= 2000 KiB`、AAR `<= 8 MiB`）、41/41 JNI 1:1 对齐及 Release R8 Dex `< 2,500` 方法数上限。
  3. `scripts/check-single-source-sync.py`：零 `<uses-permission>`、精确 `<queries>` 1:1、xorshift32 字节级反解码 `DetectionLists.java` 与文档版本一致。
  4. `scripts/check-public-api.py`（`:riskengine-sdk:apiCheck` / `apiDump`）：零插件 JDK 17 `javap` Public ABI 锁（`riskengine-sdk/api/riskengine-sdk.api`）、AAR `classes.jar` 纯度与零依赖 POM 校验。
  5. `scripts/check-boundary-guards.py`：核心 Java/C++ 反射白名单与降级策略审计（封禁 D66 受限隐藏 API 反射）及禁止按 UI 展示文案分支判定。
  6. `.github/workflows/refresh-attestation-roots.yml`（`scripts/refresh_google_attestation_roots.py`）：每周定时 + 手动核验 Google Hardware Attestation Root 与单调 CRL 底线漂移。
- **L1 纯 JVM 单元测试**：核心 `:riskengine-sdk` 完整覆盖全部 16 个收敛检测域（含 fast + postponed、`ThreatAppDetector`、`HmaUidVisibilityProbe`、`HmaBehaviorProbesTest`、`tee_integrity`、`SignedRiskEnvelope` `v=2`）、`0–100` 四维 `RiskScoringEngine` 与本地 `RiskPolicy` 策略引擎、全部 24 个 Collector（`CrashFreedomMockTest`）、跨语言黄金向量（`EnvelopeOfflineVerifierTest` 驱动 `scripts/verify_risk_envelope.py`）、V1/V2 黄金向量、硬件 GCM 绑定与 DirectBoot 迁移、三阶段推拉编排、`NativePayloadCodec`、`EvidenceItem` 合并与增量 JSON v2。`:demo` 同步运行 JVM 单元测试（`ReportFormatterScoringTest`）校验 `0–100` 格式化、四维展示、`RiskAction`、`ScoreBreakdown` 与 16 域标题。
- **L2 离线 C++ 宿主机单元测试**：`riskengine-sdk/src/test/cpp/`（`./scripts/run-cpp-tests.sh`，基于 CMake + CTest 与离线 `mini_gtest.h`/可选系统 GTest）实测生产 `maps_parser`（>4 MiB）、`raw_dir` 畸形 fuzz、`DiskElf` 16KB/PT_LOAD、`bionic_prop_area`、`payload_codec`、4-ABI `looks_like_trampoline` 与 `crypto_mini`。
- **L3 二进制 AAR 仪器测试**：`:integration-test` 严格消费独立 `riskengine-sdk-release.aar`，在 GitHub Actions Linux KVM API 30 / 34 / 36 模拟器矩阵运行 `SmokeActivity` 与 `RiskEngineInstrumentationTest`。
