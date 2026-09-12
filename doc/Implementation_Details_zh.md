# RiskEngine 实现说明

本文档是当前源码中的契约，而不是设计意向。宿主集成以 [README_zh.md](../README_zh.md) 为准。典型环境下的预期证据族见 [Adversarial_Matrix.md](./Adversarial_Matrix.md)。

本文已按提交 `15c55ef` 的实际实现同步；实现与设计意图存在差异之处在相关章节说明。

## 1. 定位与模块

RiskEngine 是本地 Android 风险信号 SDK：Java 负责编排、隐私、场景评分、分层指纹与最终报告；C++17 JNI 负责抗 libc hook 的 I/O、环境探测、ART/代码完整性、独立密封裁决与周期复检。没有服务端、没有上报、不依赖 Play Integrity。

仓库模块：

| 模块 | 作用 |
| --- | --- |
| `riskengine-sdk` | 可发布 AAR。Java 11 字节码，minSdk 30，compileSdk 36。AAR 自身不 minify |
| `demo` | 本地诊断控制台。Debug 临时签名；Release 混淆但未签正式证书 |
| `integration-test` | 只依赖生成的 Release AAR，验证独立宿主能编译并链接公开 API |

当前开发版本：`1.1.0-SNAPSHOT`（`gradle.properties` 的 `riskEngineVersion`）。Tag 发布工作流会覆盖 `releaseVersionName`。

## 2. 架构与采集流程

```text
宿主调用
  -> RiskEngine 生命周期快照（generation、config、registries、lock）
  -> coordinator 单线程串行请求（队列上限 16）
  -> collectionLock（总时限包含排队等待）
  -> SignalSnapshot.reset()
  -> worker 池（4 线程）并行 Collector
  -> worker 池并行 Detector
  -> DataAggregator
       dedupeFamilies -> applyScene -> correlate
       collector 覆盖信号 / 多来源不一致 / 合成字段
       FingerprintIdBuilder + FingerprintStore -> 分层 ID / 连续性
  -> 不可变 RiskReport
```

要点：

- `TaskScheduler` 把 coordinator 与 worker 分开，避免等待批任务的线程占满执行该批任务的池。
- 异步请求在队列满或 SDK 关闭时调用 `onError`（`RejectedExecutionException` 包装为 `IllegalStateException`）。
- `collectTimeout` 从请求入队开始计算。未在期限内返回的任务由 `addMissingCollectorResults` / `addMissingDetectionResults` 补成明确的超时/错误覆盖项。
- 同步采集禁止 Android 主线程。异步回调不自动切到主线程。
- `shutdown()` 增加生命周期代次、取消任务并清空注册表。旧代次结果不会交付；进行中的 `doCollectSync` 会在锁边界检查 generation。

并发请求被 `collectionLock` 公平串行化。第二次请求若在期限内拿不到锁，返回超时报告而不是并行再跑一遍。

## 3. 生命周期 API

| API | 行为 |
| --- | --- |
| `init(context, config)` | 严格初始化；重复调用抛 `IllegalStateException` |
| `initIfNeeded(context, config)` | 原子按需初始化；已初始化时返回 `false` |
| `collect(callback)` | 使用配置中的默认 `CollectScene` 异步采集 |
| `collect(scene, callback)` | 覆盖本次场景 |
| `collectSync()` / `collectSync(scene)` | 同步完整采集；主线程抛异常 |
| `collectReportJson()` | `collectSync()` 后序列化 |
| `reportToJson(report)` | 只序列化，不采集 |
| `getReportJson()` | 已弃用，等价于 `collectReportJson()` |
| `shutdown()` | 取消任务、释放资源并请求停止 Native 周期监控；不清除指纹存储 |

配置默认值：所有检测器组开启、`debugLog=false`、超时 10_000 ms、`PrivacyProfile.BALANCED`、`CollectScene.STANDARD`。`native_tamper`、`consistency`、`sealed_verdict` 不受检测器组开关控制，始终注册。关闭 Root/Hook 等组也不会关闭 `sealed_verdict` 内部同类探测。

## 4. Collector

`CollectorResult.Status`：`SUCCESS`、`EMPTY`、`ERROR`、`UNSUPPORTED`。

`compareSources=true` 仅用于「同一语义值的多个来源」。来源不一致时 `DeviceFingerprint` 记录字段名，聚合器生成 `multi_source_validation`（`MEDIUM` / `WARNING` / 分数 4 / 可处置）。

### 4.1 Java 层

| `fieldName` | 类 | 内容 | 隐私约束 |
| --- | --- | --- | --- |
| `android_id` | `AndroidIdCollector` | 应用范围 SHA-256（包名加盐） | `BALANCED`/`DIAGNOSTIC`，可被 `collectAndroidId` 覆盖 |
| `build_props` | `BuildPropsCollector` | `Build.*` 非敏感属性 | 始终 |
| `screen_info` | `ScreenInfoCollector` | 宽高、dpi、密度 | 始终；与 `SignalSnapshot` 共享 |
| `apk_signature` | `ApkSignatureCollector` | 签名证书哈希 | 始终 |
| `bluetooth_info` | `BluetoothCapabilityCollector` | 能力，不含 MAC | 始终 |
| `wifi_info` | `WifiInfoCollector` | 能力（如 Wi-Fi Direct），不含 SSID/BSSID/MAC | 始终 |
| `telephony` | `TelephonyCollector` | 电话类型、SIM 状态等能力，不含 IMEI/IMSI | 始终 |
| `settings` | `SettingsCollector` | 开发者选项等 | 始终 |
| `adb_state` | `AdbStateCollector` | USB/Wi-Fi ADB | 始终；与 Detector 共享 `AdbInspector` |
| `container_signals` | `ContainerSignalCollector` | cgroup / 容器路径 | 始终 |
| `gpu_info` | `GpuInfoCollector` | 离屏 EGL pbuffer：vendor/renderer、GL/EGL 版本、排序后的扩展哈希、纹理/renderbuffer/顶点属性限制 | 始终 |
| `sensor_fingerprint` | `SensorFingerprintCollector` | 排序传感器元组与厂商集合哈希、数量与能力 | 始终 |
| `cpu_topology` | `CpuTopologyCollector` | Runtime/sysfs/procfs 核数、implementer/part 分布、逐核频率范围、ABI、SoC | 始终；SoC 字段要求 API 31+ |
| `hardware_profile` | `HardwareProfileCollector` | 内存分桶、显示模式/HDR、摄像头规格与哈希、电池信息、系统共享库集合哈希 | 始终 |
| `partition_fingerprints` | `PartitionFingerprintCollector` | 分区指纹、构建日期、verified boot/vbmeta 等属性 | 始终；Native 属性白名单 |

### 4.2 Native 层（JNI bridge）

| `fieldName` | 内容 | 隐私约束 |
| --- | --- | --- |
| `drm_id` | Widevine 应用范围哈希 | 仅 `DIAGNOSTIC` 或 `collectDrmId(true)` |
| `boot_id` | `/proc/sys/kernel/random/boot_id` 应用范围哈希 | 仅 `DIAGNOSTIC` 或 `collectBootId(true)` |
| `system_properties_native` | 白名单属性，见 ini `[properties]` | 始终 |
| `cpu_info` | `/proc/cpuinfo` 摘要 | 始终 |
| `disk_size` | 数据分区大小 | 始终 |
| `kernel_info` | `uname` 等 | 始终 |

系统属性查询经过 `DetectionLists.ALLOWED_PROPERTIES` 白名单；不在名单中的 key 返回空串。

### 4.3 合成字段

聚合器在指纹中追加，**不计入覆盖率**：

- `hook_memory_signals`：来自 `hook_framework` 的 `anon_exec:` / `maps:` / `frida_pid_port:` 摘要
- `runtime_integrity_score_inputs`：各检测器状态与可处置分数汇总

失败的 Collector 会在 `detections` 中追加 `collector:<fieldName>` 的 `UNAVAILABLE` 项，供覆盖统计，Demo 不把它当作独立风险行展示。

### 4.4 分层 ID 与连续性

`FingerprintIdBuilder` 只取 `SUCCESS` Collector 中非空的指定字段，排序 `field.key=value` 后以 `SHA-256(salt + "|" + layer + "|" + joined)` 计算摘要，字段间以 U+001F 分隔。无输入的层返回空串。

| 层 | 候选输入 | 说明 |
| --- | --- | --- |
| hardware（`hw`） | 17 项 | GPU、传感器、摄像头、内存、显示、电池、CPU/SoC、可选 Widevine、屏幕 xdpi/ydpi |
| system（`sys`） | 11 项 | 分区指纹、构建日期/vbmeta、Build 指纹/补丁/bootloader、内核、共享库哈希 |
| volatile（`vol`） | 2 项 | 已启用的 Android ID 与 Boot ID 哈希 |
| composite | hardware + system | `SHA-256(salt + "\|composite\|" + hardwareId + "\|" + systemId)`；不包含 volatile，即使两层为空也可能非空 |

`FingerprintId` 公开各层 getter、硬件/系统字段数量、硬件参与字段列表；硬件覆盖百分比为整数截断，可靠条件为非空摘要且覆盖 ≥ 50%（当前至少 9/17）。这只是字段覆盖门槛，不代表唯一性或跨固件稳定性的保证。

`RiskEngine` 为 `DataAggregator` 注入 `FingerprintStore`。应用私有 `riskengine_fp` SharedPreferences 保存 32 字节随机盐的 hex、`last_hw`、`last_sys`、`first_seen` 和 `observations`。无存储的 `DataAggregator()` 使用固定盐 `riskengine` 且不比较连续性；盐访问异常也回退到该固定值。

比较顺序：无硬件基线 → `FIRST_OBSERVATION`；有基线但本次不可靠 → `INCONCLUSIVE`；硬件相同且系统相同 → `STABLE`；仅系统变化 → `SYSTEM_CHANGED`；硬件不同 → `HARDWARE_CHANGED`；存储不可用 → `UNKNOWN`。仅可靠测量更新摘要基线，观察次数仍递增。硬件变化追加 `fingerprint_continuity`（`MEDIUM`/`WARNING`/4，可处置），发生在场景、去重和交叉规则之后。

聚合器追加 `fingerprint_id`，包含 `composite`/`hardware`/`system`/`volatile`（非空时）、`hardware_coverage`、`system_coverage`、`hardware_layer_reliable`，有存储时再加 `continuity`、`observation_count`。`RiskReport.getFingerprintId()` 返回模型；构建异常时返回 `null`。当前 `RiskReport.isSyntheticCollector` 尚未排除 `fingerprint_id`，因此它也计入总检查数和完成数。

可靠门槛以上的字段集合变化仍可能导致 `HARDWARE_CHANGED`；驱动、隐私开关或显示配置变化也可能改变硬件摘要。该状态不是物理硬件更换或伪装的证明。

## 5. Detector

风险展示（`DetectionStatus`）与执行状态（`DetectionExecutionStatus`）互相独立。`BaseDetector.result(..., CheckCoverage)` 约定：

- `attempted == 0` → `UNAVAILABLE` / `no_checks_attempted`
- `succeeded == 0` → `UNAVAILABLE`，附失败原因
- `failed > 0` 且有成功子检查 → `PARTIAL`
- 全部成功且无风险 → `SAFE`；有风险 → `RISK`

`isInformational()` 表示提示性信号：解释环境，不进入 `riskScore`。旧名 `isWarnOnly()` 保留兼容并已弃用。

注册由 `DetectorRegistry` 按配置开关决定。`NativeTamperDetector`、`ConsistencyDetector`、`SealedVerdictDetector` 始终加入。

### 5.1 `root`

Java 路径探测 + Native `nativeGetRootEvidenceRaw`。

| 证据强度 | Token 示例 | 评分 |
| --- | --- | --- |
| 强 | `su_found:`、`magisk_found:`、`ksu_found:`、`apatch_found:`、`modules_found:`、`native:su:` / `native:magisk:` / `native:mount:magisk` / `native:mount:module` | `HIGH` / `DANGER` / 8 |
| 中 | `native:syscall_mismatch:...`（access/stat/open 不一致） | `MEDIUM` / `WARNING` / 4 |
| 弱 | `selinux_permissive`、`test_keys` | `LOW` / `WARNING` / 1 / informational |

路径名单来自 ini：`[su]` `[magisk]` `[kernelsu]` `[apatch]` `[modules]`。Native 另扫 `PATH` 中的 `su`/`ksud`/`apd`/`magisk`，以及 `/proc/self/mountinfo` 中的 Magisk/模块挂载。

新增 Native 探测会将结果合并进 Root evidence：

- `ksu_prctl:`、`mount_hidden:`、`listing_mismatch:`、`selinux_context:` 按强证据计分；`ns_differs`、`mount_hidden_count` 按中证据计分。
- 命名空间检查读取自身与 PID 1 的 `ns/mnt`、`mountinfo`，比较指定系统挂载点；`ns_unreadable:*` 在 `RootDetector` 中只记 `mount_ns:*` 覆盖失败。
- KernelSU 探测使用 raw `prctl` 查询版本/响应，并检查 `/proc/self/attr/current` 的 su/Magisk 上下文；阴性结果不能排除所有内核 Root 变体。
- 目录交叉检查比较 su/Magisk 路径的 `faccessat(F_OK)` 与父目录 `getdents64`，不是原子文件系统快照；Native 还探测 `[tamper_tool_paths]`。

### 5.2 `mount_analysis`

读 `/proc/mounts` 与 `/proc/self/mountinfo`。命中 Magisk / `debug_ramdisk` / `/data/adb/modules` / docker overlay 时：`MEDIUM` / `WARNING` / 4 / 可处置。两份 proc 都读不到 → `UNAVAILABLE`。

### 5.3 `hook_framework`

Java：Xposed 类与 `sHookedMethodCallbacks`、栈帧、Frida 默认端口 27042、进程名。Native：raw-syscall 读 maps、`getdents64` 扫 `/proc/self/task/*/comm`、GOT/inline hook、JNI 表。

内部用 `HookEvidenceClassifier` 分档（Detector 自身按 strong/medium 计数）：

| Rank | Token |
| --- | --- |
| STRONG | `inline_hook:`、`got_hook:`、`jni_table_hook:`、`maps:frida`、`maps:gadget`、`frida_pid`、`frida_pid_port` |
| MEDIUM | `thread:gum-js-loop`、`thread:frida`、`maps:xposed`、`maps:lsposed`、`maps:substrate`、`xposed_hooks_active`、`xposed_class_found`、`xposed_stack` |
| WEAK | `anon_exec:`、`frida_port_open`、含 `27042` |
| IGNORE | 单独的 `thread:gmain`（仅当已有 Frida 族时 Native 才会附带） |

评分：strong≥2 或 (strong≥1 且 medium≥2) → `DEADLY`/10；strong≥1 或 medium≥2 → `HIGH`/8；medium≥1 → `MEDIUM`/2/**informational**；其余弱信号 → `LOW`/1/informational。

新增分档：`jni_slot_hook:`、`jni_self_hook:`、`art_native_flag:`、`wx_segment:self`、`unix_socket:frida`/`gum`、`late_text_mismatch`、`late_wx_self`、`late_module:` 为 STRONG；`loader_unexpected:`、`loader_chain_deep:`、其他 `wx_segment:`、`late_tracer_attached`、`late_wx_art` 为 MEDIUM。`loader_depth:` 与 `passes:` 在分类器中为 IGNORE。

当前实现仍把 IGNORE 上下文保留在 details 中；若仅有 `passes:0` 等上下文，Detector 的非空 details 分支仍返回 `LOW`/1/informational，`DIAGNOSTIC` 又可将其计入分数。这是当前实现限制，并非上下文本身证明 Hook。

### 5.4 `process_scan`

Java `/proc` 进程列表 + Native `getdents64` 扫 `/proc` comm。Token 必须整词匹配（`ProcessScanDetector.containsProcessToken`），避免 `chrome` 命中 `me` 这类假阳性。

含 frida / magisk / ksud / lspd / zygisk → `HIGH`/`DANGER`/8；其他命中 → `MEDIUM`/`WARNING`/4。Java 与 Native 一侧有证据、另一侧没有时追加 `process_source_mismatch`。两侧都不可用 → `UNAVAILABLE`。

### 5.5 `native_tamper`

始终注册，读取 `nGetSoIntegrityRaw`：

| Token | 处理 |
| --- | --- |
| `text_mismatch`（可附 `text_mismatch_seg:<index>`） | 可执行段文件/内存 FNV-1a 不同 → `HIGH`/`DANGER`/8 |
| `text_mismatch:anonymous_map` | maps 路径为空 / memfd / ashmem → 同上 |
| `text_mismatch:missing_map` | 找不到 SO：初始化场景 `LOGIN`/`PAYMENT` → `MEDIUM`/`WARNING`/4；其他场景 → `UNAVAILABLE` |
| `text_mismatch:file_unreadable` / `text_mismatch:unreadable_segments` | 同上 |
| `text_mismatch:bad_elf` | `UNAVAILABLE`，不随场景升级 |

JNI 读取本身失败仍为 `UNAVAILABLE`。场景取自 `DetectorRegistry` 构造时的 `config.getCollectScene()`，**单次场景覆盖不会改变此策略**。映射缺失不能证明篡改；敏感场景升级是风险策略。`sealed_verdict` 对相同 token 另有评分（§5.12），因此该项不可用不代表总报告只会显示覆盖缺口。

GOT/inline 与 JNI 表检查仍经 `hook_framework` 消费。

### 5.6 `emulator`

`EmulatorEvidenceClassifier` 分 STRONG / WEAK，并把 `aosp_sensor`、`missing_feature`、`limited_hardware` 标为硬件噪声。

| Rank | 示例 |
| --- | --- |
| STRONG | `virtual_gpu:`、`emu_file:`、`emu_pkg:`、`qemu_prop`、`qemu_pipe`、`cpu:hypervisor`、明确的 fingerprint/model/manufacturer/product/hardware/board、`runtime_arch:x86` / `i386` |
| WEAK | `generic_fingerprint:`、`disk_small`、`screen_stock`、`no_thermal`、`emulator_ip:`、`cgroup:`、`mount_overlay`、`cmdline_mismatch` |
| 噪声弱 | `aosp_sensor`、`missing_feature`、`limited_hardware`（平板/精简 OEM 常见，不单独升级） |

评分：strong≥2 或 (strong≥1 且有用弱信号≥1) → `HIGH`/8；仅 1 个 strong → `MEDIUM`/4；只有弱信号 → `LOW`/1/**informational**。

`ro.build.characteristics` 含 `emulator` 时新增 `qemu_prop:ro.build.characteristics=...` 强证据。

### 5.7 `debug`

TracerPid > 0 → `HIGH`/`DANGER`/8。调试器连接或 maps 可执行调试路径 → `MEDIUM`/4。仅 `debuggable_flag` 或 IDA 端口 → `LOW`/1/informational。`DIAGNOSTIC` 场景仍保持「仅 debuggable」为 informational，避免 Debug APK 把自己打成高风险。

### 5.8 `adb`

默认 informational。USB ADB：`LOW`/2；Wi-Fi ADB：`MEDIUM`/4。`CollectScene.PAYMENT` 与 `DIAGNOSTIC` 会改为可处置。

### 5.9 `sandbox` / `cloud_phone` / `custom_rom`

| 检测器 | 强证据 | 弱证据 | 默认评分 |
| --- | --- | --- | --- |
| `sandbox` | 双开包、异常 data 目录/loader、dexElements > 12、UID/用户目录不一致 | 虚拟化 fd、dexElements 7–12 | 强 `MEDIUM`/4；弱 `LOW`/1/informational |
| `cloud_phone` | `cloud_pkg:`、非空 `cloud_prop:`、`virtual_gpu:`、`wired_interface:ethN` | 电池/摄像头/传感器异常 | 任意强证据 `HIGH`/7；弱 ≥ 2 为可处置 `MEDIUM`/4；仅 1 个弱为 `LOW`/1/informational |
| `custom_rom` | — | `community_rom:`、`prop_mismatch:fingerprint` | 一律 `LOW`/1/informational。社区 ROM 不是 Root 证明 |

`LOGIN`/`PAYMENT` 会把 sandbox 与 cloud_phone 改为可处置。

### 5.10 聚合追加的检测项

| 名称 | 来源 |
| --- | --- |
| `signal_correlation` | `CorrelationEngine.correlate`，见第 8 节 |
| `multi_source_validation` | 指纹多来源不一致 |
| `fingerprint_continuity` | 跨次可靠硬件摘要变化（§4.4） |
| `collector:<field>` | 非 SUCCESS 的 Collector 覆盖占位 |

### 5.11 `consistency`

始终注册，执行七组检查：分区指纹、Build 与 Native 属性、CPU 核数、ABI/os.arch、SDK/release、fingerprint 格式/品牌、verified boot。任意强证据 → `HIGH`/`DANGER`/7；仅弱证据 → `LOW`/`WARNING`/2/informational。

强证据为 `partition_fingerprint_mismatch:`、`build_prop_mismatch:`、`core_count_mismatch:`、`abi_arch_mismatch:`、`abi_64bit_mismatch:`。弱证据为 `api_release_mismatch:`、`fingerprint_malformed:`、`fingerprint_brand_mismatch:`、`verified_boot_state:`、`bootloader_unlocked`。缺少来源记覆盖失败。当前核数检测实际仅比较 Runtime 与 `/proc/cpuinfo`；sysfs 核数由 Collector 采集，没有参与该 Detector 的比较。分区指纹直接做全字符串相等判断，合法 OEM 分区差异也可能命中。

### 5.12 `sealed_verdict`

始终注册，同时检查 JNI 自身注册指针与 Native 密封分数。Native 重新运行 root/hook/self-integrity/emulator/debug 探测，不替代已有 Java Detector。原生分数各标志累加（上限 100）：代码不一致 10、inline/GOT/JNI-table/self-W+X 9、隐藏 Root 8、KernelSU 8、强 Root 7、框架 6、调试器 6、模拟器文件或 thermal zone 为 0 时 4、命名空间覆盖缺口 1。

验证返回负数产生 `verdict_unverifiable:mac_or_nonce_rejected`；与 `jni_self_hook:` 一样返回 `DEADLY`/`DANGER`/10。有效分数 ≥ 9 → `DEADLY`/10，≥ 6 → `HIGH`/8，≥ 3 → `MEDIUM`/4；其余非空证据 → `LOW`/1/informational；无证据按覆盖返回 safe。无 Native 库或读取/验证调用失败记覆盖失败，不自动等于 MAC 拒绝。`jni_self:no_range` 当前属于非空证据，不是 `jni_self_hook:`。

此 Detector 的 `DEADLY` 不会单独新增报告级硬触发：最终等级仍按 §9 的分数、Danger 数量和已有硬触发计算。`native_score:*` 也不携带已有证据家族标记，可能与原 Detector 重复计分。

## 6. Native 层

共享库名 `libriskengine.so`，CMake 3.22.1，C++17，静态 libc++，符号隐藏。

### 6.1 内联 syscall

`raw_syscall.h` 按 ABI 直接发指令，**禁止**走 libc `syscall()`：

| ABI | 指令 |
| --- | --- |
| aarch64 | `svc #0`（x8 号、x0–x5 参数） |
| arm | `svc #0`（r7 号） |
| x86_64 | `syscall` |
| i386 | `int $0x80`（最多 5 个参数；第 6 个忽略） |

`syscall_wrapper.cpp` 封装 `openat`/`faccessat`/`fstatat`/`read`/`close`/`mmap`/`munmap`/`readlinkat`/`prctl`/`getppid`/`gettid` 等。读文件、探测路径、maps 都走这条路径。

### 6.2 目录遍历

`raw_dir.cpp` 用 `getdents64` 列目录，避免 `opendir`/`readdir` 被 hook。用于 `/proc/self/task`、`/proc` 进程扫描、thermal zone。

### 6.3 字符串混淆

`OBF("...")` 使用 `__LINE__`、`__COUNTER__` 与字符串长度生成每个调用点的种子，再以滚动 xorshift 字节流 XOR 编码，运行时解码；不再使用固定 `0x5A`。这是静态字符串混淆，不是加密保证。Java `ObfuscatedLists` 仅提供解码脚手架，尚未接入 `DetectionLists` 的生成与消费，Java 名单仍是明文。

### 6.4 maps

`maps_parser.cpp` 用 raw syscall 读 `/proc/self/maps`，解析起止地址、权限、路径。Java `SignalSnapshot.getSelfMaps()` 是另一条 Java 路径，供 Hook/Debug 的 Java 侧复用；Native Hook maps **故意独立**，减少 libc hook 造成的同一盲区。

### 6.5 完整性

`native_integrity.cpp`：

1. **libc GOT / inline hook**：mmap 磁盘上的 `libc.so`，解析 ELF 动态表，检查 `list_monitored_libc_symbols()` 列出的 18 个符号（包括文件、目录、网络、属性与动态加载相关函数）。GOT 目标落在 libc RX 之外 → `got_hook:<name>`。ARM64 识别 `LDR X16/X17 + BR` 与越界 `B`；ARM32 识别 `bx/blx` 与 `ldr pc`。x86 无 trampoline 启发式。
2. **JNI 表**：`JNIEnv->FindClass` / `GetVersion` 函数指针若落在 `libart.so` RX 之外 → `jni_table_hook:...`。
3. **自身 SO FNV-1a**：遍历所有可执行 PT_LOAD 的文件范围，以 64 KiB 窗口比较磁盘与可读内存，种子含段地址与偏移。发现不同输出 `text_mismatch` 与 `text_mismatch_seg:<index>`；有候选段但所有窗口不可读输出 `text_mismatch:unreadable_segments`。部分窗口不可读会跳过，当前不单独上报部分覆盖，因此空 evidence 不保证每个窗口都已比对。
4. **JNI 自身注册表**：检查本库静态 `JNINativeMethod methods[]` 中的函数指针是否落在自身 RX 范围，越界输出 `jni_self_hook:<index>`；无范围输出 `jni_self:no_range`。它并不读取 ART 当前实际注册目标，不能保证发现后续 `RegisterNatives` 重绑定。

ART 检查通过公开反射读取 `Method.invoke`、`Runtime.exec`、`File.exists`、`NativeCollectorBridge.isNativeAvailable` 的 native modifier，不使用固定 ArtMethod 偏移；另检查 ClassLoader 父链与六个反射/注册相关 JNIEnv 槽位是否在 libart RX 范围内。Unix socket 扫描被动读取 `/proc/net/unix` 的已知 Frida/gum 名称，W+X 扫描检查自身、libart 与 libc；读取失败的部分 Native 子探测仍返回空串，尚无逐项覆盖状态。

### 6.6 Native Detector 入口

| JNI | Native | 用途 |
| --- | --- | --- |
| `nativeCheckRootRaw` / `nativeGetRootEvidenceRaw` | `native_root_detector` | Root 路径、挂载、syscall 不一致 |
| `nativeGetHookEvidenceRaw` | `native_hook_detector` | maps / 线程 / 完整性 token |
| `nativeCheckEmulatorFilesRaw` | `native_emulator_detector` | 模拟器文件 |
| `nativeGetThermalZoneCountRaw` | 同上 | thermal zone 计数 |
| `nativeGetRuntimeArchRaw` | `runtime_arch_checker` | 运行时 ABI |
| `nativeGetTracerPidRaw` | `native_debug_detector` | TracerPid |
| `nGetSelinuxEnforceRaw` | root detector | SELinux |
| `nGetBuildPropFingerprintRaw` | 读 `/system/build.prop` | 与 `ro.build.fingerprint` 对照 |
| `nScanProcessTokensRaw` | integrity 中的 process scan | Native 进程 token |
| `nGetSoIntegrityRaw` | `native_get_so_integrity_evidence` | SO FNV-1a |
| `nGetMountNsEvidenceRaw` | `mount_namespace_diff` | 自身与 PID 1 挂载差异 |
| `nGetKernelRootEvidenceRaw` | `kernel_su_probe` | prctl / SELinux 上下文 |
| `nGetSealedVerdictRaw` / `nVerifySealedVerdictRaw` | `sealed_verdict` | 密封载荷生成 / 验证并返回分数 |
| `nGetJniSelfIntegrityRaw` | `native_get_jni_self_table_evidence` | 本库静态注册指针范围 |
| `nGetMonitorFindingsRaw` / `nStopMonitorRaw` | `periodic_monitor` | 读取累积发现 / 请求停止 |

JNI 字符串不把不可信字节交给 `NewStringUTF`：限制长度、校验 UTF-8、非法序列替换后走 UTF-16 `NewString`。C++ 分配失败与 JNI 字符获取失败不跨边界遗留异常。注册失败会清理挂起异常并记录目标类名。

### 6.7 Native 构建加固

- `-fstack-protector-strong`、Release `_FORTIFY_SOURCE=2`、`-Wformat -Wformat-security`
- `-fvisibility=hidden`
- 链接：`relro,now`、`noexecstack`、`max-page-size=16384`、`--exclude-libs,ALL`
- Release 增加 thin LTO、移除 unwind table/frame pointer、常量合并、section GC 与 strip；`exports.map` 版本脚本只导出 `JNI_OnLoad`，JNI 方法仍经 `RegisterNatives` 绑定。

### 6.8 密封载荷与周期监控

密封载荷为 64 个 hex 字符，编码 8 字节 nonce、4 字节 flags、4 字节 score、8 字节单调时钟时间与 8 字节标签。32 字节密钥优先从 `/dev/urandom` 获取，失败回退到 `AT_RANDOM`，再失败使用地址/tid 派生值。标签是自定义带密钥的 FNV-1a，**不是 HMAC 或标准密码学 MAC**。验证检查长度、标签与最近签发的 nonce，但不校验时间过期、不消费 nonce；最新载荷可重复验证。密钥位于进程内存，Java 调用与最终评分仍可被改写，因此不是安全证明。

`JNI_OnLoad` 启动 detached pthread，每次延迟 20–26 秒后检查自身代码、TracerPid、自身/libart W+X、Frida/LSPosed 映射。发现去重累积为 `late_*`，读取时附 `passes:<n>`；不会修改已冻结报告或主动回调，后续 `hook_framework` 采集才消费。监控不重复完整 Root/模拟器扫描。

`shutdown()` 仅设置停止标志，不 join 或清空发现/计数；同进程重新 `init` 不会再次调用 `JNI_OnLoad`，目前没有重启入口。

## 7. 共享信号

每次报告开始前 `SignalSnapshot.reset()`。`SignalResult<T>` 保留 success / empty / unavailable / error。Collector 与 Detector 共享：

- ADB 状态、系统属性、`/proc/self/maps`（Java 路径）
- 本机监听端口、进程快照、文本文件、路径存在性、容器信号
- 同一命令的结构化 `ShellExecutor.Result`
- SELinux、`build.prop` fingerprint、CPU/磁盘/内核、Native 进程 token、SO 完整性、屏幕度量

因此 ADB Collector 与 Detector 不再各扫一遍；Java Hook/Debug 复用 maps 与端口。Native Hook maps 仍独立读取。

`ShellExecutor.Result` 区分 `SUCCESS`、`INVALID_COMMAND`、`TIMEOUT`、`NON_ZERO_EXIT`、`INTERRUPTED`、`EXECUTION_ERROR`，并携带 stdout/stderr/exitCode/durationMs/failureReason。字符串-only 助手已弃用。

新增共享信号包括 GPU vendor/renderer、网络接口名、命名空间/内核 Root evidence、JNI 自身检查与密封裁决。`getGpuIdentity()` 为 Emulator/Cloud Detector 缓存离屏探测，但 `GpuInfoCollector` 仍独立采集，一次报告可能创建两次 EGL context。网卡名优先读 sysfs，无结果才用 Java 枚举，不做两源比较。系统属性现在只走 Native 白名单读取，已移除 shell `getprop` 回退；空属性保留 EMPTY。

## 8. 场景、家族去重与交叉规则

`DataAggregator.aggregate` 顺序：

1. `CorrelationEngine.dedupeFamilies`：同一 `EvidenceFamily`（`frida` / `debugger` / `xposed` / `root_fw` / `qemu`）若已被靠前的检测器占用，后到且 `score > 0` 的可处置结果改为 informational，避免 Magisk 同时给 `root` 与 `process_scan` 加两份分。
2. `CorrelationEngine.applyScene`：按 `CollectScene` 把指定检测器从 informational 提升为 actionable。不关闭检测器，不降低已可处置的结果。
3. `CorrelationEngine.correlate`：可能追加一条 `signal_correlation`。
4. Collector 覆盖信号、多来源不一致、原有合成字段。
5. 分层指纹 ID、连续性比较与可选 `fingerprint_continuity`。后者不会再经过场景/去重/交叉规则，且不包含在此前生成的 `runtime_integrity_score_inputs` 中。

#新增共享信号包括 GPU vendor/renderer、网络接口名、命名空间/内核 Root evidence、JNI 自身检查与密封裁决。`getGpuIdentity()` 为 Emulator/Cloud Detector 缓存离屏探测，但 `GpuInfoCollector` 仍独立采集，一次报告可能创建两次 EGL context。网卡名优先读 sysfs，无结果才用 Java 枚举，不做两源比较。系统属性现在只走 Native 白名单读取，已移除 shell `getprop` 回退；空属性保留 EMPTY。

## 8.1 场景提升

| 场景 | 提升为可处置 |
| --- | --- |
| `STANDARD` | 无 |
| `LOGIN` | `emulator`、`cloud_phone`、`sandbox` |
| `PAYMENT` | LOGIN + `adb` |
| `DIAGNOSTIC` | 除「debug 且仅 `debuggable_flag`」外的全部 informational |

#新增共享信号包括 GPU vendor/renderer、网络接口名、命名空间/内核 Root evidence、JNI 自身检查与密封裁决。`getGpuIdentity()` 为 Emulator/Cloud Detector 缓存离屏探测，但 `GpuInfoCollector` 仍独立采集，一次报告可能创建两次 EGL context。网卡名优先读 sysfs，无结果才用 Java 枚举，不做两源比较。系统属性现在只走 Native 白名单读取，已移除 shell `getprop` 回退；空属性保留 EMPTY。

## 8.2 交叉规则

| ID | 条件 | 结果 |
| --- | --- | --- |
| C1 | 模拟器当前 ≤ `LOW`，且有 hypervisor 或 (小磁盘 + x86) | `MEDIUM` / `WARNING` / 4 |
| C2 | 恰好 1 个 STRONG + hypervisor/QEMU，且模拟器已是 `MEDIUM` | 升至 `HIGH` / `DANGER` / 4 |
| C3 | inline/GOT hook **且** Frida 族（hook 或 process_scan） | `DEADLY` / `DANGER` / 10，硬触发 |
| C4 | `syscall_mismatch` **且** 模块/Magisk 挂载 | `HIGH` / `DANGER` / 8 |
| C5 | `prop_mismatch:fingerprint`、无 `community_rom:`、模拟器 NORMAL | `LOW` / `WARNING` / 1 / informational（resetprop 提示） |
| C7 | `LOGIN`/`PAYMENT` 下云真机无 `cloud_pkg:` 但弱证据 ≥ 2 | `LOW` / `WARNING` / 2 |

无匹配则不追加 `signal_correlation`。C3 同时满足 `RiskReport.hasHardTrigger()`。

## 9. 报告与评分

阈值常量在 `RiskReport`：`MEDIUM_THRESHOLD=4`、`HIGH_THRESHOLD=10`、`DEADLY_THRESHOLD=18`。

综合等级：

| 等级 | 条件（先硬触发，再分数/计数） |
| --- | --- |
| `DEADLY` | 硬触发；或分数 ≥ 18；或可处置 Danger ≥ 3 |
| `HIGH` | 分数 ≥ 10 或可处置 Danger ≥ 1 |
| `MEDIUM` | 分数 ≥ 4 或可处置 Warning ≥ 2 |
| `LOW` | 分数 > 0，或存在任意 Warning/Danger（含 informational） |
| `UNKNOWN` | 以上都不满足，且 `unknownCount > 0` 或存在 `PARTIAL`/`UNAVAILABLE`/`TIMEOUT`/`ERROR` |
| `SAFE` | 分数 0、无提示/风险、覆盖完整 |

硬触发（跳过 informational）：

- 任意检测器 details 含 `inline_hook:` 或 `got_hook:`，且该条风险 ≥ `HIGH`
- `hook_framework` 含 `frida_pid_port` / `maps:frida` / `maps:gadget`
- `signal_correlation` 含 `C3:`

其他报告字段：

- `riskScore`：非 informational 的 `score` 之和
- `maxRiskScore`：所有 `maxScore` 之和（技术容量）
- `displayThresholdMaximum`：固定 18
- `warningCount` / `dangerCount` / `unknownCount`：按 `DetectionStatus` 计数，**含** informational
- `checkCount`：非 `collector:*` 的检测项 + 非合成 Collector
- `completedCheckCount`：执行状态为 `SAFE`/`RISK` 的检测项 + `SUCCESS` 的原始 Collector
- `coveragePercent`：`round(completed / total * 100)`；total 为 0 时为 100
- `reportStatus`：全部完成 `COMPLETE`；一个都没完成且无可用检测 `UNAVAILABLE`；否则 `PARTIAL`

当前覆盖统计只排除 `hook_memory_signals` 与 `runtime_integrity_score_inputs` 两项合成字段；`fingerprint_id` 仍计入，见 §4.4。

聚合后 `RiskReport`、`DeviceFingerprint` 与内部 `CollectorResult` 被 freeze。

## 10. 隐私

| 档位 | Android ID | Boot ID | Widevine |
| --- | --- | --- | --- |
| `MINIMAL` | 关 | 关 | 关 |
| `BALANCED` | 开 | 关 | 关 |
| `DIAGNOSTIC` | 开 | 开 | 开 |

三项均可被 Builder 覆盖。`PrivacyUtils.hashIdentifier` 计算 `SHA-256(packageName + ":" + value)` 的 hex。这是应用范围假名，不是加密或匿名化。

SDK 不采集原始 IMEI、IMSI、MAC、SSID、BSSID。Native 属性读取受 ini 白名单约束。

五个新增硬件 Collector 与分层 ID 在所有档位运行；`MINIMAL` 不禁用它们或 `FingerprintStore`。安装盐与摘要存在应用私有偏好文件，正常卸载/清除数据会删除，不实现 Keystore 跨重装关联；宿主备份/恢复策略仍影响持久性。盐读取失败回退固定值时，安装范围隔离不再有保证。

## 11. 名单单源

只读清单：`riskengine-sdk/src/main/resources/lists/artifact_paths.ini`。

生成物（提交在仓库中，修改 ini 后必须同步）：

- `riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java`
- `riskengine-sdk/src/main/cpp/generated/detection_lists.h`

`RootPathListConsistencyTest` 校验 Java 数组与 ini 一致。节包括 su / magisk / kernelsu / apatch / modules / emulator_files / emulator_packages / cloud_packages / sandbox_packages / properties / process tokens 等。

此次新增 `[tamper_tool_paths]` 与属性条目，并扩展 Java/Native 生成列表。`PARTITION_FINGERPRINT_PROPERTIES`、`CLOUD_PHONE_PROPERTIES`、`VIRTUAL_GPU_MARKERS` 与 `list_monitored_libc_symbols()` 等分组还定义在生成源码中；不能假设所有分组均有同名 ini 节。`ObfuscatedLists` 尚未替换明文 Java 清单。

## 12. JSON

`RiskReportJsonSerializer` 使用 `org.json`（Android 框架已提供；单元测试用 `org.json:json`）。根对象字段：

`timestampMs`、`sdkVersion`、`riskScore`、`maxRiskScore`、`displayThresholdMaximum`、`warningCount`、`dangerCount`、`unknownCount`、`availableDetectionCount`、`detectionCount`、`checkCount`、`completedCheckCount`、`incompleteCheckCount`、`coveragePercent`、`reportStatus`、`overallRiskLevel`、`collectScene`、`fingerprint`、`detections`。

每条 detection 含：`detectorName`、`riskLevel`、`status`、`executionStatus`、`score`、`maxScore`、`informational`、`checksAttempted`/`Succeeded`/`Failed`、`failureReasons`、`details`、`evidence`、`timestampMs`。

当前序列化器未新增顶层 `fingerprintId`，Java getter 也不会自动成为 JSON 字段。分层 ID 与连续性通过已有 Collector 序列化路径输出到 `fingerprint.fingerprint_id.values`，其值为字符串；硬件参与字段列表只在 `FingerprintId` Java 模型中。

## 13. ProGuard / R8

- SDK AAR `isMinifyEnabled = false`。在库模块 minify 会拆掉嵌套公开类型，并让 Release 单元测试找不到类。
- `consumer-rules.pro` keep：`RiskEngine`、`RiskEngineConfig`（含 `Builder`）、`RiskEngineCallback`、`PrivacyProfile`、`CollectScene`、`model.**`、`NativeCollectorBridge`（JNI 按名注册）、所有 `native` 方法。
- Demo Release 开启 minify。

## 14. Demo 展示契约

Demo 直接依赖工程内 SDK，是诊断控制台：

1. 无启动采集、无标题营销文案、无隐私说明卡。首屏即状态卡。
2. 状态卡：中文风险结论、主要依据（已人话化）、风险分 / 18、覆盖率、耗时。「复制报告」在状态卡标题行，有结果后可见。
3. 环境检测：风险项优先。折叠行 = 中文名 + 语义徽章 + 摘要，不含 `snake_case` id。展开后才出现「检测器：root」与原始 token。
4. 摘要人话化：`native:mount:magisk` → Magisk 挂载；`text_mismatch:missing_map` → 未能在内存映射中找到 Native 库。原始 token 只在详情中出现一次，不与中文句重复。
5. 「需关注」排除 informational（ADB、弱模拟器、社区 ROM、仅 debuggable 等）。
6. `collector:*` 不作为环境检测行；覆盖缺口计入顶部覆盖率。
7. SDK 合成字段（`hook_memory_signals`、`runtime_integrity_score_inputs`）独立分区。
8. 错误状态灰色 + 0% 进度，不与最高风险混淆。
9. 复制输出脱敏摘要：无标识哈希、原始属性、路径、PID。
10. 展开行 ripple 画在 foreground，展开后清除 pressed/focus，避免残留灰底。
11. 状态可跨 Activity 重建。触觉只在新结果到达时触发。
12. `allowBackup=false`，禁止设备迁移导出。

该提交未修改 Demo 的名称映射或展示布局；新增 Detector/Collector 仍走现有通用展示路径，尚无专门的分层 ID/连续性界面。

## 15. 测试

单元测试（`riskengine-sdk/src/test`）：

| 测试 | 覆盖 |
| --- | --- |
| `RiskScoringModelTest` | 等级阈值、informational 不加分、硬触发 |
| `FailureSemanticsTest` | Collector/Detector 失败不变成 SAFE |
| `DetectorCoverageTest` | `CheckCoverage` 全失败 → UNAVAILABLE |
| `CorrelationEngineTest` | 场景提升、家族去重、C1–C7 |
| `EmulatorScoringTest` | 强/弱/噪声弱信号 |
| `HookTokenRankingTest` | Hook token 分档 |
| `ProcessPatternNegativeTest` | 进程名整词匹配、负例 |
| `RootPathListConsistencyTest` | Java 名单与 ini 一致 |
| `RiskEngineConfigTest` | 隐私档位、场景、超时边界 |
| `RiskReportJsonSerializerTest` | JSON 字段 |
| `DataAggregatorTest` / `SignalSnapshotTest` / `TaskSchedulerTest` / `ShellExecutorTest` / `CollectorResultTest` / `ProcfsUtilsTest` | 聚合、缓存、线程、Shell、模型 |

`integration-test` 只编译链接公开 API，不跑设备检测。当前没有自动设备矩阵工作流；`Adversarial_Matrix.md` 是预期证据说明，不能代替 ARM64 OEM 真机验证。

提交附带的 [Implementation_Status_2026-09.md](./Implementation_Status_2026-09.md) 记录四 ABI 与 Java 编译通过，以及 52 项测试中 2 项失败：`RiskEngineConfigTest.disabledDetectorsAreNotRegistered` 尚按 1 个而非 3 个无条件检测器断言；`DataAggregatorTest.synthesizedFieldsAreExposedButNotDoubleCountedInCoverage` 未反映新增 `fingerprint_id` 的覆盖计数。这是提交中的历史记录，不是本文档更新时重跑所得。新增 EGL/ART/内核/监控能力仍需设备验证。

## 16. 构建与发布

```bash
./gradlew :riskengine-sdk:test :riskengine-sdk:lint
./gradlew :riskengine-sdk:assembleRelease :riskengine-sdk:sourceReleaseJar
./gradlew :demo:lintDebug :demo:assembleDebug
```

- PR 与分支 Push：单测、Lint、AAR/POM/sources、Demo Debug APK、压缩包完整性。
- `vMAJOR.MINOR.PATCH` Tag：AAR、sources JAR、POM、临时 Debug APK、SHA-256。流水线不保存生产签名密钥。
- `maven-publish` publication 已就绪，远端仓库尚未选定；当前分发以 GitHub Release 文件为准。

## 17. 已知边界

- 命名空间差异依赖 PID 1 procfs 可见性，不保证识破完整 DenyList/Shamiko；命名空间不同、目录枚举差异本身也可能来自合法隔离或读取时序。
- 各检测路径的失败语义尚不完全一致：`root` 对 `ns_unreadable:*` 记覆盖失败，密封裁决却加 1 个 Native 分；密封裁决把所有 `text_mismatch*`（含 missing_map/file_unreadable/bad_elf/unreadable_segments）计作代码风险，监控也把这些后缀锁存为 `late_text_mismatch`。因此不能把 `native_tamper` 的 `UNAVAILABLE` 推广为全报告仅覆盖不足。
- `native_tamper` 场景在初始化时绑定；密封载荷验证不防最新 nonce 重放；JNI 自检只看静态注册表；监控停止后同进程不自动重启。详见 §5–6。
- x86/i386 无 ARM trampoline 检测；GOT 与 FNV-1a 比对仍运行。FNV-1a 不是密码学哈希。
- 虚拟 GPU、ethN、分区指纹差异、动态核数、ClassLoader/dexElements 与匿名映射都可能有合法来源，需要 OEM 真机与宿主框架回归。GPU 离屏采集尚需驱动兼容性验证。
- 分层 ID 依赖可用字段与安装盐，不能保证跨重装、跨固件唯一识别设备；当前仍有两项测试预期与实现不一致（§15）。
- 本地信号、Java 判定与进程内 Native 密钥可被篡改；SDK 不替代服务端风控、硬件证明或 Play Integrity。
