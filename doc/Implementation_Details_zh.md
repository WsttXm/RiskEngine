# RiskEngine 实现说明

本文档是当前源码中的契约，而不是设计意向。宿主集成以 [README_zh.md](../README_zh.md) 为准。典型环境下的预期证据族见 [Adversarial_Matrix.md](./Adversarial_Matrix.md)。

## 1. 定位与模块

RiskEngine 是本地 Android 风险信号 SDK：Java 负责编排、隐私、评分与报告；C++17 JNI 负责抗 libc hook 的 I/O、maps 解析、路径探测与完整性检查。没有服务端、没有上报、不依赖 Play Integrity。

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
       applyScene -> dedupeFamilies -> correlate
       collector 覆盖信号 / 多来源不一致 / 合成字段
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
| `shutdown()` | 取消任务并释放资源 |

配置默认值：所有检测器组开启、`debugLog=false`、超时 10_000 ms、`PrivacyProfile.BALANCED`、`CollectScene.STANDARD`。`native_tamper` 不受配置开关控制，始终注册。

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

## 5. Detector

风险展示（`DetectionStatus`）与执行状态（`DetectionExecutionStatus`）互相独立。`BaseDetector.result(..., CheckCoverage)` 约定：

- `attempted == 0` → `UNAVAILABLE` / `no_checks_attempted`
- `succeeded == 0` → `UNAVAILABLE`，附失败原因
- `failed > 0` 且有成功子检查 → `PARTIAL`
- 全部成功且无风险 → `SAFE`；有风险 → `RISK`

`isInformational()` 表示提示性信号：解释环境，不进入 `riskScore`。旧名 `isWarnOnly()` 保留兼容并已弃用。

注册由 `DetectorRegistry` 按配置开关决定。`NativeTamperDetector` 始终加入。

### 5.1 `root`

Java 路径探测 + Native `nativeGetRootEvidenceRaw`。

| 证据强度 | Token 示例 | 评分 |
| --- | --- | --- |
| 强 | `su_found:`、`magisk_found:`、`ksu_found:`、`apatch_found:`、`modules_found:`、`native:su:` / `native:magisk:` / `native:mount:magisk` / `native:mount:module` | `HIGH` / `DANGER` / 8 |
| 中 | `native:syscall_mismatch:...`（access/stat/open 不一致） | `MEDIUM` / `WARNING` / 4 |
| 弱 | `selinux_permissive`、`test_keys` | `LOW` / `WARNING` / 1 / informational |

路径名单来自 ini：`[su]` `[magisk]` `[kernelsu]` `[apatch]` `[modules]`。Native 另扫 `PATH` 中的 `su`/`ksud`/`apd`/`magisk`，以及 `/proc/self/mountinfo` 中的 Magisk/模块挂载。

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

### 5.4 `process_scan`

Java `/proc` 进程列表 + Native `getdents64` 扫 `/proc` comm。Token 必须整词匹配（`ProcessScanDetector.containsProcessToken`），避免 `chrome` 命中 `me` 这类假阳性。

含 frida / magisk / ksud / lspd / zygisk → `HIGH`/`DANGER`/8；其他命中 → `MEDIUM`/`WARNING`/4。Java 与 Native 一侧有证据、另一侧没有时追加 `process_source_mismatch`。两侧都不可用 → `UNAVAILABLE`。

### 5.5 `native_tamper`

始终运行。读取 Native `nGetSoIntegrityRaw`：

| Token | 处理 |
| --- | --- |
| `text_mismatch` | 内存 RX 与文件前 4 KiB CRC 不一致 → `HIGH`/`DANGER`/8 |
| `text_mismatch:anonymous_map` | maps 路径为空 / memfd / ashmem → 同上，可处置 |
| `text_mismatch:missing_map` | maps 中找不到 `libriskengine.so` → **`UNAVAILABLE`** |
| `text_mismatch:file_unreadable` | 文件打不开 → `UNAVAILABLE` |
| `text_mismatch:bad_elf` | ELF 解析失败 → `UNAVAILABLE` |

`missing_map` 常见于 Magisk Hide 把 SO 从 maps 抹掉。记为覆盖不足而不是安全，也不把它当成已证实篡改——用户态无法区分「被隐藏」与「加载失败」。

GOT/inline hook 与 JNI 表检查由 `native_get_integrity_evidence` 产出，经 `hook_framework` 消费，不走 `native_tamper`。

### 5.6 `emulator`

`EmulatorEvidenceClassifier` 分 STRONG / WEAK，并把 `aosp_sensor`、`missing_feature`、`limited_hardware` 标为硬件噪声。

| Rank | 示例 |
| --- | --- |
| STRONG | `emu_file:`、`emu_pkg:`、`qemu_prop`、`qemu_pipe`、`cpu:hypervisor`、明确的 fingerprint/model/manufacturer/product/hardware/board、`runtime_arch:x86` / `i386` |
| WEAK | `generic_fingerprint:`、`disk_small`、`screen_stock`、`no_thermal`、`emulator_ip:`、`cgroup:`、`mount_overlay`、`cmdline_mismatch` |
| 噪声弱 | `aosp_sensor`、`missing_feature`、`limited_hardware`（平板/精简 OEM 常见，不单独升级） |

评分：strong≥2 或 (strong≥1 且有用弱信号≥1) → `HIGH`/8；仅 1 个 strong → `MEDIUM`/4；只有弱信号 → `LOW`/1/**informational**。

### 5.7 `debug`

TracerPid > 0 → `HIGH`/`DANGER`/8。调试器连接或 maps 可执行调试路径 → `MEDIUM`/4。仅 `debuggable_flag` 或 IDA 端口 → `LOW`/1/informational。`DIAGNOSTIC` 场景仍保持「仅 debuggable」为 informational，避免 Debug APK 把自己打成高风险。

### 5.8 `adb`

默认 informational。USB ADB：`LOW`/2；Wi-Fi ADB：`MEDIUM`/4。`CollectScene.PAYMENT` 与 `DIAGNOSTIC` 会改为可处置。

### 5.9 `sandbox` / `cloud_phone` / `custom_rom`

| 检测器 | 强证据 | 弱证据 | 默认评分 |
| --- | --- | --- | --- |
| `sandbox` | 双开包、异常 data 目录、ClassLoader 标记 | 虚拟化 fd | 强 `MEDIUM`/4；弱 `LOW`/1/informational |
| `cloud_phone` | `cloud_pkg:` | 电池/摄像头/传感器异常 | 同上 |
| `custom_rom` | — | `community_rom:`、`prop_mismatch:fingerprint` | 一律 `LOW`/1/informational。社区 ROM 不是 Root 证明 |

`LOGIN`/`PAYMENT` 会把 sandbox 与 cloud_phone 改为可处置。

### 5.10 聚合追加的检测项

| 名称 | 来源 |
| --- | --- |
| `signal_correlation` | `CorrelationEngine.correlate`，见第 8 节 |
| `multi_source_validation` | 指纹多来源不一致 |
| `collector:<field>` | 非 SUCCESS 的 Collector 覆盖占位 |

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

`syscall_wrapper.cpp` 封装 `openat`/`faccessat`/`fstatat`/`read`/`close`/`mmap`/`munmap` 等。读文件、探测路径、maps 都走这条路径。

### 6.2 目录遍历

`raw_dir.cpp` 用 `getdents64` 列目录，避免 `opendir`/`readdir` 被 hook。用于 `/proc/self/task`、`/proc` 进程扫描、thermal zone。

### 6.3 字符串混淆

`obf_str.h` 的 `OBF("...")` 在编译期 XOR `0x5A`，运行时还原。路径、Frida/Magisk 关键字、符号名不在 `.rodata` 中明文出现。这是静态字符串隐藏，不是密码学保护。

### 6.4 maps

`maps_parser.cpp` 用 raw syscall 读 `/proc/self/maps`，解析起止地址、权限、路径。Java `SignalSnapshot.getSelfMaps()` 是另一条 Java 路径，供 Hook/Debug 的 Java 侧复用；Native Hook maps **故意独立**，减少 libc hook 造成的同一盲区。

### 6.5 完整性

`native_integrity.cpp`：

1. **libc GOT / inline hook**：mmap 磁盘上的 `libc.so`，解析 ELF 动态表，检查 `openat`/`faccessat`/`read`/`connect`/`ptrace`/`fopen`。GOT 目标落在 libc RX 之外 → `got_hook:<name>`。ARM64 识别 `LDR X16/X17 + BR` 与越界 `B`；ARM32 识别 `bx/blx` 与 `ldr pc`。x86 无 trampoline 启发式。
2. **JNI 表**：`JNIEnv->FindClass` / `GetVersion` 函数指针若落在 `libart.so` RX 之外 → `jni_table_hook:...`。
3. **自身 SO CRC**：在 maps 中定位 `libriskengine.so`，比较第一个可执行 PT_LOAD 的文件与内存前 4 KiB CRC-32。缺失/匿名/不可读/坏 ELF 产出带后缀的 `text_mismatch:*` token。

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
| `nGetSoIntegrityRaw` | `native_get_so_integrity_evidence` | SO CRC |

JNI 字符串不把不可信字节交给 `NewStringUTF`：限制长度、校验 UTF-8、非法序列替换后走 UTF-16 `NewString`。C++ 分配失败与 JNI 字符获取失败不跨边界遗留异常。注册失败会清理挂起异常并记录目标类名。

### 6.7 Native 构建加固

- `-fstack-protector-strong`、Release `_FORTIFY_SOURCE=2`、`-Wformat -Wformat-security`
- `-fvisibility=hidden`
- 链接：`relro,now`、`noexecstack`、`max-page-size=16384`、`--exclude-libs,ALL`

## 7. 共享信号

每次报告开始前 `SignalSnapshot.reset()`。`SignalResult<T>` 保留 success / empty / unavailable / error。Collector 与 Detector 共享：

- ADB 状态、系统属性、`/proc/self/maps`（Java 路径）
- 本机监听端口、进程快照、文本文件、路径存在性、容器信号
- 同一命令的结构化 `ShellExecutor.Result`
- SELinux、`build.prop` fingerprint、CPU/磁盘/内核、Native 进程 token、SO 完整性、屏幕度量

因此 ADB Collector 与 Detector 不再各扫一遍；Java Hook/Debug 复用 maps 与端口。Native Hook maps 仍独立读取。

`ShellExecutor.Result` 区分 `SUCCESS`、`INVALID_COMMAND`、`TIMEOUT`、`NON_ZERO_EXIT`、`INTERRUPTED`、`EXECUTION_ERROR`，并携带 stdout/stderr/exitCode/durationMs/failureReason。字符串-only 助手已弃用。

## 8. 场景、家族去重与交叉规则

`DataAggregator.aggregate` 顺序：

1. `CorrelationEngine.dedupeFamilies`：同一 `EvidenceFamily`（`frida` / `debugger` / `xposed` / `root_fw` / `qemu`）若已被靠前的检测器占用，后到且 `score > 0` 的可处置结果改为 informational，避免 Magisk 同时给 `root` 与 `process_scan` 加两份分。
2. `CorrelationEngine.applyScene`：按 `CollectScene` 把指定检测器从 informational 提升为 actionable。不关闭检测器，不降低已可处置的结果。
3. `CorrelationEngine.correlate`：可能追加一条 `signal_correlation`。
4. Collector 覆盖信号、多来源不一致、合成指纹字段。

### 8.1 场景提升

| 场景 | 提升为可处置 |
| --- | --- |
| `STANDARD` | 无 |
| `LOGIN` | `emulator`、`cloud_phone`、`sandbox` |
| `PAYMENT` | LOGIN + `adb` |
| `DIAGNOSTIC` | 除「debug 且仅 `debuggable_flag`」外的全部 informational |

### 8.2 交叉规则

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

聚合后 `RiskReport`、`DeviceFingerprint` 与内部 `CollectorResult` 被 freeze。

## 10. 隐私

| 档位 | Android ID | Boot ID | Widevine |
| --- | --- | --- | --- |
| `MINIMAL` | 关 | 关 | 关 |
| `BALANCED` | 开 | 关 | 关 |
| `DIAGNOSTIC` | 开 | 开 | 开 |

三项均可被 Builder 覆盖。`PrivacyUtils.hashIdentifier` 计算 `SHA-256(packageName + ":" + value)` 的 hex。这是应用范围假名，不是加密或匿名化。

SDK 不采集原始 IMEI、IMSI、MAC、SSID、BSSID。Native 属性读取受 ini 白名单约束。

## 11. 名单单源

只读清单：`riskengine-sdk/src/main/resources/lists/artifact_paths.ini`。

生成物（提交在仓库中，修改 ini 后必须同步）：

- `riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java`
- `riskengine-sdk/src/main/cpp/generated/detection_lists.h`

`RootPathListConsistencyTest` 校验 Java 数组与 ini 一致。节包括 su / magisk / kernelsu / apatch / modules / emulator_files / emulator_packages / cloud_packages / sandbox_packages / properties / process tokens 等。

## 12. JSON

`RiskReportJsonSerializer` 使用 `org.json`（Android 框架已提供；单元测试用 `org.json:json`）。根对象字段：

`timestampMs`、`sdkVersion`、`riskScore`、`maxRiskScore`、`displayThresholdMaximum`、`warningCount`、`dangerCount`、`unknownCount`、`availableDetectionCount`、`detectionCount`、`checkCount`、`completedCheckCount`、`incompleteCheckCount`、`coveragePercent`、`reportStatus`、`overallRiskLevel`、`collectScene`、`fingerprint`、`detections`。

每条 detection 含：`detectorName`、`riskLevel`、`status`、`executionStatus`、`score`、`maxScore`、`informational`、`checksAttempted`/`Succeeded`/`Failed`、`failureReasons`、`details`、`evidence`、`timestampMs`。

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

`integration-test` 只编译链接公开 API，不跑设备检测。Instrumentation 矩阵（API 30/33/35/36 x86_64）在 CI 中按周/手动触发，不能替代 ARM64 OEM 真机。

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

- 内核 mount namespace 隐藏（完整 Magisk DenyList / Shamiko）无法在无 attestation 的用户态保证识破。相关检查失败必须是 `UNKNOWN`/`PARTIAL`/`UNAVAILABLE`，不能变成 `SAFE`。
- `native_tamper` 的 `missing_map` 按设计是覆盖缺口。若宿主要把「SO 从 maps 消失」当作风险，应在宿主侧解释该 `UNAVAILABLE`，而不是指望 SDK 把它打成 DANGER。
- x86/i386 无 ARM trampoline 检测；GOT 检查与 CRC 仍可用。
- 匿名可执行区有 JIT/zygote/scudo 等白名单；OEM 差异仍可能误报，需要真机回归。
- 本地信号可被高级对手对抗。本 SDK 补充、而不是替代服务端风控、硬件证明或 Play Integrity。
