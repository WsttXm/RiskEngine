# RiskEngine

[English](./README.md)

Android 本地设备指纹采集、硬件信任根证明与运行环境风险检测（RASP）SDK。采用单一零依赖的纯 Java 11 + C++17 JNI 核心（`:riskengine-sdk`，零第三方运行时依赖、零 `<uses-permission>`）：在设备上采集信号、按延迟分层执行 **16 大收敛检测域（Detection Domains）**，通过确定性 **0–100 四维本地评分引擎**（`RiskScoringEngine` + 不可变本地 `RiskPolicy`）计算风险，并以拉取模式返回可解释的 `RiskReport` / 增量 JSON v2 / 离线可验签硬件信封 `SignedRiskEnvelope`（`v=2`），或以推送模式实时下发分层进度与运行期篡改告警。

核心 `:riskengine-sdk` **没有服务端、没有上报通道、不依赖 Play Integrity 或 SafetyNet**。结果只在本机产出（可选通过 `SignedRiskEnvelope` `v=2` 由宿主服务端执行 6 步离线验签）。本仓库收敛为精简的 3 模块单核布局：`:riskengine-sdk`、`:demo` 与 `:integration-test`。

当前开发版本为 `2.0.1-SNAPSHOT`（仅保留 64 位 Native ABI，详见 [ADR-0003](./docs/adr/0003-drop-32bit-abi-support.md)）。

## 它做什么，不做什么

| 会做 | 不会做 |
| --- | --- |
| 采集非敏感设备属性与应用范围标识哈希 | 采集原始 IMEI / IMSI / MAC / SSID / BSSID 或经纬度坐标 |
| 检测 Root、挂载异常、Hook 与 Native 自完整性、调试、应用完整性/重打包、多开/虚拟容器、网络 MitM/CA/VPN、位置模拟、屏幕远控/电诈/时间篡改、模拟器、云真机、ADB、自定义 ROM、TEE/KeyMint 篡改、高危应用/HMA 隐藏与跨源一致性 | 替代服务端风控、远程策略编排或 Play Integrity |
| 将主动攻击威胁（`RiskReport` / `ThreatListener`）与设备安全卫生态势（`DevicePosture` / `DeviceStateListener`）清晰分离，并将分层评估置信度（`confidencePercent`）与风险分彻底解耦 | 把检查失败静默当成“安全”，或因设备不支持某硬件或单个非关键探针超时而将干净真机降级为 `UNKNOWN` |
| 在 `0–100` 标准化标尺上按 4 个正交风险维度（`TAMPERING`、`PRIVILEGE`、`ENVIRONMENT`、`FRAUD_CONTEXT`）确定性评分，输出可审计 `ScoreBreakdown`、推荐 `RiskAction` 与宿主可定制本地 `RiskPolicy` | 依赖云端后端才能自定义阈值、维度权重或证据家族白名单 |
| 支持主线程零同步 IO 初始化（`init()` `< 5 ms`）、三阶段推送监控（`CRITICAL -> FAST -> POSTPONED`）与按需拉取（`collect` / `collectSync`） | 在 `init()` 调用线程同步阻塞 `SharedPreferences`、Keystore 或 `System.loadLibrary()` |
| 按采集场景（`CollectScene`）与本地策略（`RiskPolicy`）调整信号权重、计分与推荐处置动作 | 按场景关闭 Detector |
| 在 Demo 中本地展示（`0–100` 仪表盘、四维风险条、`RiskAction` 与 `ScoreBreakdown`）并复制脱敏报告 | 自动上传或云备份结果 |

高级对手可以篡改用户态信号。内核级 mount namespace 隐藏（例如完整 DenyList）无法在无硬件 attestation 的用户态保证识破。宿主应把本 SDK 作为多源决策的一部分。

## 能力概览（16 大收敛核心检测域 + 22 个默认 Collector）

| 方向 | 检测器 | 分层 | 主要信号 |
| --- | --- | :---: | --- |
| TEE 硬件信任根与 KeyMint | `tee_integrity` | `POSTPONED` | 零依赖根优先 OID `.17` 与规范 CBOR RKP OID `.30` 解析、内置 Google Hardware Attestation Root + 单调离线 CRL 底线、StrongBox→TEE `AttestationCapability`、5 向量 Native TrickyStore/Binder 探针（`tee_binder_probe.cpp`：maps、`PipeMemoryReader` 校验 `libbinder` `ioctl` GOT/16B 入口、三路 `BINDER_VERSION`、轮换顺序 Binder 蜜罐、Leaf DER）、借助 `bindIsolatedService` 的 Keystore2 `Domain.APP` vs `Domain.GRANT` 跨 UID 链分裂、API 31+ `generateKey` 尾包 `TAG_USER_ID`、API 35+ Post-Processing 差异、覆写双读反缓存陷阱、StrongBox 约束及 VINTF KeyMint HAL / `OperationErrorPath`（含三星/小米 MTK 豁免） |
| 高危应用与 HMA 隐藏对抗 | `threat_apps` | `POSTPONED` | 不可变宿主策略 `ThreatAppPolicy` + 10+ 官方发布证书 SHA-256 库（KernelSU / KSU-Next / SukiSU / Magisk / APatch / HideMyApplist / HMA-OSS / LSPosed / GameGuardian / LuckyPatcher / Shizuku）、v2/v3/v3.1 签名轮换谱系、`nativeLibraryDir` 守护载荷（`libksud.so`/`libapd.so`/`libmagisk.so`）、公开 Manifest XML `android:zygotePreloadName`，以及全代际 HMA/Thanox 行为侧信道：`disposable_child` 内 `getpriority(PRIO_USER)` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`、跨用户 `MATCH_ANY_USER` 异常抑制、有序广播 `resultTo`/`isOrderedBroadcast` 自检对照、API 35+ `PermissionService` 差集（1s 预算截断 -> `PARTIAL`）与精确 `Thanox` `IThanos` `dropbox` Binder 核验（`root_fw` 去重 + 独立 `hma_hiding` 家族） |
| 应用完整性与来源 | `app_integrity` | `CRITICAL` | 宿主硬编码预期包名校验、Java APK v2/v3/v3.1 签名谱系 + Native 原始 syscall 直读 `base.apk` ZIP/APK Signing Block 证书 SHA-256 交叉比对、API 30+ `getInstallSourceInfo()` 非官方来源检查、Release `ObfuscationSentinel` 混淆自检 |
| Hook 与 Native 自完整性 | `hook_framework` | `CRITICAL` + `POSTPONED` | Xposed/Frida（maps/FD `linjector` 与 `frida-gadget`/35ms 限时 D-Bus 端口 `27042–27045`/双源 `comm`+`status` 线程/Unix socket/匿名 `r-xp` ELF/`dl_iterate_phdr` vs `maps` 隐匿库差集/只读 `sigaction`）、`memfd` 私有 ELF、W+X 映射、ART 反射/JNI 槽位、事件驱动周期监控 `late_*` 锁存、COW 安全 `SelfIntegrityProbe`，以及 Stage 3 `ZygiskProbe`（Bionic `libc.so` `SHT_SYMTAB` `g_array` `atexit` 审计，兼容 LLVM SRA 与 API 30–37）与 `LsposedProbe`（Binder `0x5F4C5350`、Zygote GID 审计、全线程栈） |
| 反调试 | `debug` | `CRITICAL` | Native `OBF` 保护双路径 `TracerPid`（`/proc/self/status`、`/proc/<pid>/task/<pid>/status`、`/proc/self/task/*/status` 及差异检测）、`/proc/self/task/*/stat` 第 3 字段 `'t'`（定位最后一个 `')'` 防进程名干扰）、`wchan` `ptrace_stop`、JDWP 线程与 `@jdwp-control` 抽象 Socket、调试器连接、maps 调试路径、IDA 端口、`debuggable`（全场景默认提示性）、可选 `PR_SET_DUMPABLE(0)` |
| Root 与挂载 | `root`、`mount_analysis` | `FAST` + `POSTPONED` | Root 路径（含 `EACCES`/`ENOENT` 父目录可达性对照）、KernelPatch `sys_truncate`、KSU `reboot`/ioctl/时序侧信道（`disposable_child` 隔离）、SUSFS 探测、Netlink 权限泄漏、SELinux enforce/status/ABI/脏策略、`getdents64` 交叉检查；`mount_analysis` 新增 `statx(STATX_MNT_ID)` 对比 `mountinfo`、只读分区 `rw`、3 次 `fstatat` `st_mtime`、`statfs` `overlayfs`/`tmpfs` 与可选 `RiskIsolatedProbeService`（`isolatedProcess="true"`）跨进程挂载比对（`C9:stealth_root_with_unmount`） |
| 多开与虚拟容器 | `multi_instance` | `FAST` + `POSTPONED` | 零隐藏 API 反射：规范目录深度与 `uid / 100000` 精准区分（主用户 `0`/Work Profile `10..89` vs OEM 双开 `999`/`>=900`/`95`/`128..150` vs VirtualApp/ParallelSpace/BlackBox 嵌套容器）、`st_uid` 矛盾、多 APK maps、动态 `Proxy$` Binder 检测、`InstallTokenSanitizer`，以及 Stage 3 `disposable_child` `sacrificial_syscall_pack`（`openat2`/`statx`/`memfd_create`/`pidfd_open`/`renameat2` libc vs 原始内联 syscall） |
| 网络风险与 MitM | `network_risk` | `FAST` | 零 `<uses-permission>`：`AndroidCAStore` `user:` 用户根证书 + `cacerts-added`（Charles/Fiddler/mitmproxy/Burp）、运行时守卫 `TRANSPORT_VPN` 与 `/sys/class/net`（`tun*`/`ppp*`/`wg*`/`utun*`）降级回退、代理来源标签（绝不记录代理鉴权凭据）、主流代理工具官方发布证书 SHA-256 与只读 `/data/adb/modules/{box4,box_for_root}` |
| 位置模拟 | `location_risk` | `FAST` | 零位置权限、零经纬度 PII：本地 `Location` 契约金丝雀（getter/setter/field-mask/`reset()`/API 31+ `setMock`/`isMock` 往返一致性击穿 Xposed `LocationGetterHooker`），以及宿主已授权限时的缓存 `Location.isMock()` 与 `AppOpsManager` 模拟定位检查 |
| 屏幕远控、防电诈与时间 | `screen_and_fraud` | `FAST` | 虚拟/演示显示（`scrcpy`/`MediaProjection`/AnyDesk/TeamViewer）、非系统第三方无障碍服务、非内置虚拟输入设备、API 34/35 截录屏生命周期回调（权限守卫）、`AudioManager` 通话中 `ongoing_call`（`PAYMENT` 联合触发 `C10:vishing_fraud_combo`）、`Build.TIME`/`AUTO_TIME`/单调钟 `time_spoofing`；配套宿主可选 `RiskWindowGuard` |
| 模拟器 / 云真机 / ROM | `emulator`、`cloud_phone`、`custom_rom` | `FAST` + `POSTPONED` | QEMU/ranchu 与现代特征库（Waydroid/Cuttlefish/WSA/Corellium/LDPlayer 9/MuMu 12 与 AVF `>= 2` 联合防误报）、Native Bridge（`houdini`/`libnb`/`libndk_translation`）、虚拟 GPU（豁免真机 ANGLE-on-Vulkan）、零 SoC 硬件 `MediaCodec`、Stage 3 `SensorNoiseProbe`（`<= 200ms` 联合防误报）、`sched_yield` CV（仅 INFO）与 ARM64 `cntvct_el0` 时钟漂移；`custom_rom` 新增 `libstagefright.so` 符号与 `framework-res.apk` 多块设备映射（含 Pixel/HarmonyOS 豁免） |
| 调试桥 | `adb` | `FAST` | 1.5s 条件双采样去抖（干净设备零休眠）、`/dev/socket/adbd` 三态 `fstatat` + `@jdwp-control` + `init.svc.adbd=stopped` 隐藏矛盾（全场景 `HIGH`/7 可处置）；普通 USB/Wi-Fi ADB 默认提示性，`PAYMENT`/`DIAGNOSTIC` 升可处置 |
| 一致性与交叉规则 | `consistency`、`signal_correlation` | `FAST` + `POSTPONED` / 聚合器 | Treble 分区/Build 属性、升级版 `BootloaderProbe`（硬件 `RootOfTrust` 优先、`/proc/bootconfig`、21 项 Boot/AVB/三星 Knox 属性、VBMeta 空摘要 SHA-256/512 陷阱）、Bionic `prop_area` 空洞/serial/尾字节取证、PlayIntegrityFix 侧信道、ARM64 `MIDR_EL1`、3 源内核一致性、Widevine Java vs NDK `AMediaDrm`（动态 `dlopen("libmediandk.so")`）双源一致性，以及跨检测器规则（`C1`–`C8:spoofed_verified_boot`、`C9:stealth_root_with_unmount`、`C10:vishing_fraud_combo`） |
| 设备指纹 v2、卫生态势与硬件信封 | 22 个默认 Collector（`DIAGNOSTIC` 下 24 个） | `POSTPONED` | `FingerprintVersion`（`V1` 比特冻结 / `V2`）、`FingerprintStability`（`STABLE`/`OPTIMAL`/`UNIQUE`）、可插拔 `FingerprintHasher`、零权限 `codec_info`/`input_devices`/`security_posture`、结构化 `CpuInfoParser`、AndroidKeyStore `AES-256-GCM` 硬件绑定（`device_binding_broken`）、DirectBoot DE 存储、`DevicePosture`、`RiskReport.TrustTier`（`STRONG_HARDWARE`）及双模式硬件 `SignedRiskEnvelope`（`PERSISTENT_KEY` `<10ms` 与 `FRESH_ATTESTATION`） |

清单路径以 `riskengine-sdk/src/main/resources/lists/artifact_paths.ini` 为单源，Java `DetectionLists` 与 Native `detection_lists.h`（含编译期 FNV-1a 64 位属性白名单哈希表）均由其生成。

SDK **零声明 `<uses-permission>`** 且**零第三方运行时依赖**。Manifest 仅为已知模拟器、云真机、官方代理工具及精选 Root/HMA/高危工具包声明了 `<queries>` 包可见性（由 CI Gate 3 强制与 `artifact_paths.ini` 1:1 同步）。

## 环境要求

- JDK 17+（Java 11 源码/目标字节码）
- Android Gradle Plugin 8.13.1
- Compile SDK 36 / Target SDK 36 / Min SDK 30
- NDK `27.0.12077973`，CMake `3.22.1+`，C++17（`-fno-exceptions -fno-rtti`）
- Native ABI：`arm64-v8a`、`x86_64`（仅 64 位，16KB ELF `LOAD` 对齐，详见 [ADR-0003](./docs/adr/0003-drop-32bit-abi-support.md)；若宿主同时集成其他含 `.so` 的 SDK，请在宿主配置 `ndk { abiFilters += listOf("arm64-v8a") }` 或 `listOf("arm64-v8a", "x86_64")`，避免进程以 32 位模式运行导致 Native 探针降级）

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
./scripts/ci-verify.sh                             # 完整 CI 流水线：核心 SDK + Demo + 集成测试 + Gates 1–6 + L2 C++
./gradlew :riskengine-sdk:apiCheck --no-daemon     # 零插件 JDK 17 javap Public ABI 锁与 AAR/POM 纯度校验
./gradlew :demo:testDebugUnitTest --no-daemon      # Demo UI 0–100 评分与格式化单元测试
python3 -B scripts/test_verify_risk_envelope.py -v # SignedRiskEnvelope v=2 跨语言离线验签测试
./scripts/run-cpp-tests.sh                         # 100% 离线 L2 C++ 宿主机单元测试（CMake + CTest）
```

| 产物 | 路径 | 说明 |
| --- | --- | --- |
| SDK AAR | `riskengine-sdk/build/outputs/aar/riskengine-sdk-release.aar` | 宿主集成（2 个 64 位 ABI 全部 strip、无 `.comment`、仅导出 2 个 JNI 符号、16KB 对齐、单 ABI `.so <= 2000 KiB`、AAR `<= 4 MiB`、R8 Dex `< 2,500` 方法） |
| SDK Sources | `riskengine-sdk/build/intermediates/source_jar/release/release-sources.jar` | 发布用源码包 |
| Demo Debug APK | `demo/build/outputs/apk/debug/demo-debug.apk` | 临时 Debug 证书，仅供侧载 |
| Demo Release APK | `demo/build/outputs/apk/release/demo-release-unsigned.apk` | 已混淆；分发前需正式证书签名 |

Tag 发布（`v*.*.*`）会自动打包核心 `:riskengine-sdk` 发布产物（AAR / sources JAR / POM）、临时 Debug Demo APK 与 `SHA256SUMS`。临时 APK 不用于生产或应用商店；不同 Tag 的临时证书可能不同，签名冲突时请先卸载旧 Demo。

### 初始化、推送监控与按需采集

```java
// 可选：基于内置 CollectScene 预设叠加不可变本地 RiskPolicy 策略
RiskPolicy paymentPolicy = RiskPolicy.builder(CollectScene.PAYMENT)
        .dimensionWeight(RiskDimension.FRAUD_CONTEXT, 1.3)
        .actionThresholds(25, 55, 80)          // CHALLENGE / RESTRICT / BLOCK
        .highAction(RiskAction.BLOCK)
        .informationalOnlyFamily("adb")        // 保持可见但不计分（0 分 / ALLOW）
        .build();

RiskEngineConfig config = new RiskEngineConfig.Builder()
        .privacyProfile(PrivacyProfile.BALANCED)
        .collectTimeout(15000)
        .collectScene(CollectScene.STANDARD)
        .riskPolicy(paymentPolicy)                          // 可选本地策略覆盖
        .fingerprintVersion(FingerprintVersion.V2)          // 如需与 v1.x 比特一致请锁定 V1
        .fingerprintStability(FingerprintStability.OPTIMAL)
        .expectedPackageName("com.example.hostapp")
        .expectedSigningCertSha256Base64("<RELEASE_KEY_SHA256_BASE64>")
        .enableAntiDumpable(false)                          // 显式可选；见下方崩溃捕获组件说明
        .enableIsolatedProcessProbe(true)                   // 按需 isolatedProcess 跨进程挂载比对；宿主可用 tools:node="remove" 剥离
        .enablePeriodicMonitor(true)
        .build();

// 主线程零同步 IO（< 5 ms）：Native .so 加载、PR_SET_DUMPABLE、周期监控与 FingerprintStore 预热全部异步完成
RiskEngine.initIfNeeded(context, config);

// 1) 推送模式（推荐用于实时 RASP 防护与启动分层快速感知）：
RiskEngine.startMonitoring(
        new ThreatListener() {
            @Override
            public void onThreatDetected(ThreatEvent event) {
                Log.w("RiskEngine", "Threat [" + event.getScanTier() + "]: "
                        + event.getDetectorName() + " -> " + event.getRiskLevel());
            }

            @Override
            public void onRuntimeTamperDetected(ThreatEvent event) {
                Log.e("RiskEngine", "Runtime tamper: " + event.getDetails());
            }
        },
        new DeviceStateListener() {
            @Override
            public void onDeviceStateEvaluated(DevicePosture posture) {
                Log.i("RiskEngine", "Posture: keystore=" + posture.getKeystoreSecurityLevel()
                        + ", encrypted=" + posture.isStorageEncrypted());
            }
        },
        new ExecutionStateListener() {
            @Override
            public void onCriticalChecksFinished(TierReport critical) { /* app_integrity, debug, hook_framework（统一 0–100 标尺） */ }
            @Override
            public void onFastChecksFinished(TierReport fast) { /* 其余 11 个 FAST 检测域（统一 0–100 标尺） */ }
            @Override
            public void onPostponedChecksFinished(RiskReport fullReport) { /* 全量 Collector、tee_integrity、threat_apps 与聚合报告 */ }
        });

// 2) 拉取模式（按需触发完整采集，例如支付前核验）：
RiskEngine.collect(CollectScene.PAYMENT, new RiskEngineCallback() {
    @Override
    public void onSuccess(RiskReport report) {
        Log.d("RiskEngine", "Risk: " + report.getOverallRiskLevel()
                + ", Action: " + report.getRecommendedAction()
                + ", TrustTier: " + report.getTrustTier()
                + ", Score: " + report.getRiskScore() + " / " + report.getMaxRiskScore()
                + ", Confidence: " + report.getConfidencePercent() + "%"
                + ", Dims: " + report.getDimensionScores());
    }

    @Override
    public void onError(Throwable error) {
        Log.e("RiskEngine", "Collect failed", error);
    }
});
```

回调运行在 SDK 后台线程；更新 UI 时需切回主线程。`collectTimeout` 是整次请求共享的总时限，覆盖排队等待、Collector 与 Detector，而不是每个任务各自计时。默认超时 10 秒，合法范围 1–120,000 毫秒。

同步接口禁止在 Android 主线程调用：

```java
RiskReport report = RiskEngine.collectSync();
String json = RiskEngine.reportToJson(report);       // 不重复采集
String freshJson = RiskEngine.collectReportJson();   // 重新采集并序列化
```

可选主动窗口防护助手（绝不自动修改宿主窗口，由宿主在敏感页面按需调用）：

```java
// 在登录 / 支付 / 输密等高敏 Activity 中按需启用
RiskWindowGuard.enableScreenCaptureProtection(activity, true);   // WindowManager.LayoutParams.FLAG_SECURE
RiskWindowGuard.enableOverlayProtection(activity, true);         // API 31+ setHideOverlayWindows(true)
RiskWindowGuard.enableTouchObscuredFilter(rootView, true);       // View.setFilterTouchesWhenObscured(true)
```

> **关于 `enableAntiDumpable(true)` 的兼容性说明**：开启后会在 Native 后台线程调用 `prctl(PR_SET_DUMPABLE, 0)` 阻断非 Root 进程 `ptrace` 附加。该选项默认 `false`，因为 `dumpable=0` 可能影响依赖 `ptrace` 的三方崩溃收集组件（如旧版 Breakpad / Bugly）；请在验证自家崩溃监控组件兼容后再开启。

`init` 拒绝重复初始化；多入口应用使用原子的 `initIfNeeded`。调用 `RiskEngine.stopMonitoring()` 可解绑推送监听而不销毁 SDK；不再使用时调用 `RiskEngine.shutdown()`：会推进生命周期代次、取消任务、注销 `AppLifecycleObserver`、清空生命周期状态，并在释放 `lifecycleLock` 之后唤醒并等待 Native 周期复检线程退出；旧代次结果不会交付。

SDK AAR 自身不 minify；宿主 R8 使用附带的 `consumer-rules.pro`（保留全部公开 API、`RiskPolicy`、`RiskDimension`、`RiskAction`、`ScoreBreakdown`、`EvidenceItem`、`DevicePosture`、`ThreatEvent`、`TierReport`、`SignedRiskEnvelope` 与 `NativeMonitorDispatcher.onNativeThreatDetected`，并**刻意不保留 `ObfuscationSentinel`** 以便 `AppIntegrityDetector` 在 Release 构建中自检混淆是否生效）。

## 宿主云备份排除、隔离进程服务剥离与 DirectBoot 配置

`RiskEngine` 内置按需拉起的 `android:isolatedProcess="true"` 辅助服务（`RiskIsolatedProbeService`），供 Stage 3（`POSTPONED`）的 `mount_analysis` 跨进程识破 Shamiko/DenyList 选择性卸载隐藏（`C9:stealth_root_with_unmount`），并在 `finally` 中立即 `unbindService()` 绝不常驻内存。若宿主严格要求单进程，可关闭 `.enableIsolatedProcessProbe(false)` 并在宿主 `AndroidManifest.xml` 中剥离该服务（`IsolatedProbeClient` 自动优雅降级为 `UNAVAILABLE`）：

```xml
<service
    android:name="com.wsttxm.riskenginesdk.process.RiskIsolatedProbeService"
    tools:node="remove" />
```

`FingerprintStore` 将加密连续性状态保存在设备保护存储（DE）的 `riskengine_fp` SharedPreferences 中，确保 `directBootAware` 宿主在解锁前初始化零崩溃（仅在 `UserManager.isUserUnlocked() == true` 时执行一次性 CE→DE 迁移）。

宿主应用**必须**在备份规则中排除 `riskengine_fp.xml`，避免数据被云备份或换机迁移到另一台设备后触发误报 `device_binding_broken`：

**`res/xml/data_extraction_rules.xml`（Android 12 / API 31+）：**

```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="riskengine_fp.xml" />
        <exclude domain="device_sharedpref" path="riskengine_fp.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="riskengine_fp.xml" />
        <exclude domain="device_sharedpref" path="riskengine_fp.xml" />
    </device-transfer>
</data-extraction-rules>
```

**`res/xml/backup_rules.xml`（Android 11 / API 30）：**

```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <exclude domain="sharedpref" path="riskengine_fp.xml" />
    <exclude domain="device_sharedpref" path="riskengine_fp.xml" />
</full-backup-content>
```

## 正式发布签名与 Google Android Developer Verification（ADI）检查清单

启用 `AppIntegrityDetector` 上架生产环境前，请按以下清单逐项核对：

1. **提取全部正式发布签名证书的 SHA-256 Base64 摘要**（覆盖 Play App Signing 密钥、官网/国内渠道独立签名密钥，以及 APK v3/v3.1 密钥轮换期的新旧证书）：
   ```bash
   # 从已签名的 Release APK 直接提取（推荐，与端上最终校验对象一致）
   apksigner verify --print-certs app-release.apk \
     | awk -F': ' '/certificate SHA-256 digest/ {print $2}' \
     | xxd -r -p | openssl base64

   # 或从 Play Console -> App Integrity 下载的 deployment_cert.der 提取
   openssl x509 -in deployment_cert.der -inform DER -outform DER \
     | openssl dgst -sha256 -binary | openssl base64
   ```
2. **在 `RiskEngineConfig.Builder` 中钉扎包名、证书与可信商店白名单**：
   - `.expectedPackageName("com.example.hostapp")`（请写死字面量，勿直接传可能被 Hook 的 `context.getPackageName()`）。
   - `.expectedSigningCertSha256Base64("<play_cert_b64>", "<direct_channel_cert_b64>")`。
   - 若存在定制渠道或企业分发，通过 `.trustedInstallerPackages(...)` 覆盖或补充内置官方商店列表（Google Play、华为 AppGallery、小米、OPPO、vivo、三星、荣耀）。
3. **Google Android Developer Verification（ADI）所有权注册**：若应用接入 Google ADI 验证，请在宿主模块打入已签名的 `assets/adi-registration.properties`，并核对注册证书与 Play App Signing / 分发 APK 签名及 `expectedSigningCertSha256Base64` 完全一致。
4. **确认 Release 混淆已开启**：确保宿主 Release 构建开启 `isMinifyEnabled = true`，且**不要**手动添加 `-keep class com.wsttxm.riskenginesdk.detector.ObfuscationSentinel`（或宽泛的 `-keep class com.wsttxm.riskenginesdk.**`），否则会触发 `release_unobfuscated` 告警。

## 采集场景与本地策略引擎（`RiskPolicy`）

每次采集仍运行全部已启用的 Detection Domain。聚合管线先应用生效的本地 `RiskPolicy`（基于内置 `CollectScene` 预设叠加宿主覆盖项），再执行顺序无关的证据家族取最大值（family-max）去重、跨检测域关联规则与标准化评分（`applyPolicy -> dedupeFamilies -> correlate -> RiskScoringEngine`）。

| 场景 | 行为 | 默认 `HIGH` 处置动作 |
| --- | --- | :---: |
| `STANDARD` | 默认划分。ADB、弱模拟器、社区 ROM、单纯 Bootloader 解锁提示、OEM 双开、模拟定位 AppOp/缓存 mock、`ongoing_call`、代理工具证书/模块、仅 `debuggable` 等为提示性（`0` 分，`ALLOW`） | `RESTRICT` |
| `LOGIN` | 模拟器、云真机、OEM 双开、缓存/AppOp 模拟定位以及确认的 Bootloader 解锁 / 橙色启动状态转为可处置（`MEDIUM`/`HIGH`）；激活 `C7` | `RESTRICT` |
| `PAYMENT` | 在 `LOGIN` 基础上，ADB、非官方安装来源与代理工具证书/模块转为可处置；投屏/第三方无障碍提权至 `HIGH`；`ongoing_call` 叠加屏幕控制触发 `C10:vishing_fraud_combo`；双重 Bootloader/橙色启动或硬件确认启动异常升为 `HIGH` | `BLOCK` |
| `DIAGNOSTIC` | 除「仅 `debuggable` 标志」外，全部非覆盖信号可处置，便于本地诊断 | `RESTRICT` |

可通过 `RiskPolicy.builder(CollectScene)` 无后端定制本地风控策略，并通过 `RiskEngineConfig.Builder.riskPolicy(RiskPolicy)` 注入：

- **`dimensionWeight(RiskDimension, double)`**：调节 4 个风险维度的权重系数（有限值 `>= 0.0`；设为 `0.0` 可在综合分中屏蔽该维度）。
- **`actionThresholds(challenge, restrict, block)`**：覆盖 `0–100` 动作阈值（满足 `1 <= challenge < restrict < block <= 100`，默认 `30 / 60 / 85`）。
- **`highAction(RiskAction)`**：覆盖 `HIGH` 等级对应的推荐动作（例如在 `RESTRICT` 与 `BLOCK` 间切换）。
- **`allowlistFamily(family)` / `informationalOnlyFamily(family)` / `familyMultiplier(family, double)`**：将指定证据家族加白（0 分、不触发关联规则与 Hard Trigger）、降为仅提示（保留证据但 0 分 / `ALLOW`）或设置自定义强度倍率。
- **`suppressHardTrigger(codeOrPrefix)`**：按精确代码或前缀选择性抑制 Hard Trigger（如 `"inline_hook:"`）。

配置默认场景：`RiskEngineConfig.Builder.collectScene(...)`。单次调用可通过 `collect(scene, callback)` / `collectSync(scene)` 覆盖。

## 企业级 0–100 四维评分引擎与结果语义

单个 Collector 或 Detector 失败时不会被静默转换为安全结果。同时，合法的平台/硬件缺失（`UNSUPPORTED` / `EMPTY`）单独计入 `unsupportedCheckCount`，绝不会把纯净真机从 `SAFE` 降级为 `UNKNOWN`。

| 状态 | 含义 |
| --- | --- |
| `CollectorResult.Status.SUCCESS` | 至少采集到一个可用值（`system_properties_native` 部分属性受 SELinux 限制但仍有可读项时记录 `partial_errors` 并保持 `SUCCESS`） |
| `CollectorResult.Status.EMPTY` | 采集正常结束但无值；计入 `unsupportedCheckCount`，不视为覆盖失败 |
| `CollectorResult.Status.ERROR` | Collector 执行失败或超出本次请求可用时间；降低覆盖率与置信度 |
| `CollectorResult.Status.UNSUPPORTED` | 当前设备或平台不提供该信号；计入 `unsupportedCheckCount`，不视为覆盖失败 |
| `DetectionStatus` | 风险展示：`NORMAL` / `WARNING` / `DANGER` / `UNKNOWN` |
| `DetectionExecutionStatus` | 执行：`SAFE` / `RISK` / `PARTIAL` / `UNAVAILABLE` / `DISABLED` / `TIMEOUT` / `ERROR` |

### 四大正交风险维度（21 个 Evidence Family）

`RiskScoringEngine` 为完整 `RiskReport` 与阶段 `TierReport` 提供统一的 `0–100` 标准化评分，将全部 21 个证据家族确定性映射到 4 个正交 `RiskDimension`：

| `RiskDimension` | 映射的证据家族（共 21 族） |
| --- | --- |
| `TAMPERING`（6） | `app_tamper`、`hook_integrity`、`frida`、`xposed`、`debugger`、`tee_tamper` |
| `PRIVILEGE`（8） | `root_fw`、`boot_integrity`、`prop_tamper`、`hw_spoof`、`hma_hiding`、`device_binding`、`custom_rom`、`adb` |
| `ENVIRONMENT`（3） | `emulator`、`virtual_container`、`threat_app` |
| `FRAUD_CONTEXT`（4） | `network_mitm`、`location_spoof`、`screen_control`、`fraud_context` |

### 确定性三阶段评分管线

1. **顺序无关家族取最大值（Family-Max）**：按 Evidence Family 聚合可处置检出项，彻底消除检测器注册顺序依赖，每个家族取单源最强内部强度（内部 `1..10` 平滑映射至概率强度 `0.10..0.92`）。同家族其他检测器以 `deduped:corroborating_evidence` 保留完整取证可见性，既不重复计分也不会压制强信号。
2. **有界多源印证加权（Corroboration Lift）**：同一可处置证据家族在 `>= 2` 个独立观测层（如 `JAVA + NATIVE`、`NATIVE + ISOLATED`、`HARDWARE`）或 `>= 2` 个不同 Detection Domain 得到相互印证时，给予有界加权 `+0.06`（上限封顶 `0.95`）。
3. **维度内 Noisy-OR、纯弱信号封顶与 Hard Trigger 保底**：
   - 维度内多家族通过 Noisy-OR（`1 - product(1 - p_i)`）融合并映射至 `0–100`；若某维度内全部可处置信号均为 `LOW`（无 `MEDIUM` 及以上），该维度得分强制封顶 `<= 35`。
   - 四大加权维度与跨检测域关联规则（`C1`–`C10`）经加权 Noisy-OR 融合得到综合 `0–100` 分。
   - 权威 Hard Trigger 由 `RiskScoringEngine.extractHardTriggers(...)` 单点解析并暴露于 `RiskReport.getHardTriggers()`。任意未被 `RiskPolicy` 抑制的 Hard Trigger 直接锁定 `RiskLevel.DEADLY` 与 `RiskAction.BLOCK`，并将综合分保底至 `95–100`（`min(100, 95 + 2 * (count - 1))`）。

### 综合等级、`RiskAction` 与分层评估置信度

| 综合等级 | 默认分档（`0–100`） | 默认推荐 `RiskAction` | 条件 |
| --- | :---: | :---: | --- |
| `SAFE` | `0` | `ALLOW` | 分数 `0`、无提示/风险信号、无 `CRITICAL` 域失败且 `confidencePercent >= 70` |
| `LOW` | `1–29`（或纯提示性 `0` 分） | `ALLOW` | 分数 `1–29`，或仅有提示性信号（`score = 0`） |
| `MEDIUM` | `30–59` | `CHALLENGE` | 分数 `>= challengeThreshold`（默认 `30`） |
| `HIGH` | `60–84` | `RESTRICT`（`PAYMENT` 收紧为 `BLOCK`） | 分数 `>= restrictThreshold`（默认 `60`） |
| `DEADLY` | `85–100` | `BLOCK` | 分数 `>= blockThreshold`（默认 `85`），或命中任意有效 Hard Trigger（保底 `95–100`） |
| `UNKNOWN` | `0` | `REVIEW` | 分数为 `0` 且（至少 1 个 `CRITICAL` 检测域失败/超时、加权 `confidencePercent < 70` 或全部检测器不可用） |

**分层评估置信度（`confidencePercent`，`0–100%`）** 按执行层级加权计算完成度（`CRITICAL = 3`、`FAST = 2`、`POSTPONED = 1`、Collector = `1`）并与 `riskScore` 解耦：单个非关键（`FAST`/`POSTPONED`）探针超时不会把干净真机压成 `UNKNOWN`，而是保持 `SAFE` 并诚实输出 `ReportStatus.PARTIAL` 与下降后的 `confidencePercent`；仅在 `CRITICAL` 域失败、加权置信度 `< 70%` 或全不可用时进入 `UNKNOWN`（建议 `RiskAction.REVIEW`）。

权威 Hard Trigger 包括：GOT/inline hook 与自完整性篡改（`inline_hook:`、`got_hook:`、`text_mismatch`、`late_text_mismatch`、`jni_self_hook:`、`fn_prologue_hook:`、`late_wx_self`、`memfd_private_elf:`、`late_memfd_elf`、`art_native_cleared:`）、高置信度 Frida PID/端口/maps/FD（`frida_pid_port`、`maps:frida`、`maps:gadget`、`fd:linjector`、`late_frida_fd`）、应用重打包（`apk_sig_mismatch`、`pkg_name_mismatch`、`apk_native_java_sig_conflict`）、VBMeta 空摘要伪造陷阱（`vbmeta_empty_input_digest`）、TEE 硬件证明篡改（`tee_grant_chain_split`、`tee_binder_ioctl_hook`、`tee_keybox_revoked`）以及关联规则 `C3:`、`C6:`、`C8:`。

`RiskReport.getTrustTier()` 提供综合可信层级：`STRONG_HARDWARE`（`SAFE` + 硬件 Keystore + 磁盘加密 + 锁屏安全）、`LOCAL_VERIFIED`（`SAFE`/`LOW` 且覆盖完整）、`DEGRADED`（`MEDIUM`/`UNKNOWN`/覆盖不完整）或 `COMPROMISED`（`HIGH`/`DEADLY`）。

`maxRiskScore` 与 `displayThresholdMaximum` 均统一为 `100`，与 `RiskReport`、`TierReport` 及 Demo 仪表盘保持一致。

## 输出、增量 JSON v2 与硬件签名信封 `v=2`

`RiskReport` 在聚合后不可变，主要字段：

| 字段 | 说明 |
| --- | --- |
| `fingerprint` | 聚合后的设备指纹（各 Collector 结果，含 `fingerprint_id`） |
| `fingerprintId` | 硬件/系统/易变层/复合 ID、`version`（`V1`/`V2`）、`stability`、`anchorDriftCount` 与分桶摘要；构建失败时为 `null` |
| `devicePosture` | 非威胁安全卫生态势（`hasPasscode`、`storageEncrypted`、`storageEncryptionStatus`、`keystoreLevel`、`biometricStatus`、`devMode`、`adbEnabled`、`systemVpn`、`unofficialStore`、`lockscreenOrBiometricReset`） |
| `trustTier` | `STRONG_HARDWARE` / `LOCAL_VERIFIED` / `DEGRADED` / `COMPROMISED` |
| `detections` | 检测结果（`scanTier`、向后兼容的 `details[]`、`evidenceFamilies[]` 以及一等公民不可变 `List<EvidenceItem>`） |
| `overallRiskLevel` | 综合风险等级（`SAFE` / `LOW` / `MEDIUM` / `HIGH` / `DEADLY` / `UNKNOWN`） |
| `recommendedAction` | 本地推荐处置动作 `RiskAction`（`ALLOW` / `CHALLENGE` / `RESTRICT` / `BLOCK` / `REVIEW`） |
| `riskScore` / `maxRiskScore` / `displayThresholdMaximum` | 标准化 `0–100` 综合风险分（`maxRiskScore = 100`，`displayThresholdMaximum = 100`） |
| `dimensionScores` | `Map<RiskDimension, Integer>`（`TAMPERING`、`PRIVILEGE`、`ENVIRONMENT`、`FRAUD_CONTEXT` 四维 `0–100` 子分） |
| `scoreBreakdown` | 可审计 `ScoreBreakdown`（`preFloorScore`、`finalScore` 及逐项 `Entry`：`FAMILY`、`CORROBORATION_LIFT`、`CORRELATION_RULE`、`HARD_TRIGGER_FLOOR`） |
| `hardTriggers` | 排序去重的权威 Hard Trigger 列表（与 `SignedRiskEnvelope` `v=2` 1:1 同源） |
| `confidencePercent` | 按检测层级加权的评估置信度（`0–100%`），与 `riskScore` 解耦 |
| `warningCount` / `dangerCount` / `unknownCount` | 各状态计数（含提示性） |
| `reportStatus` | `COMPLETE` / `PARTIAL` / `UNAVAILABLE` |
| `checkCount` / `completedCheckCount` / `unsupportedCheckCount` / `coveragePercent` | Detector + Collector 覆盖；`UNSUPPORTED`/`EMPTY` 独立计入 `unsupportedCheckCount` |
| `collectScene` / `riskPolicy` | 本次实际使用的场景与生效的不可变 `RiskPolicy` |
| `timestampMs` / `sdkVersion` | 采集时间与 SDK 版本 |

`EvidenceItem` 包含 `code`、`primarySource`、`mergedSources`、`location`、`value`、`evidenceFamily` 与 `rank`。`DataAggregator` 会自动将同 `(code, location)` 的 `JAVA` 与 `NATIVE` 证据合并为 `mergedSources = {JAVA, NATIVE}` 并保留最高 `Rank`。

JSON 由 `RiskReportJsonSerializer` 零额外依赖生成，遵循**严格增量 JSON v2 契约**（顶层输出 `schemaVersion: 2`、`riskScore`、`maxRiskScore: 100`、`displayThresholdMaximum: 100`、`confidencePercent`、`recommendedAction`、`hardTriggers[]`、`dimensionScores{}`、`scoreBreakdown[]`、`trustTier`、`devicePosture`、`unsupportedCheckCount`、`fingerprintId`，`detections[]` 输出 `scanTier`、`evidenceFamilies[]`、`evidenceItems[]`），完全保持既有字段向后兼容。

`SignedRiskEnvelope` 升级至规范载荷协议 **`v=2`**（`SignedRiskEnvelope.PROTOCOL_VERSION = 2`），由 17 个递归键排序 UTF-8 字段构成——在 `0–100` `score` 与权威 `hardTriggers` 基础上新增 `action`、`confidence` 与四维 `dimensions`（`TAMPERING`/`PRIVILEGE`/`ENVIRONMENT`/`FRAUD_CONTEXT`），使用硬件 ECDSA P-256 签名。服务端 6 步离线验签规范与零依赖 Python 验签器（`scripts/verify_risk_envelope.py`）见 [docs/Signed_Envelope_Verification.md](./docs/Signed_Envelope_Verification.md)。

## 分层指纹 v2、硬件绑定与本地存储

`report.getFingerprintId()` 返回受显式契约约束的 `FingerprintId`：

- **`FingerprintVersion`**：`V1`（与 v1.x 100% 比特一致冻结的 13 硬件 + 11 系统字段算法，由黄金向量回归测试锁定）与 `V2`（默认：新增 `codec_info`、`input_devices`、`security_posture` 与剔除 `BogoMIPS`/`cpu MHz` 的结构化 `CpuInfoParser`）。`LATEST` 已标注 `@Deprecated`，引导宿主显式锁定版本。
- **`FingerprintStability`**：`STABLE`（仅物理硬件桶）、`OPTIMAL`（默认：硬件 + 系统 + 新增零权限维度）、`UNIQUE`（叠加已授权易变标识）。
- **`FingerprintHasher`**：可插拔摘要接口（默认 UTF-8 + SHA-256）。

各层混入 32 字节随机安装盐，并经不可导出的 `AndroidKeyStore` `AES-256-GCM` 密钥（优先 `StrongBox`，不可用自动降级 `TEE`）加密存于设备保护（DE）私有 `riskengine_fp` SharedPreferences。`FingerprintStore` 分离**不可变初始锚定基线**（`anchor_hw` / `anchor_hw_buckets`，自动迁移 v1 `last_hw`）与可变最近观测（`last_hw` / `last_sys` + `drift_count`）：

- 硬件漂移递增 `drift_count` 并持续上报 `HARDWARE_CHANGED`（`fingerprint_continuity`，`MEDIUM`/4），绝不覆盖初始锚点。
- 若本地密文文件存在但 `AndroidKeyStore` 包装密钥缺失或 GCM 验签失败（`AEADBadTagException`），明确产出 **`device_binding_broken`**（`fingerprint_continuity`，`HIGH`/7 可处置），精准识破 Root 跨机克隆应用数据或篡改 XML。
- 硬件哨兵密钥捕获 `KeyPermanentlyInvalidatedException` 时置位 `devicePosture.lockscreenOrBiometricReset = true`。
- 宿主可通过 `RiskEngine.resetFingerprintBaseline()` 显式重锚基线（保留安装盐）。

`isHardwareLayerReliable()` 的准确判定条件为：`hardwareId` 非空、`getHardwareCoveragePercent() >= 50` 且至少命中 `gpu`/`cpu`/`sensor` 中的 2 个核心物理桶。

## 隐私

| 档位 | 默认标识采集 |
| --- | --- |
| `MINIMAL` | 不采 Android ID、Boot ID、Widevine |
| `BALANCED` | 仅 Android ID 的应用范围 SHA-256 哈希（默认） |
| `DIAGNOSTIC` | 另加 Boot ID、Widevine 的应用范围哈希 |

`collectAndroidId` / `collectBootId` / `collectDrmId` 可覆盖档位。哈希输入包含宿主包名，因此是确定性的应用范围假名，**不是**加密、匿名化或不可逆性保证。报告从不输出原始 Android ID、DRM ID、Boot ID、IMEI、IMSI、Wi-Fi/Bluetooth MAC、SSID、BSSID、代理鉴权凭据或经纬度坐标。

硬件 Collector 和分层 ID 构建在所有隐私档位下运行；`MINIMAL` 仅关闭上述三类标识，不关闭硬件指纹或本地连续性存储。存储不可用时回退到进程内随机生成的临时盐（不使用固定常量盐），仅在本次进程生命周期有效。

## Demo

`demo` 模块在保留 Fluid Design 流体视觉语言的基础上完成了 v2.0 增量评分升级：

- **隐私合规同意前置闸门**：首次调用 `RiskEngine.initIfNeeded()` 前弹出隐私声明弹窗并将状态持久化至 Demo `SharedPreferences`；用户拒绝时 SDK 保持未初始化状态。
- **0–100 三阶段渐进 `RiskGaugeView` 与四维总览卡**：通过 `RiskEngine.startMonitoring(...)` 驱动检测，接入 `ExecutionStateListener` 在主线程无阻塞平滑绘制对齐 `0–100` 标尺的 `CRITICAL -> FAST -> POSTPONED` 三段式进度弧，同步展示推荐 `RiskAction` 胶囊标签、评估置信度（`confidencePercent`）、四正交维度子分条（`TAMPERING`、`PRIVILEGE`、`ENVIRONMENT`、`FRAUD_CONTEXT`）、Hard Trigger 徽章以及可点击展开的 `ScoreBreakdown` 逐项归因详情抽屉。
- **16/16 收敛检测域全量呈现**：`ReportFormatter` 直接消费 SDK 一等公民 `EvidenceItem`、`DevicePosture` 与 `ScoreBreakdown`，完整展示全部 16 大 RASP 检测域（含 `tee_integrity`、`threat_apps` 与 HMA 侧信道、`C8`–`C10` 及 Widevine 一致性）与 22/24 个 Collector。
- **分层指纹分桶与连续性卡片**：展示分层 ID、`FingerprintVersion`（`V1`/`V2`）、`FingerprintStability`（`STABLE`/`OPTIMAL`/`UNIQUE`）、`anchorDriftCount`、`device_binding` 硬件绑定状态、5 大物理硬件分桶摘要（`gpu`/`cpu`/`sensor`/`camera`/`memory_battery`）以及带二次确认弹窗的 `RiskEngine.resetFingerprintBaseline()` 按钮。
- **实时威胁与态势推送流抽屉（`ThreatStreamDrawer`）**：顶部悬浮「推送流」胶囊入口，实时呈现 `ThreatListener`（高亮运行期篡改事件与 HUD 弹窗提示）及 `DeviceStateListener` 安全态势快照。
- 环境检测优先排列风险项，「需关注」仅统计可处置 Warning/Danger，`UNKNOWN` 绝不误渲染为安全，复制报告严格脱敏（含 `0–100` 分值、`RiskAction`、置信度与四维子分），且禁用云备份与设备迁移。

## 公开 API

| API | 说明 |
| --- | --- |
| `RiskEngine.init(Context, RiskEngineConfig)` | 非阻塞初始化；重复调用抛出 |
| `RiskEngine.initIfNeeded(Context, RiskEngineConfig)` | 原子按需初始化；返回本次是否执行了初始化 |
| `RiskEngine.startMonitoring(ThreatListener, DeviceStateListener, ExecutionStateListener)` | 启动三阶段推送监控（`CRITICAL -> FAST -> POSTPONED`）与实时 Native/截录屏告警 |
| `RiskEngine.stopMonitoring()` | 注销推送监听器，不销毁 SDK |
| `RiskEngine.collect(RiskEngineCallback)` | 异步拉取采集 |
| `RiskEngine.collect(CollectScene, RiskEngineCallback)` | 按场景异步拉取采集 |
| `RiskEngine.collectSync()` / `collectSync(CollectScene)` | 同步拉取采集；禁止主线程 |
| `RiskEngine.collectSignedEnvelopeSync(CollectScene, byte[], EnvelopeMode)` | 完整采集并签发离线可验证硬件风控信封 `SignedRiskEnvelope` `v=2`（`PERSISTENT_KEY` `<10ms` 或 `FRESH_ATTESTATION`，无硬件时显式 `SOFTWARE_FALLBACK`） |
| `RiskEngine.collectReportJson()` | 完整采集并序列化增量 JSON v2 |
| `RiskEngine.reportToJson(RiskReport)` | 序列化已有报告，不重复采集 |
| `RiskEngine.resetFingerprintBaseline()` | 显式清空/重锚不可变硬件指纹基线（保留安装盐） |
| `RiskEngine.getReportJson()` | 已弃用，等价于 `collectReportJson()` |
| `RiskEngine.shutdown()` | 取消任务、注销生命周期监听并在 `lifecycleLock` 外等待 Native 监控线程退出 |
| `RiskPolicy` / `RiskPolicy.Builder` | 基于 `CollectScene` 预设的不可变本地策略引擎：支持维度权重、动作分数阈值、`highAction`、家族模式/倍率（`ALLOWLIST` / `INFORMATIONAL_ONLY`）与 Hard Trigger 抑制 |
| `RiskDimension` / `RiskAction` / `ScoreBreakdown` | 四正交风险维度（`TAMPERING`、`PRIVILEGE`、`ENVIRONMENT`、`FRAUD_CONTEXT`）、五级推荐动作（`ALLOW`、`CHALLENGE`、`RESTRICT`、`BLOCK`、`REVIEW`）与逐项可解释评分归因 |
| `ThreatAppPolicy.Builder` | 不可变宿主策略构建器：自定义高危包名、自定义证书 SHA-256、高危权限组合与 HMA 探针开关 |
| `RiskWindowGuard.enableScreenCaptureProtection` / `enableOverlayProtection` / `enableTouchObscuredFilter` | 宿主显式可选的窗口防截录屏/防覆盖/防点击劫持助手 |
| `RiskEngineConfig.Builder` | `debugLog`、`collectTimeout`、`privacyProfile`、`collectScene`、`riskPolicy`、`collectAndroidId`/`BootId`/`DrmId`、`fingerprintVersion`、`fingerprintStability`、`fingerprintHasher`、`expectedPackageName`、`expectedSigningCertSha256Base64`、`trustedInstallerPackages`、`additionalThreatPackages`、`threatAppPolicy`、`enableAntiDumpable`、`enablePeriodicMonitor`、`enableIsolatedProcessProbe`、`enableTeeAttestation`、`enableThreatAppDetection` 与各域 `enable*` 开关（`consistency` 始终注册） |

## 仓库模块（单核三模块架构）

RiskEngine v2.0.0 收敛为单一零依赖核心 SDK（详见 [ADR-0001](./docs/adr/0001-single-core-sdk-without-extension-submodules.md)）：

| 模块 | 技术栈 | 核心职责 |
| --- | --- | --- |
| `:riskengine-sdk` | 纯 Java 11 + C++17（零三方依赖、零 `<uses-permission>`） | 可发布核心 AAR，承载全部 16 大收敛检测域、22/24 个 Collector、`0–100` 四维 `RiskScoringEngine`、不可变 `RiskPolicy`、分层指纹 v2 与 `SignedRiskEnvelope` `v=2` |
| `:demo` | Java + AndroidX Material | Fluid Design 流体界面本地诊断控制台，展示 `0–100` 仪表盘、四维子分条、`RiskAction`、`ScoreBreakdown`、指纹连续性与实时 `ThreatStreamDrawer` |
| `:integration-test` | Android Instrumentation | 独立消费 `riskengine-sdk-release.aar` 二进制产物，在 API 30 / 34 / 36 KVM 模拟器矩阵执行 L3 端到端验证 |

## 可执行工程治理、能力边界与加固

- **6 大自动化 CI 静态治理门禁**（集成于 `scripts/ci-verify.sh` 与 `.github/workflows/ci.yml`）：
  1. **Gate 1（`scripts/check-evidence-records.py`）**：动态解析 `DetectorRegistry` 校验 `docs/evidence/*.md` 1:1 完整覆盖（16/16 检测域，每份均含 7 项必填契约章节）。
  2. **Gate 2（`scripts/check-elf-hardening.sh` + `scripts/check-jni-and-dex.py`）**：64 位双 ABI（`arm64-v8a`、`x86_64`）ELF 加固校验（仅 2 个 JNI 导出符号、16KB `LOAD` 对齐、strip 无 `.comment`、`.so <= 2000 KiB`、AAR `<= 4 MiB`）、41/41 JNI 名称+签名精确 1:1 对齐及 Release R8 Dex `< 2,500` 方法数上限。
  3. **Gate 3（`scripts/check-single-source-sync.py`）**：零 `<uses-permission>`、52 项 `<queries>` 与 `artifact_paths.ini` + `NetworkRiskDetector` 精确 1:1、`DetectionLists.java` xorshift32 字节级反解码比对与文档版本一致。
  4. **Gate 4（`scripts/check-public-api.py` / `:riskengine-sdk:apiCheck`）**：零插件 JDK 17 `javap` Public ABI 锁（`riskengine-sdk/api/riskengine-sdk.api`）、AAR `classes.jar` 纯度与零依赖 POM 校验。
  5. **Gate 5（`scripts/check-boundary-guards.py`）**：核心 Java/C++ 反射白名单与降级说明审计（封禁 D66 受限隐藏 API 反射）及禁止按 UI 展示文案分支判定。
  6. **Gate 6（`.github/workflows/refresh-attestation-roots.yml`）**：每周定时 + 手动 dry-run 核验 Google Hardware Attestation Root 与单调 CRL 底线漂移。
- **L1 + L2 + L3 三层测试金字塔**：
  - **L1（JVM）**：核心 `:riskengine-sdk`（全部 16 检测域 fast+postponed、`0–100` 四维评分与 `RiskPolicy`、全部 24 Collector `CrashFreedomMockTest`、Java↔Python 6 步 `v=2` 离线验签黄金向量、V1/V2 指纹黄金向量）+ `:demo` 评分与格式化单元测试。
  - **L2（离线 Native C++ 宿主机测试）**：`riskengine-sdk/src/test/cpp/`（`./scripts/run-cpp-tests.sh`）100% 离线运行 CMake/CTest，实测 `maps_parser`（>4 MiB）、`raw_dir` 畸形 fuzz、`DiskElf` 16KB/PT_LOAD、`bionic_prop_area`、`payload_codec`、64 位 `looks_like_trampoline` 与 `crypto_mini`。
  - **L3（二进制 AAR 仪器测试）**：`:integration-test` 独立消费 `riskengine-sdk-release.aar`，在 GitHub Actions Linux KVM API 30 / 34 / 36 模拟器矩阵执行端到端验证。
- Native I/O 采用各 ABI 内联 syscall、`getdents64`、流式 `/proc/self/maps`、`pipe2(O_CLOEXEC)` `safe_mem_read`、`disposable_child` 高危系统调用隔离、`-fno-exceptions -fno-rtti`、ThinLTO 与多态 `ScopedObfString` + `secure_zero`。

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/Implementation_Details_zh.md](./docs/Implementation_Details_zh.md) | 源码级契约：单核三模块架构、16 大检测域、`0–100` 四维评分与 `RiskPolicy`、TEE 信任根、HMA 侧信道、`SignedRiskEnvelope` `v=2`、6 大 CI 门禁、L1–L3 测试与 JSON v2 |
| [docs/evidence/](./docs/evidence/) | 16 份按域拆分的证据契约记录（`root.md` .. `threat_apps.md`） |
| [docs/Signed_Envelope_Verification.md](./docs/Signed_Envelope_Verification.md) | 硬件风控信封服务端 6 步离线验签规范（`v=2`）、标准化拒绝码与 Python/Java 参考用法 |
| [docs/Adversarial_Matrix.md](./docs/Adversarial_Matrix.md) | 原厂 OEM 兼容基线、现代对抗矩阵预期与 SLA 签字门禁 |
| [docs/validation/TEMPLATE.md](./docs/validation/TEMPLATE.md) | 可重复的真机验证与发版归档报告模板 |
| [GLOSSARY.md](./GLOSSARY.md) 与 [docs/adr/](./docs/adr/) | 领域术语表与架构决策记录（`ADR-0001`、`ADR-0002`） |

## 许可证

MIT。见 [LICENSE](./LICENSE)。
