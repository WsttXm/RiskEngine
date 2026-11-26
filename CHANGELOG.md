# Changelog

All notable changes to **RiskEngine** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

> For GitHub Releases, `.github/workflows/build-release.yml` automatically extracts the matching `## [vX.Y.Z]` section from this file via `scripts/extract-release-notes.py`.

---

## [v2.0.0] - 2026-11-26

### 单核三模块收敛与 16 大检测域（Single-Core Consolidation & 16 Converged Domains）
- **单一零依赖核心架构（ADR-0001）**：发布前彻底收敛为 3 模块仓库（`:riskengine-sdk`、`:demo`、`:integration-test`），不随 `v2.0.0` 引入任何可选扩展子模块或未消费的孤立 SPI，确保锁定后的核心公开 ABI 简洁纯净、**零第三方运行时依赖**且**零 `<uses-permission>`**。
- **16 大收敛检测域体系**：在保持 `minSdk = 30` / `compileSdk = 36` 与既有核心调用契约平滑升级的前提下，收敛交付 16 大顶层 Detection Domain：
  - `CRITICAL` 层：`app_integrity`（APK v2/v3/v3.1 签名与 Native 原始系统调用交叉校验、防重打包）、`hook_framework`（COW 安全分窗 SHA-256 自完整性、4-ABI Trampoline/GOT 校验、Frida/memfd/fd 隐蔽注入）、`debug`（双路径 `TracerPid`、`stat` `'t'`、`wchan`、JDWP 与可选 `PR_SET_DUMPABLE`）。
  - `FAST` 层：`root`、`mount_analysis`、`multi_instance`、`network_risk`、`location_risk`、`screen_and_fraud`、`adb`、`emulator`、`cloud_phone`、`custom_rom`、`consistency`（含 `POSTPONED` 双阶段重探针无损合并）。
  - `POSTPONED` 层：`tee_integrity`（硬件信任根与 KeyMint/TrickyStore 防护）、`threat_apps`（签名免疫高危应用库与 HMA 全代际侧信道对抗）。
- **结构化证据与关联规则**：新增一等公民 `EvidenceItem`（`SourceLayer`、`Rank`、同源跨层自动合并）、覆盖 21 个证据家族的 `EvidenceFamily`、`DevicePosture` 非威胁安全态势与 `RiskReport.TrustTier`，新增 `C6:bridge_or_integrity_tamper`、`C8:spoofed_verified_boot`、`C9:stealth_root_with_unmount`、`C10:vishing_fraud_combo` 交叉规则。

### 企业级 0–100 四维评分引擎与本地 `RiskPolicy` 策略（Normalized Multidimensional Scoring & Local Policy）
- **标准化 0–100 四维评分引擎（ADR-0002）**：全面替代旧版无界线性累加与注册顺序依赖去重，引入确定性三阶段 `RiskScoringEngine`（`RiskReport` 与阶段 `TierReport` 共用同一 `0–100` 标尺）：
  - **四正交维度（`RiskDimension`）**：将全部 21 个证据家族映射至 `TAMPERING`、`PRIVILEGE`、`ENVIRONMENT`、`FRAUD_CONTEXT`，独立计算 `0–100` 子分。
  - **顺序无关 Family-Max + 多源印证加权（Corroboration Lift）**：同一家族取单源最强强度，重复项以 `deduped:corroborating_evidence` 保留完整取证；跨观测层（`>= 2` 层）或跨检测域（`>= 2` 域）印证给予有界加权（`+0.06`，封顶 `0.95`）。
  - **Noisy-OR 饱和融合与防膨胀封顶**：维度内采用 Noisy-OR 融合，纯 `LOW` 弱信号维度封顶 `<= 35`；跨维度与 `C1`–`C10` 关联规则加权 Noisy-OR 融合；默认分档 `0` SAFE、`1–29` LOW（纯提示性信号保持 `0` 分与 `ALLOW`）、`30–59` MEDIUM、`60–84` HIGH、`85–100` DEADLY。
  - **权威 Hard Trigger 单源解析与 `95–100` 保底**：`RiskScoringEngine.extractHardTriggers` 与 `RiskReport.getHardTriggers()` 单点收敛，有效 Hard Trigger 直接锁定 `DEADLY` / `BLOCK` 并保底 `95–100` 分。
  - **分层评估置信度与五级推荐动作**：按 `CRITICAL=3 / FAST=2 / POSTPONED=1` 加权计算 `confidencePercent`（与风险分解耦，仅 `CRITICAL` 失败、加权置信度 `< 70%` 或全不可用时进入 `UNKNOWN` / `REVIEW`）；新增五级 `RiskAction`（`ALLOW`/`CHALLENGE`/`RESTRICT`/`BLOCK`/`REVIEW`）与逐项可审计 `ScoreBreakdown`（`FAMILY`、`CORROBORATION_LIFT`、`CORRELATION_RULE`、`HARD_TRIGGER_FLOOR`）。
- **不可变本地策略引擎（`RiskPolicy`）**：提供 `RiskPolicy.forScene(CollectScene)` 与 `RiskPolicy.builder(CollectScene)`，支持宿主无后端自定义四维权重、动作阈值、`highAction`、家族模式（`ALLOWLIST`/`INFORMATIONAL_ONLY`/自定义倍率）与 Hard Trigger 抑制，通过 `RiskEngineConfig.Builder.riskPolicy(...)` 接入。

### 硬件信任根、增量 JSON v2 与 `v=2` 离线可验签信封（Hardware Trust Root, JSON v2 & Envelope `v=2`）
- **零依赖硬件证明与反伪造**：内置纯 Java 严格最小 DER / 规范 CBOR（RFC 8949）解析器（OID `.17` 根优先校验与 RKP OID `.30` 校验）、Google Hardware Attestation Root 锚点与 1,699 条单调离线 CRL 吊销底线；覆盖 `Keystore2ParcelClient` 冻结 AIDL 协议（零受限隐藏 API 反射）、Keystore2 `Domain.APP` vs 隔离进程 `Domain.GRANT` 证书链分裂校验、`libbinder.so` `ioctl` GOT/内联钩子与三路 `BINDER_VERSION` 校验、覆写反缓存陷阱、StrongBox 软模拟识别与 Widevine Java↔NDK 双层一致校验。
- **增量 JSON v2 与 `v=2` 硬件签名信封**：`RiskReportJsonSerializer` 增量输出 `maxRiskScore=100`、`displayThresholdMaximum=100`、`confidencePercent`、`recommendedAction`、`hardTriggers[]`、`dimensionScores{}`、`scoreBreakdown[]`；`SignedRiskEnvelope` 升级至协议 `v=2`（17 字段规范载荷新增 `action`/`confidence`/`dimensions` 并复用 `RiskReport.getHardTriggers()`），同步升级零依赖 Python 6 步离线验签器 [`scripts/verify_risk_envelope.py`](https://github.com/WsttXm/RiskEngine/blob/v2.0.0/scripts/verify_risk_envelope.py)（默认 `reject_score_threshold=60`、`min_confidence=70`）及 Java↔Python 黄金向量一致性测试。

### 深度对抗、HMA 全代际侧信道、推拉双模与分层指纹 v2
- **异步 `<5ms` 初始化与推拉双模**：`RiskEngine.init()` 主线程零同步 I/O，新增 `startMonitoring(ThreatListener, DeviceStateListener, ExecutionStateListener)` 严格按 `CRITICAL -> FAST -> POSTPONED` 渐进推送结果（阶段 `TierReport` 统一对齐 `0–100` 标尺），并支持后台周期完整性巡检与运行期篡改实时回调。
- **内核与框架深度对抗**：新增 `util/disposable_child` 隔离高危系统调用执行框架、`RiskIsolatedProbeService` 跨进程挂载比对、Bionic `prop_area` 共享内存空洞/序列号/尾字节取证、ARM64 `MIDR_EL1` / `cntvct_el0` 时钟漂移与 `KernelPatch SuperCall` / `KernelSU` / `SUSFS` 侧信道、`Zygisk` Bionic `atexit` 匿名回调与空洞检测、`LSPosed` Binder 魔数 `0x5F4C5350` / GID 审计、`ADB` 协议防抖与原生 `AF_NETLINK` 零权限网卡枚举。
- **第 16 检测域 `threat_apps` 与 HMA 对抗**：提供不可变 `ThreatAppPolicy` 宿主自定义策略 API、10+ 官方 Root/HMA/修改器发布证书 SHA-256 库、`<queries>` 单源同步、一次性子进程 `getpriority(PRIO_USER)` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`、跨用户 `MATCH_ANY_USER` 异常抑制、有序广播 `resultTo` 自检对照、Android 15+ `PermissionService` 差集与 `Thanox` `IThanos` Binder 精准核验。
- **分层指纹 v2 与硬件密钥绑定**：新增 `FingerprintVersion`（`V1` 冻结兼容 / `V2` 零权限高熵增强）与 `FingerprintStability`（`STABLE` / `OPTIMAL` / `UNIQUE`）、AndroidKeyStore AES-GCM 硬件密钥封装与不可变 `anchor_hw` 防洗白、`UserManager.isUserUnlocked()` 保护的 DirectBoot CE→DE 迁移及显式 `resetFingerprintBaseline()`。

### 可执行工程治理、三层测试体系与 Demo Fluid UI v2
- **6 大 CI 静态治理门禁**：`docs/evidence/*.md`（16/16 契约校验）、JNI 41/41 1:1 + 4-ABI ELF 加固（`<= 2000 KiB`/ABI、16KB 对齐、2 导出符号）+ Release R8 Dex `< 2,500` 方法、`<queries>`/INI/版本单源同步、零插件 JDK 17 `javap` Public ABI 锁（`apiCheck`/`apiDump` + AAR/POM 纯度）、反射白名单与文案协议边界审计、每周定时 Google 信任根/CRL 刷新工作流（Gate 6）。
- **L1 + L2 + L3 三层自动化测试**：核心 `:riskengine-sdk` 与 `:demo` JVM 单元测试（L1）、100% 离线 CMake/CTest 原生 C++ 宿主机单元测试（L2，`scripts/run-cpp-tests.sh`）、独立消费 Release AAR 二进制的 `:integration-test` 仪器测试与 GitHub Actions Linux KVM API 30/34/36 模拟器矩阵（L3）。
- **Demo Fluid UI v2 评分升级**：保留 `v1.5.0` Fluid Design 流体视觉体系，校准 `RiskGaugeView` 至 `0–100` 标尺与三阶段（`CRITICAL -> FAST -> POSTPONED`）渐进弧度态，新增四维风险进度条、推荐 `RiskAction` 标签、评估置信度、Hard Trigger 徽章、可展开 `ScoreBreakdown` 归因详情抽屉、首次初始化前隐私同意弹窗、分层指纹分桶卡片（含基线重置确认）、顶部实时 `ThreatStreamDrawer` 及 16/16 检测域全量本地化。

---

## [v1.5.0] - 2026-11-21

### 检测项精简与准确性优化（Detector Streamlining & Accuracy）
- **核心检测项收敛至 9 项**：从 SDK（Java 层、Native C++ 层、JNI 桥接、`RiskEngineConfig`、`artifact_paths.ini` 及 `AndroidManifest.xml`）与 Demo 中彻底移除 **Native 密封校验**（`sealed_verdict`）、**Native 完整性**（`native_tamper`）、**沙箱与虚拟化**（`sandbox`）、**可疑进程**（`process_scan`）4 项冗余/高噪检测器，保留 9 项高价值核心安全检测。
- **移除无效的 `/proc/1/mountinfo` 挂载命名空间比对**：清理 `mount_namespace_diff` 子检测（Android 7.0+ `/proc` 默认启用 `hidepid=invisible,gid=3009`，普通应用进程访问 `/proc/1/*` 恒返回 `ENOENT`），消除 `ROOT检测` 中固定出现的“未完成子项”告警，使子项覆盖率恢复 100%（`8/8`），并修复 `native_check_root()` 在未 Root 设备上恒返回 `true` 的缺陷。
- **检测项命名规范化**：统一优化检测项展示名称——`ROOT权限检测` 精简为 **`ROOT检测`**，`调试器连接` 调整为 **`Debug模式`**，`系统一致性` 明确为 **`系统信息防篡改`**（涵盖分区指纹、属性防伪、Verified Boot 启动链与内核篡改校验）。
- **内存映射路径富化**：增强 `HookFrameworkDetector`、`DebugDetector` 与 `native_hook_detector.cpp`，在扫描 `/proc/self/maps` 检出 Frida / Xposed / LSPosed / Substrate / 调试器特征时附带完整映射文件路径。

### Demo 流体视觉重塑与结构化检出详情（Fluid UI & Structured Findings）
- **Fluid Design 流体界面重构**：全新设计 Demo 视觉体系与应用图标，引入自定义圆环风险仪表盘（`RiskGaugeView`）、分段控制器（`SegmentedControlView`）、弹性交互动画（`SpringTouchHelper`）、底部悬浮操作栏与日夜主题一键切换。
- **结构化检出详情卡片**：重构检测项点击后的详情弹窗（`FluidDetailSheet` / `ReportFormatter`），摒弃原先笼统的“检出证据”列表与晦涩的“原始标识”技术 token，直接按卡片展示每项风险的 **检出位置**（具体文件路径、系统属性名、内核节点或 API）、**检出内容** 与 **风险说明**。
- **Java + Native 双源同项自动合并**：同一风险路径或特征被 Java 与 Native 双层同时检出时自动合并为一张卡片并标注 `Java + Native`，消除重复条目；同时将诊断类指标独立至“运行环境信息”区块，并修复多卡片场景下底部弹窗高度越界遮挡状态栏的问题。

---

## [v1.4.0] - 2026-11-20

### 安全加固与反篡改（Native Hardening & Anti-Tampering）
- **Release / RelWithDebInfo 二进制加固**：CMake 同时对 `Release` 与 `RelWithDebInfo` 启用 ThinLTO（`-flto=thin`）、段回收（`--gc-sections`）、unwind 表裁剪及 `exports.map` 符号导出控制，仅暴露 `JNI_OnLoad` / `JNI_OnUnload`，显著压缩 `.so` 体积并隐藏内部符号。
- **字符串混淆与动态 JNI 校验**：加固 `OBF()` 运行时解密以防 Clang 常量折叠，对敏感检测路径与动态 JNI 注册名进行混淆，并在运行期校验 JNI 函数指针归属与函数序言完整性。
- **Sealed Verdict 协议升级**：升级为 `HMAC-SHA256` + 64 位随机 Challenge 绑定 + 64 槽防重放环形缓冲 + 单次调用打包校验，防止跨调用重放与 Java/Native 桥接伪造。
- **完整性深度检测**：支持 `extractNativeLibs=false`（APK 内嵌未解压 `.so`）场景下的 `.text` 分段哈希校验；新增 `libc` / `libdl` 磁盘与内存 ELF 导出表差异比对、自身 GOT Hook 检测及全线程 `TracerPid` 扫描。
- **检测特征单一事实来源**：统一由 `artifact_paths.ini` 通过 Gradle `:riskengine-sdk:generateDetectionLists` 自动生成混淆后的 Java `DetectionLists` 与 C++ `detection_lists.h`。

### 动态红队对抗与检出修复（Verified on Pixel 6 KSU/Zygisk/Shamiko & AVD）
- **穿透魔改 Frida 隐蔽注入**：新增匿名私有可执行 `memfd` ELF 注入检测，针对伪装为 `/memfd:jit-cache` 的魔改版 Frida（如 `xmrda-server-17.16.1`）即使未下 Hook 也可高置信度检出。
- **KernelSU / Shamiko / MoveCertificate 挂载异常检测**：识别只读系统子路径（如 `/system/etc/security/cacerts`）上的异常 `tmpfs` 挂载，以及 `release-keys` 构建下的 `-dirty` 内核特征。
- **桥接篡改关联与硬触发**：新增 `CorrelationEngine` `C6:bridge_tamper` 关联规则、`art_hook_detector` 对 `NativeCollectorBridge` 的 `ACC_NATIVE` 标志位校验、受权限保护的本地回环 Frida D-Bus 探测，以及 `RiskReport` 中 `sealed:*` 异常硬触发定级。
- **误报与噪声治理**：消除原生 Android 10–16 上 `sealed:coverage_loss` 误告警、无 `INTERNET` 权限时 `ifaddrs` `EPERM` 噪声以及非授权 `/proc/*` 读取触发的 SELinux AVC 拒绝日志。

### 设备指纹、Demo 与文档（Fingerprinting, Demo & Docs）
- **分层指纹稳定性提升**：将硬件层指纹稳定化至 5 个物理分桶（CPU/GPU/Display/Memory/Storage 等），支持分桶连续性比对与进程级临时 fallback salt。
- **兼容性增强**：新增兼容 ANGLE 的 `GpuClassifier`、适配 Project Treble 的一致性校验规则，以及顶层 `fingerprintId` JSON 字段输出。
- **Demo、测试与文档同步**：补齐 Demo UI 采集器/证据文案映射，单元测试扩展至 73 项，中英文 README 与架构/检测/指纹文档同步更新。

### 构建与 CI/CD 基础设施（CI & Build Parity）
- 升级 `android-actions/setup-android` 至 `v4`（显式配置 `packages: platform-tools`），修复 Google 下线旧 `tools` 包导致的 GitHub Actions 构建失败。
- 将 JDK / CompileSdk / Build-Tools / CMake / NDK 版本统一收敛至 `gradle.properties`，并通过 `.github/actions/setup-android-env` 与 `scripts/ci-verify.sh`（`./build.sh ci`）保障本地与 CI/Release 构建环境及校验流程完全一致。
- 新增 `scripts/extract-release-notes.py`，发版流水线自动从 `CHANGELOG.md` 提取对应版本更新日志并发布到 GitHub Releases 页面。

---

## [v1.3.1] - 2026-09-13

- 加固采集链路与 Native 完整性校验，修复若干边界问题。

## [v1.3.0] - 2026-09-13

- 调整 `minSdk` 与多模块构建配置，修复若干检测与构建缺陷。

## [v1.2.0] - 2026-08-18

- 增强检测器能力与 Demo 展示体验。

## [v1.1.0] - 2026-07-04

- 扩展安全检测与设备指纹模块，完善发布流程。

## [v1.0.0] - 2026-06-29

- RiskEngine Android SDK 首个正式发布版本。
