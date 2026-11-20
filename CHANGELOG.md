# Changelog

All notable changes to **RiskEngine** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

> For GitHub Releases, `.github/workflows/build-release.yml` automatically extracts the matching `## [vX.Y.Z]` section from this file via `scripts/extract-release-notes.py`.

---

## [v1.5.0] - 2026-11-21

### 检测项精简与准确性优化（Detector Streamlining & Accuracy）
- **核心检测项收敛至 9 项**：从 SDK（Java 层、Native C++ 层、JNI 桥接、`RiskEngineConfig`、`artifact_paths.ini` 及 `AndroidManifest.xml`）与 Demo 中彻底移除 **Native 密封校验**（`sealed_verdict`）、**Native 完整性**（`native_tamper`）、**沙箱与虚拟化**（`sandbox`）、**可疑进程**（`process_scan`）4 项冗余/高噪检测器，保留 9 项高价值核心安全检测。
- **移除无效的 `/proc/1/mountinfo` 挂载命名空间比对**：清理 `mount_namespace_diff` 子检测（Android 7.0+ `/proc` 默认启用 `hidepid=invisible,gid=3009`，普通应用进程访问 `/proc/1/*` 恒返回 `ENOENT`），消除 `ROOT检测` 中固定出现的“未完成子项”告警，使子项覆盖率恢复 100%（`8/8`），并修复 `native_check_root()` 在未 Root 设备上恒返回 `true` 的缺陷。
- **检测项命名规范化**：统一优化检测项展示名称——`ROOT权限检测` 精简为 **`ROOT检测`**，`调试器连接` 调整为 **`Debug模式`**，`系统一致性` 明确为 **`系统信息防篡改`**（涵盖分区指纹、属性防伪、Verified Boot 启动链与内核篡改校验）。
- **内存映射路径富化**：增强 `HookFrameworkDetector`、`DebugDetector` 与 `native_hook_detector.cpp`，在扫描 `/proc/self/maps` 检出 Frida / Xposed / LSPosed / Substrate / 调试器特征时附带完整映射文件路径。

### Demo 流体视觉重塑与结构化检出详情（Fluid UI & Structured Findings）
- **Apple Fluid Design 界面重构**：全新设计 Demo 视觉体系与应用图标，引入自定义圆环风险仪表盘（`RiskGaugeView`）、分段控制器（`SegmentedControlView`）、弹性交互动画（`SpringTouchHelper`）、底部悬浮操作栏与日夜主题一键切换。
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
