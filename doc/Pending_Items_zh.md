# RiskEngine 待解决项

本文仅记录当前工作区无法安全闭环、或需要外部设备/基础设施决策的事项。其余修复已进入源码、测试、Demo 或工作流。

## 1. ARM64/OEM 真机误报与对抗回归

- 范围：至少覆盖 Pixel、三星、小米/红米、OPPO/一加、vivo 等 Android 30–36 真机，以及 Root、Magisk、LSPosed、Frida Gadget/Server 的正例设备。
- 重点：匿名可执行区、AOSP/厂商传感器、通用 fingerprint、容器痕迹、进程可见性和 SELinux 权限差异。
- 验收：每个机型保存 SDK 版本、系统构建、执行覆盖、原始证据和人工结论；正常设备的强风险误报为 0，预置正例均产生对应证据。
- 当前证据：本地 API 36 ARM64 模拟器 instrumentation 与 Demo 采集通过；模拟器环境不能替代 OEM 真机。

## 2. Java/Native Root 路径名单单源化

- 现状：Java 与 Native 名单目前内容一致，但仍各自维护。Native 需要在 Java 层被 Hook 时保持独立检查能力，直接由 Java 传入名单会削弱这一目标。
- 候选方案：在构建期从一个只读清单生成 Java 类和 C++ header，并增加生成物一致性测试。
- 验收：源码仓库只有一个可编辑名单；Java/Native 生成物由 CI 校验且不能手工漂移。

## 3. Native task 目录遍历抗 Hook

- 现状：`/proc/self/maps` 已使用 raw syscall 读取；线程目录仍通过 `opendir/readdir` 遍历，libc 被定向 Hook 时可能影响线程名检测。
- 候选方案：为各 ABI 实现并测试 `getdents64` 包装，同时保留失败状态而非返回安全。
- 验收：Frida/LSPosed 对 libc 目录 API 的 Hook 不会使线程检测静默变为安全；API 30–36 与 4 ABI 回归通过。

## 4. 远程工作流与发布环境验证

- 由于本次明确禁止 `git push`，新增 PR CI、周度设备矩阵和 Tag Release 尚未在 GitHub 执行。
- 首次推送后应在临时分支/测试 Tag 验证 artifact 路径、权限、Action 版本和 Release notes；测试 Tag 完成后按仓库策略清理。
- 临时 Debug 签名 APK 是既定产物，只用于用户侧载。验收时应确认 Release 页面继续明确签名可能变化、冲突时需卸载旧版、不得用于商店或生产分发。

## 5. Maven 远端仓库选择

- AAR、sources JAR、POM 和 `maven-publish` publication 已就绪，但未配置远端 Maven 仓库或凭据；当前发布仍以 GitHub Release 文件为准。
- 需要维护者选择 GitHub Packages、Maven Central 或内部仓库后再增加凭据与发布任务。

