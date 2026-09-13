# RiskEngine 代码审查与修复报告（2026-09-13）

## 审查范围

本轮覆盖 SDK Java API、并发调度、采集与评分模型、JNI 注册边界、Native 文件/ELF 解析、线程生命周期、Demo、集成测试清单以及 Gradle Lint。审查基线为 `dev` 分支的 `d25663e`，修复分支为 `codex/code-review-fixes-20260913`。

“全部潜在问题”无法被有限的静态分析和主机测试穷尽，尤其安全检测的真假阳性依赖 Android 版本、OEM、ABI 与对抗环境。本报告因此把已由代码路径证明并修复的问题，与仍需设备矩阵验证的风险分开记录。

## 已修复问题

| 级别 | 问题 | 影响 | 修复 |
| --- | --- | --- | --- |
| 高 | 采集超时后不响应中断的旧任务仍可写入共享 `SignalSnapshot` | 后续报告可能读取上一轮的迟到缓存，形成跨报告污染 | 每次采集创建独立快照及 Collector/Detector 实例，迟到任务只能写回旧快照 |
| 高 | Native monitor 为 detached 线程，`shutdown()` 不等待退出，同进程重新初始化也不会重启 | 代码卸载时可能仍执行旧线程；重新初始化失去周期检测 | 改为可中断等待、join、显式重启并清空代次状态；`JNI_OnUnload` 也执行停止与 join |
| 高 | 密封结果的密钥初始化和 `last_nonce` 存在并发竞争 | 并发签发可能产生数据竞争，或令合法 blob 被另一调用立即作废 | 串行化密钥初始化，以 MAC + 随机 nonce + 10 秒单调时钟窗口验证并发 blob |
| 高 | 密封裁决定义了 `kJniSelfHook` 权重，但生成 blob 时从未执行 JNI 注册表检查 | Java 层独立检查可被一起 Hook，密封分数漏掉本应由 Native 保护的自检证据 | 生成密封结果时传入实际 `JNINativeMethod` 指针表，写入 Hook/覆盖损失标志并参与 Native 计分 |
| 高 | `getdents64` 结果直接信任 `d_reclen` 与 NUL 终止符 | 被破坏或异常返回可导致越界读、未对齐访问或死循环 | 校验总长度、record 长度、剩余边界与名称终止符；用 `memcpy` 读取字段避免未对齐访问，异常按 `EIO` 失败 |
| 高 | ELF、maps 与运行时符号解析存在整数溢出和未验证指针解引用 | 畸形/被篡改元数据可能触发越界访问或崩溃 | 加入地址加法、区间、ELF 头、符号、重定位与字符串映射边界检查，并限制遍历数量 |
| 中 | `collect(scene)` 只在最终聚合使用覆盖场景，`native_tamper` 仍绑定初始化场景；锁等待超时报告也退回默认场景 | 同一 API 请求内部策略不一致 | Detector 按本次有效场景创建，正常路径和超时路径统一使用覆盖场景 |
| 中 | 证据去重允许 informational/context-only 信号先占用 family；任一 family 重复就把含新证据的整个结果降级 | 后续真实高危信号可能不计分，混合新证据也可能丢分 | 只有可处置信号才占用 family；仅在结果的全部 family 都已计分时降级，并增加回归测试 |
| 中 | Native 信号缓存的 double-check 实际没有重新读取字段 | 并发等待者仍会重复执行昂贵或非幂等 Native 探测 | 锁内重新读取真实缓存字段后再决定是否调用 Native |
| 中 | Native 系统属性异常被兼容方法转换为空字符串 | 执行失败被当成“成功但属性为空”，覆盖率虚高 | 新增带状态的属性接口并在快照和 Collector 中保留 ERROR/UNAVAILABLE |
| 中 | Sandbox 多用户路径计算使用 `uid % 100000`（appId）作为用户目录编号 | 工作资料夹/多用户环境中的目录一致性判断错误 | 改用 `uid / 100000`，同时覆盖 `/data/user`、`/data/user_de` 与仅限 user 0 的旧路径 |
| 中 | `FingerprintStore` 的盐生成与连续性更新不是跨实例原子操作，计数可溢出且首次时间返回 0 | 并发实例可能返回不同盐或丢更新，长期计数翻负 | 使用进程级锁串行化读改写、饱和计数，并返回实际首次观测时间 |
| 低 | 磁盘块数乘块大小未检查溢出 | 极端或异常 statfs 数据可能返回负/错误容量 | 乘法前做上界检查，溢出返回不可用 |
| 低 | 无法解析的 Android release、未知未来 SDK 仍被计为一致性检查成功 | 覆盖率虚高 | 改为明确的 coverage failure |
| 低 | 云手机摄像头能力只检查后摄特性 | 仅前摄设备可能被误判无摄像头 | 使用 `FEATURE_CAMERA_ANY` |
| 低 | Demo 有国际化、兼容 drawable、废弃资源和自适应图标目录告警；集成测试缺备份规则与图标 | Lint 噪声与小型兼容问题 | 使用字符串占位符/兼容资源加载，删除未使用资源，补数据提取规则，按 API 目录组织自适应图标 |

## 验证

- `:riskengine-sdk:testDebugUnitTest`、`:riskengine-sdk:testReleaseUnitTest`：两个变体各 56 个测试、0 失败；新增 2 个证据去重回归测试。
- `:riskengine-sdk:assembleRelease`：arm64-v8a、armeabi-v7a、x86_64、x86 全部 Native 编译及 AAR 打包成功。
- `:riskengine-sdk:lintDebug`、`:integration-test:lintDebug`、`:demo:lintDebug`：无 error；集成测试 Lint 已清零，SDK 剩 6 个、Demo 剩 16 个非阻断 warning。
- `git diff --check`：无空白错误。

## 尚未直接修复的风险与建议

1. 建立 API 30–36、arm64 为主的真机矩阵，并包含 Samsung、Xiaomi、OPPO/vivo、Pixel、Chromebook、工作资料夹和 `extractNativeLibs=false`。当前单个 instrumented test 只能证明 API 链接，不能量化真假阳性。
2. `sealed_verdict` 的 keyed FNV-1a 不是标准密码学 MAC，且密钥位于同一进程。若服务端需要可信结论，应使用 Android 硬件证明/Play Integrity 等远端可验证信号；本地 sealed verdict 只应作为提高绕过成本的机制。
3. Sandbox 的 `BaseDexClassLoader.pathList` 反射属于非 SDK API。代码已把失败计入覆盖不足，但 Android 后续版本可能永久禁止；建议准备公开 API/构建期注入的替代方案。
4. x86/i386 没有 ARM inline trampoline 启发式；这些 ABI 仍有 GOT 与文件/内存比对，但检测覆盖弱于 ARM。若业务不需要 x86 真机，可明确把它定位为模拟器兼容 ABI。
5. `DetectionLists` 仍含明文规则，`ObfuscatedLists` 尚未接入生成流程。这不是正确性 bug，但会降低静态逆向成本；建议由构建期生成器统一产出 Java/C++ 编码表并做一致性测试。
6. Lint 剩余项主要是检测器故意使用的固定系统路径、非 SDK 反射、依赖版本提示和重复圆形图标。依赖升级尤其 AGP 9.x 属于迁移工作，应单独升级并跑发布/消费端兼容测试，不宜混入本次 bugfix。
7. `ConsistencyDetector` 的 CPU 核数一致性目前只比较 Runtime 与 `/proc/cpuinfo` 两源，注释所述 sysfs 第三源尚未接入共享快照；建议在真机基线建立后补齐，以免动态离线核心造成新的误报。
