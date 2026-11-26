package com.wsttxm.riskenginesdk.demo.ui;

import android.content.Context;

import androidx.annotation.ColorRes;
import androidx.annotation.StringRes;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.FingerprintStability;
import com.wsttxm.riskenginesdk.FingerprintVersion;
import com.wsttxm.riskenginesdk.demo.R;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskAction;
import com.wsttxm.riskenginesdk.model.RiskDimension;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.ScoreBreakdown;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;
import com.wsttxm.riskenginesdk.model.ThreatEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Presentation formatter and localizer for {@link RiskReport} models.
 *
 * <p>Drives all 16/16 converged Detection Domains (including {@code tee_integrity},
 * {@code C8:spoofed_verified_boot}, {@code WidevineParityProbe}, {@link SignedRiskEnvelope},
 * and {@code threat_apps} + HMA side-channels) as well as ADR-0002 normalized 0–100 four-dimension
 * scoring, {@link RiskAction}, Assessment Confidence, and {@link ScoreBreakdown} attribution
 * directly from structured {@link DetectionResult#getEvidenceItems()} ({@link EvidenceItem}) and
 * {@link DevicePosture}.
 */
public final class ReportFormatter {

    /**
     * Minimal string lookup seam allowing {@link ReportFormatter} to run identically on Android
     * {@link Context} and pure JVM unit tests without mocking framework dependencies.
     */
    public interface StringResolver {
        String get(@StringRes int resId);
        String get(@StringRes int resId, Object... formatArgs);
    }

    public static final class EvidenceDetail {
        public final String title;
        public final String sourceTag;
        public final String location;
        public final String content;
        public final String risk;
        public final String inlineSummary;
        public final boolean diagnosticOnly;
        final String mergeKey;

        EvidenceDetail(String title,
                       String sourceTag,
                       String location,
                       String content,
                       String risk,
                       String inlineSummary,
                       boolean diagnosticOnly,
                       String mergeKey) {
            this.title = title;
            this.sourceTag = sourceTag;
            this.location = location;
            this.content = content;
            this.risk = risk;
            this.inlineSummary = inlineSummary;
            this.diagnosticOnly = diagnosticOnly;
            this.mergeKey = mergeKey;
        }

        EvidenceDetail withSourceTag(String mergedTag) {
            return new EvidenceDetail(
                    title, mergedTag, location, content, risk, inlineSummary, diagnosticOnly, mergeKey);
        }
    }

    public static final class FailureDetail {
        public final String target;
        public final String reason;

        FailureDetail(String target, String reason) {
            this.target = target;
            this.reason = reason;
        }
    }

    /** Readable presentation model for a single {@link ScoreBreakdown.Entry}. */
    public static final class BreakdownItem {
        public final ScoreBreakdown.Category category;
        public final String categoryLabel;
        public final String title;
        public final String detail;
        public final String dimensionLabel;
        public final String sourceSummary;
        public final String pointsLabel;
        @ColorRes
        public final int accentColorRes;
        @ColorRes
        public final int badgeBgRes;

        BreakdownItem(ScoreBreakdown.Category category,
                      String categoryLabel,
                      String title,
                      String detail,
                      String dimensionLabel,
                      String sourceSummary,
                      String pointsLabel,
                      @ColorRes int accentColorRes,
                      @ColorRes int badgeBgRes) {
            this.category = category;
            this.categoryLabel = categoryLabel;
            this.title = title;
            this.detail = detail;
            this.dimensionLabel = dimensionLabel;
            this.sourceSummary = sourceSummary;
            this.pointsLabel = pointsLabel;
            this.accentColorRes = accentColorRes;
            this.badgeBgRes = badgeBgRes;
        }
    }

    private static final class EvidenceMeta {
        final String title;
        final String risk;

        EvidenceMeta(String title, String risk) {
            this.title = title;
            this.risk = risk;
        }
    }

    /** Structured metadata table indexed by {@link EvidenceItem#getCode()}. */
    private static final Map<String, EvidenceMeta> EVIDENCE_META;

    static {
        Map<String, EvidenceMeta> m = new LinkedHashMap<>();
        // App Integrity (P1-6)
        m.put("pkg_name_mismatch", new EvidenceMeta("应用包名不匹配",
                "运行时包名与宿主固定预期包名不一致，高度疑似应用被重打包篡改。"));
        m.put("apk_sig_mismatch", new EvidenceMeta("APK 签名证书不匹配",
                "当前安装包签名 SHA-256 与宿主配置的合法签名集合不符，可能已被二次签名重打包。"));
        m.put("apk_native_java_sig_conflict", new EvidenceMeta("Native 与 Java 签名读取冲突",
                "底层原始系统调用读取的 base.apk 签名与 PackageManager 返回结果矛盾，疑似存在 Binder/PM Hook 欺骗。"));
        m.put("apk_signing_lineage_mismatch", new EvidenceMeta("APK v3 签名轮换谱系不匹配",
                "当前签名证书历史轮换链未包含宿主预期证书。"));
        m.put("unofficial_installer", new EvidenceMeta("非官方应用商店安装",
                "应用安装来源不在内置或自定义的受信任官方商店列表中，存在侧载风险。"));
        m.put("release_unobfuscated", new EvidenceMeta("Release 包未启用代码混淆",
                "哨兵类名保持原样，说明正式版未启用 R8/ProGuard 混淆，逆向分析成本显著降低。"));

        // Multi-Instance & Virtual Container (P1-7)
        m.put("nested_container_path", new EvidenceMeta("嵌套虚拟容器目录",
                "应用私有目录深度或属主包名异常，疑似运行在 VirtualApp / BlackBox 等虚拟多开容器中。"));
        m.put("container_source_dir", new EvidenceMeta("异常 APK 加载路径",
                "APK 位于其他应用的私有数据目录内，属于典型多开插件加载特征。"));
        m.put("user_id_path_mismatch", new EvidenceMeta("进程 UID 与目录用户 ID 矛盾",
                "Process.myUid()/100000 与数据目录路径中的用户 ID 不一致，疑似虚拟沙箱重定向。"));
        m.put("dir_uid_mismatch", new EvidenceMeta("目录属主 UID 不匹配",
                "应用数据目录的 stat.st_uid 与当前进程 UID 矛盾，疑似被容器宿主共享目录。"));
        m.put("multi_apk_maps", new EvidenceMeta("进程空间映射多个第三方 APK",
                "/proc/self/maps 同时加载了其他非系统应用 APK，属于典型虚拟容器宿主特征。"));
        m.put("container_maps_artifact", new EvidenceMeta("检出多开容器引擎库",
                "进程内存中检出已知虚拟多开框架动态库或路径痕迹。"));
        m.put("binder_dynamic_proxy", new EvidenceMeta("系统服务 Binder 动态代理",
                "核心系统服务句柄被 java.lang.reflect.Proxy 动态代理接管，疑似虚拟容器或 Hook 拦截。"));
        m.put("oem_dual_app", new EvidenceMeta("系统应用分身环境",
                "当前运行在厂商系统双开/分身空间（如 user 999），登录/支付等敏感场景需关注多账号风险。"));

        // Network & MitM (P1-8)
        m.put("user_ca_cert", new EvidenceMeta("已安装用户自定义 CA 根证书",
                "系统信任库存在用户安装的根证书（如 Charles/Fiddler/mitmproxy），HTTPS 流量可能正被中间人抓包解密。"));
        m.put("vpn_active", new EvidenceMeta("活跃系统 VPN 隧道",
                "设备当前存在活跃的 VPN 通道或虚拟隧道网卡，网络流量可能被重定向审计。"));
        m.put("http_proxy", new EvidenceMeta("已配置 HTTP 代理",
                "系统或 JVM 代理属性已启用，网络请求可能经过外部抓包代理服务器。"));
        m.put("proxy_tool_cert", new EvidenceMeta("检出已知代理工具",
                "设备已安装经官方签名核验的代理/抓包工具应用。"));
        m.put("proxy_module", new EvidenceMeta("检出透明代理模块",
                "检出 Root 透明代理模块目录（box4 / box_for_root），流量可在内核层被透明转发。"));

        // Location Risk (P1-9)
        m.put("location_canary_tamper", new EvidenceMeta("位置 API 契约被 Hook 篡改",
                "零权限 Location 往返金丝雀校验失败，确认存在 Xposed/LSPosed 定位劫持模块。"));
        m.put("cached_location_mock", new EvidenceMeta("缓存定位标记为模拟位置",
                "系统缓存位置明确带有 isMock 标记，当前地理位置可信度存疑。"));
        m.put("mock_location_appop_allowed", new EvidenceMeta("模拟位置权限已授予",
                "AppOpsManager 指示模拟位置操作处于允许状态。"));

        // Screen & Anti-Fraud (P1-10)
        m.put("virtual_display", new EvidenceMeta("活跃虚拟显示/投屏会话",
                "检出非默认投屏或虚拟显示设备（如 scrcpy / MediaProjection / 远控软件），屏幕内容可能正在被远程查看。"));
        m.put("third_party_a11y", new EvidenceMeta("第三方无障碍服务活跃",
                "存在非系统第三方无障碍服务，可读取界面敏感内容并模拟点击操作。"));
        m.put("virtual_input", new EvidenceMeta("检出虚拟输入设备",
                "检出非系统 uinput/虚拟触控输入设备，可能存在自动化脚本或远程控制注入。"));
        m.put("screen_recording_active", new EvidenceMeta("正在进行屏幕录制",
                "系统录屏状态回调指示当前页面正被录制，支付与密码输入存在泄露风险。"));
        m.put("screen_capture_observed", new EvidenceMeta("近期发生截屏行为",
                "生命周期回调捕获到应用界面近期被截屏。"));
        m.put("ongoing_call", new EvidenceMeta("当前处于语音/VoIP 通话中",
                "音频模式指示设备正在通话中；单独出现仅作提示，在支付场景叠加投屏/无障碍将触发反电诈告警。"));
        m.put("time_spoofing", new EvidenceMeta("系统时钟疑似被篡改",
                "系统时间早于构建时间、关闭自动校时或相对单调时钟发生显著倒退/跳变。"));
        m.put("vishing_fraud_combo", new EvidenceMeta("高危电诈组合场景（C10）",
                "支付场景下同时处于通话中并开启投屏/录屏或第三方无障碍远控，高度疑似电信诈骗远程协助操作。"));

        // Debug & Hook Integrity (P0-8, P1-11, P1-12)
        m.put("tracer_pid", new EvidenceMeta("进程正被调试器附加",
                "TracerPid 非零，表明有外部调试器正通过 ptrace 附加并控制当前进程。"));
        m.put("tracer_pid_mismatch", new EvidenceMeta("双路径 TracerPid 矛盾",
                "/proc/self/status 与 /proc/<pid>/task 读数自相矛盾，存在反反调试 Hook 掩盖调试痕迹。"));
        m.put("stat_tracing_stop", new EvidenceMeta("线程处于内核调试挂起态",
                "/proc/self/task/*/stat 检出状态 't'（TASK_TRACED），确认线程正受 ptrace 跟踪。"));
        m.put("wchan_ptrace_stop", new EvidenceMeta("线程阻塞在 ptrace_stop",
                "内核等待通道 wchan 指向 ptrace_stop，确认存在底层调试器介入。"));
        m.put("jdwp_thread", new EvidenceMeta("检出 JDWP 调试线程",
                "进程内存在 JDWP / ADB connection 调试线程。"));
        m.put("jdwp_socket", new EvidenceMeta("检出 @jdwp-control 抽象套接字",
                "/proc/net/unix 检出 JDWP 控制套接字，存在 Java 层调试通道。"));
        m.put("debugger_connected", new EvidenceMeta("Java 调试器已连接",
                "android.os.Debug 报告调试器已连接或等待连接。"));
        m.put("debuggable_flag", new EvidenceMeta("应用启用了 debuggable 标记",
                "AndroidManifest 含 FLAG_DEBUGGABLE（开发构建常见，全场景默认仅提示）。"));
        m.put("ida_port_open", new EvidenceMeta("IDA 默认调试端口监听",
                "本地回环监听 23946 端口，疑似运行 IDA android_server。"));
        m.put("maps_exec_path", new EvidenceMeta("内存映射调试工具可执行段",
                "/proc/self/maps 检出 android_server / gdbserver / lldb / frida 映射。"));
        m.put("text_mismatch", new EvidenceMeta("自身代码段 .text 完整性被篡改",
                "libriskengine.so 或系统库可执行段分窗 SHA-256 与磁盘 ELF 不一致，确认存在内存补丁或代码注入。"));
        m.put("late_text_mismatch", new EvidenceMeta("后台复检发现代码段被动态篡改",
                "周期监控在初始化后捕获到 .text 代码段哈希漂移，存在延迟注入攻击。"));
        m.put("inline_hook", new EvidenceMeta("底层函数被 Inline Hook",
                "核心系统函数入口检出非正常跳转 trampoline 指令，函数执行流已被劫持。"));
        m.put("got_hook", new EvidenceMeta("GOT/PLT 符号表被劫持",
                "动态链接重定位表项指向模块外部地址，关键库调用被拦截。"));
        m.put("jni_self_hook", new EvidenceMeta("JNI 注册函数入口被篡改",
                "SDK 自身 JNI 函数序言 SHA-256 较加载基线发生变化，检测逻辑正遭劫持。"));
        m.put("fn_prologue_hook", new EvidenceMeta("核心检测函数序言被篡改",
                "核心原生检测函数前 16 字节与初始基线不符，存在运行期 inline 补丁。"));
        m.put("frida_maps", new EvidenceMeta("进程内存检出 Frida 注入模块",
                "/proc/self/maps 发现 Frida Agent 或 Gadget 动态库，进程正被动态插桩。"));
        m.put("frida_dbus_port", new EvidenceMeta("Frida D-Bus 协议端口响应",
                "本地端口响应 Frida D-Bus AUTH 握手，确认 Frida Server 活跃运行。"));
        m.put("late_frida_fd", new EvidenceMeta("后台复检发现 Frida 文件描述符",
                "周期监控在 /proc/self/fd 捕获到延迟注入的 Frida / linjector 句柄。"));
        m.put("bridge_or_integrity_tamper", new EvidenceMeta("底层自检与 Java 层严重矛盾（C6）",
                "Native 自完整性检出篡改而 Java 层回报正常，或存在隐蔽对抗伴随链接异常。"));
        m.put("device_binding_broken", new EvidenceMeta("硬件密钥绑定校验失效",
                "AndroidKeyStore AES-GCM 密钥缺失或密文验签失败，疑似应用数据被克隆迁移至其他设备或 XML 遭篡改。"));
        m.put("hardware_layer_changed", new EvidenceMeta("设备硬件层指纹发生突变",
                "本次观测与锚定硬件基线发生漂移，高度疑似使用了改机工具篡改硬件标识。"));

        // Root, Kernel Side-Channels, SELinux & Mount Forensics (Phase 2)
        m.put("su_found", new EvidenceMeta("su 提权可执行文件", "系统路径检出 su 提权入口，可突破应用沙箱隔离。"));
        m.put("su", new EvidenceMeta("su 提权可执行文件", "底层系统调用检出 su 提权入口，设备运行环境不可信。"));
        m.put("path_su", new EvidenceMeta("PATH 中的 Root 工具", "进程 PATH 目录暴露 su 提权文件。"));
        m.put("magisk_found", new EvidenceMeta("Magisk 框架路径", "检出 Magisk Root 框架核心目录或模块痕迹。"));
        m.put("magisk", new EvidenceMeta("Magisk 框架路径", "Native 探测检出 Magisk Root 框架痕迹。"));
        m.put("ksu_found", new EvidenceMeta("KernelSU 框架路径", "检出内核级 Root 方案 KernelSU 组件路径。"));
        m.put("ksu", new EvidenceMeta("KernelSU 框架路径", "Native 探测检出 KernelSU 痕迹。"));
        m.put("apatch_found", new EvidenceMeta("APatch 内核补丁路径", "检出 APatch / KPatch 内核补丁组件。"));
        m.put("apatch", new EvidenceMeta("APatch 内核补丁路径", "Native 探测检出 APatch 痕迹。"));
        m.put("modules_found", new EvidenceMeta("Root 模块目录", "检出 Root 扩展模块目录，可能挂载隐藏或改机模块。"));
        m.put("modules", new EvidenceMeta("Root 模块目录", "Native 探测检出 Root 扩展模块目录。"));
        m.put("syscall_mismatch", new EvidenceMeta("系统调用访问结果矛盾", "同一路径不同系统调用结果矛盾，存在 Root 隐藏对抗框架。"));
        m.put("listing_mismatch", new EvidenceMeta("目录遍历与访问不一致", "父目录遍历结果与直接访问不一致，存在敏感路径隐藏。"));
        m.put("ksu_prctl", new EvidenceMeta("内核级 Root 接口响应", "内核响应 KernelSU/APatch 私有 prctl 指令。"));
        m.put("kernelpatch_truncate", new EvidenceMeta("KernelPatch 内核钩子响应", "检测到 APatch/KernelPatch sys_truncate 超级调用接口。"));
        m.put("kernelpatch_supercall_hello", new EvidenceMeta("KernelPatch SuperCall 握手响应", "内核响应 APatch/KernelPatch 私有 SuperCall 魔数（0x11581158）。"));
        m.put("ksu_reboot", new EvidenceMeta("KernelSU reboot 魔数响应", "内核响应 KernelSU 私有 reboot 魔数协议。"));
        m.put("ksu_ioctl", new EvidenceMeta("KernelSU ioctl 通道响应", "检出 KernelSU ioctl 驱动或匿名 fd 控制接口。"));
        m.put("ksu_timing_sidechannel", new EvidenceMeta("KernelSU 内核路径时序侧信道", "敏感路径系统调用耗时分布呈现显著内核钩子拦截特征。"));
        m.put("susfs_probe", new EvidenceMeta("SUSFS 内核隐藏模块痕迹", "检出 SUSFS 路径伪装或挂载隐藏侧信道特征。"));
        m.put("netlink_cap_leak", new EvidenceMeta("Netlink 内核权限异常暴露", "应用进程在非特权上下文中异常具备高危 Netlink 内核访问能力。"));
        m.put("selinux_permissive", new EvidenceMeta("SELinux 处于宽松模式", "SELinux 强制访问控制已降级为 Permissive。"));
        m.put("selinux_enforce_conflict", new EvidenceMeta("SELinux 强制模式多源冲突", "Java/Native/状态页对 SELinux enforce 状态的观测相互矛盾。"));
        m.put("selinux_policy_dirty", new EvidenceMeta("SELinux 策略异常篡改", "检出 Magisk/KSU/APatch 注入的自定义 SELinux 域策略规则。"));
        m.put("system_tmpfs_mount", new EvidenceMeta("只读系统分区异常 tmpfs 挂载", "只读系统子路径被 tmpfs 覆盖，常用于注入根证书或替换文件。"));
        m.put("isolated_mount_diff", new EvidenceMeta("隔离进程挂载视图差异", "isolatedProcess 独立挂载视图暴露了主进程被 Shamiko/DenyList 卸载隐藏的 Root 挂载项。"));
        m.put("statx_mnt_id_hidden", new EvidenceMeta("statx 挂载 ID 隐匿异常", "statx(STATX_MNT_ID) 返回的挂载 ID 在 /proc/self/mountinfo 中缺失，存在内核挂载隐藏。"));
        m.put("system_ro_rw_mount", new EvidenceMeta("系统只读分区被以可写方式挂载", "只读系统分区挂载项含精确 rw 标志，系统完整性可能已遭破坏。"));
        m.put("mount_mtime_mismatch", new EvidenceMeta("挂载目录时间戳双读不一致", "多次底层 fstatat 观测系统目录 st_mtime 出现矛盾，存在路径劫持或覆写。"));
        m.put("statfs_overlay_on_system", new EvidenceMeta("系统目录检出 OverlayFS 覆写", "statfs 检出系统只读路径被 OverlayFS 覆盖挂载。"));
        m.put("statfs_tmpfs_on_system", new EvidenceMeta("系统目录检出 Tmpfs 覆写", "statfs 检出系统只读路径被 Tmpfs 内存文件系统覆盖。"));
        m.put("stealth_root_with_unmount", new EvidenceMeta("隐蔽 Root 伴随挂载隐藏（C9）", "常规 Root 路径检查全阴性但隔离进程挂载视图或 Bionic 属性区暴露底层篡改。"));

        // Bionic Prop Forensics, Hardware Consistency & Custom ROM (Phase 2)
        m.put("bootloader_unlocked", new EvidenceMeta("Bootloader 已解锁", "设备启动链已解锁，允许刷入第三方镜像或 Root。"));
        m.put("verified_boot_state", new EvidenceMeta("Verified Boot 状态异常", "启动校验状态非官方锁定绿态。"));
        m.put("vbmeta_empty_input_digest", new EvidenceMeta("VBMeta 空摘要伪造陷阱", "Verified Boot 属性声称绿态但 vbmeta.digest 为空摘要，疑似属性伪造。"));
        m.put("bionic_prop_hole", new EvidenceMeta("Bionic 属性共享内存空洞", "只读 __properties__ 区域检出 resetprop 删除属性遗留的 trie 空洞。"));
        m.put("prop_area_hole", new EvidenceMeta("Bionic 属性共享内存空洞", "只读 __properties__ 区域检出 resetprop 删除属性遗留的 trie 空洞。"));
        m.put("prop_area_hole_critical", new EvidenceMeta("核心属性区共享内存空洞", "关键只读属性分区检出 resetprop 删除遗留的 trie 空洞。"));
        m.put("prop_area_serial_anom", new EvidenceMeta("Bionic 属性序列号篡改异常", "系统只读属性 serial 计数异常偏高，疑似运行期被 resetprop 改写。"));
        m.put("prop_ro_serial_modified", new EvidenceMeta("Bionic 属性序列号篡改异常", "系统只读属性 serial 计数异常偏高，疑似运行期被 resetprop 改写。"));
        m.put("prop_tail_residual", new EvidenceMeta("Bionic 属性尾字节残留", "只读属性字符串终止符后存在未清零历史覆写残留。"));
        m.put("prop_ro_nul_tail_residual", new EvidenceMeta("Bionic 属性尾字节残留", "只读属性字符串终止符后存在未清零历史覆写残留。"));
        m.put("prop_area_meta_anomaly", new EvidenceMeta("Bionic 属性区元数据异常", "系统只读属性共享内存区头部元数据偏离标准基线。"));
        m.put("prop_area_selinux_anomaly", new EvidenceMeta("Bionic 属性区 SELinux 上下文异常", "只读属性文件 SELinux 安全上下文与预期不符。"));
        m.put("kernel_dirty_on_release", new EvidenceMeta("正式版系统运行自编译脏内核", "release-keys 构建的内核版本带有 -dirty 后缀，常见于自编译 KernelSU / 第三方内核。"));
        m.put("pif_spoof", new EvidenceMeta("PlayIntegrityFix 伪造痕迹", "检出 PlayIntegrityFix / PIF 属性指纹篡改侧信道特征。"));
        m.put("midr_mismatch", new EvidenceMeta("ARM64 CPU 寄存器与属性矛盾", "硬件 MIDR_EL1 芯片识别码与系统宣称 SoC/平台不一致，存在硬件伪造。"));
        m.put("midr_sysfs_mismatch", new EvidenceMeta("ARM64 MIDR_EL1 与 sysfs 矛盾", "硬件 MIDR_EL1 指令读数与 sysfs CPU 标识不一致，存在内核/属性伪造。"));
        m.put("midr_cpuinfo_mismatch", new EvidenceMeta("ARM64 MIDR_EL1 与 cpuinfo 矛盾", "硬件 MIDR_EL1 指令读数与 /proc/cpuinfo 硬件字段不一致。"));
        m.put("sysfs_cpuinfo_mismatch", new EvidenceMeta("sysfs 与 cpuinfo CPU 标识矛盾", "sysfs 与 /proc/cpuinfo 报告的处理器型号不一致。"));
        m.put("kernel_source_mismatch", new EvidenceMeta("多源内核版本不一致", "uname、/proc/version 与内核构建属性三源交叉比对存在矛盾。"));
        m.put("kernel_uname_osrelease_mismatch", new EvidenceMeta("uname 与 osrelease 内核版本矛盾", "原始 uname 与 /proc/sys/kernel/osrelease 读数不一致，疑似 SUSFS 内核伪造。"));
        m.put("kernel_uname_proc_version_mismatch", new EvidenceMeta("uname 与 /proc/version 矛盾", "原始 uname 与 /proc/version 内核版本字符串不一致。"));
        m.put("widevine_java_ndk_mismatch", new EvidenceMeta("Widevine DRM 跨层不一致", "Java 与 NDK MediaDrm 设备标识或安全级别读数自相矛盾。"));
        m.put("community_rom", new EvidenceMeta("社区第三方 ROM", "设备运行非厂商原厂社区定制 ROM（常规场景仅作提示）。"));
        m.put("stagefright_custom_symbol", new EvidenceMeta("libstagefright 社区定制符号", "系统媒体库检出第三方社区 ROM 定制符号（常规场景仅作提示）。"));
        m.put("framework_res_multi_dev", new EvidenceMeta("framework-res 多块设备映射", "系统框架资源同时映射于多个块设备，疑似定制 ROM 或覆盖挂载。"));

        // Deep Frida, Zygisk & LSPosed Probes (Phase 2)
        m.put("fd_linjector", new EvidenceMeta("Frida linjector 句柄注入", "/proc/self/fd 检出 Frida linjector 匿名/内存注入句柄。"));
        m.put("fd_frida", new EvidenceMeta("Frida 文件描述符痕迹", "/proc/self/fd 指向 Frida Agent/Gadget 句柄。"));
        m.put("anon_elf_exec", new EvidenceMeta("匿名可执行内存检出 ELF 镜像", "无文件关联的匿名 r-xp 内存页含完整 ELF 头，疑似隐蔽内存加载器注入。"));
        m.put("stealth_so_hidden_in_maps", new EvidenceMeta("隐匿动态库未现身 /proc/self/maps", "dl_iterate_phdr 枚举到已加载库但 maps 中缺失，存在 maps 过滤对抗。"));
        m.put("stealth_so_unlinked", new EvidenceMeta("动态库脱离链接器链表", "maps 中存在未注册于 dl_iterate_phdr 链表的匿名/手工映射动态库。"));
        m.put("sigaction_anon_handler", new EvidenceMeta("异常信号处理器指向匿名内存", "SIGSEGV/SIGTRAP/SIGILL 信号处理函数指向匿名可执行区，疑似异常劫持。"));
        m.put("zygisk_atexit_anon", new EvidenceMeta("Zygisk atexit 匿名回调残留", "Bionic atexit 表存在指向匿名可执行页的回调函数指针。"));
        m.put("zygisk_atexit_holes", new EvidenceMeta("Zygisk atexit 连续卸载空洞", "Bionic atexit 数组出现连续 3 个以上运行时锚定空洞，高度疑似 Zygisk 模块卸载残留。"));
        m.put("lsposed_binder_magic", new EvidenceMeta("LSPosed Binder 魔数响应", "系统服务 Binder 响应 LSPosed 私有事务码 0x5F4C5350。"));
        m.put("lsposed_gid_mismatch", new EvidenceMeta("Zygote 附加 GID 权限异常", "进程 /proc/self/status Groups 存在与授权权限不符的异常附加 GID。"));
        m.put("lsposed_stack_trace", new EvidenceMeta("全线程调用栈检出 Xposed/LSPosed", "异常栈或全线程堆栈暴露 LSPosed/XposedBridge 钩子帧。"));
        m.put("lsposed_uncaught_handler", new EvidenceMeta("全局异常处理器指向 Hook 框架", "默认 UncaughtExceptionHandler 归属 Xposed/LSPosed 类加载器。"));

        // ADB Protocol Forensics (Phase 2)
        m.put("settings_adb_enabled", new EvidenceMeta("USB ADB 调试已开启", "设备开启了 USB 调试桥。"));
        m.put("settings_adb_wifi_enabled", new EvidenceMeta("无线 ADB 调试已开启", "设备开启了无线网络调试，远程接入面扩大。"));
        m.put("adbd_socket", new EvidenceMeta("检出 /dev/socket/adbd 套接字",
                "底层系统调用确认 /dev/socket/adbd 套接字节点存在（USB/无线调试开启时常见）。"));
        m.put("jdwp_control_socket", new EvidenceMeta("检出 @jdwp-control 控制通道",
                "抽象命名空间 @jdwp-control 响应连接，表明系统调试桥控制通道处于活跃状态。"));
        m.put("adbd_contradiction", new EvidenceMeta("隐藏 ADB 守护进程矛盾", "系统属性声称 init.svc.adbd=stopped 但底层协议探针证实 adbd 仍活跃。"));
        m.put("adbd_hidden_socket", new EvidenceMeta("隐藏 /dev/socket/adbd 套接字", "底层系统调用证实 /dev/socket/adbd 存在而系统属性隐藏了 ADB 状态。"));
        m.put("adbd_hidden_jdwp_control", new EvidenceMeta("隐藏 @jdwp-control 协议通道", "抽象命名空间 @jdwp-control 响应连接而系统属性宣称 ADB 关闭。"));

        // Virtualization, Emulator, Cloud Phone & Syscall Traps (Phase 2)
        m.put("virtual_gpu", new EvidenceMeta("虚拟 GPU 渲染器", "EGL 渲染器为 SwiftShader/llvmpipe/virgl 等虚拟实现。"));
        m.put("emu_file", new EvidenceMeta("模拟器特征文件", "文件系统检出 QEMU / 现代模拟器专属节点或驱动。"));
        m.put("emu_pkg", new EvidenceMeta("模拟器宿主应用包", "设备安装有已知模拟器配套组件包。"));
        m.put("emu_prop", new EvidenceMeta("现代虚拟化平台属性", "检出 Waydroid/Cuttlefish/WSA/Corellium/LDPlayer 9/MuMu 12 平台特征属性。"));
        m.put("native_bridge", new EvidenceMeta("Native Bridge 二进制翻译层", "检出 houdini/libnb/libndk_translation 翻译层，ARM 应用运行于 x86 模拟环境。"));
        m.put("avf_virtualization", new EvidenceMeta("AVF/Microdroid 虚拟化客体", "联合命中多项 Android Virtualization Framework 客体特征。"));
        m.put("arm64_clock_drift", new EvidenceMeta("ARM64 硬件时钟源漂移", "cntvct_el0 硬件计数器与单调时钟出现显著虚拟化时钟漂移。"));
        m.put("sched_yield_low_cv", new EvidenceMeta("调度耗时人工低方差分布", "sched_yield 耗时变异系数极低，仅作为虚拟化辅助信息佐证。"));
        m.put("zero_hw_codec", new EvidenceMeta("零 SoC 硬件编解码器", "系统仅提供 c2.android.*/OMX.google.* 软解，无物理 SoC 硬件编解码器。"));
        m.put("sensor_static_zero_var", new EvidenceMeta("物理传感器静态零方差", "加速度计/陀螺仪连续采样标准差为 0.0，缺乏物理 MEMS 热噪声，联合硬件异常佐证云机/模拟器。"));
        m.put("sacrificial_syscall_mismatch", new EvidenceMeta("用户态系统调用翻译劫持", "一次性隔离子进程对比 libc 与原始内联 syscall 结果矛盾，证实处于虚拟多开/syscall 拦截容器。"));
        m.put("cloud_pkg", new EvidenceMeta("云手机配套组件", "检出云真机平台专属客户端或控制服务包。"));
        m.put("cloud_prop", new EvidenceMeta("云手机系统属性", "检出云手机平台特征系统属性。"));
        m.put("wired_interface", new EvidenceMeta("有线以太网接口", "设备暴露 ethN 有线网卡（云机常见，单独出现仅作弱佐证）。"));
        m.put("battery_zero", new EvidenceMeta("电池电压/温度归零异常", "电池电压或温度读数为 0，疑似虚拟化供电环境。"));
        m.put("battery_anomaly", new EvidenceMeta("电池充电状态矛盾", "电量 100% 且显示充电中但无外部供电接入。"));
        m.put("low_camera_count", new EvidenceMeta("摄像头硬件缺失", "设备未报告任何物理摄像头硬件。"));
        m.put("very_low_sensor_count", new EvidenceMeta("物理传感器极少", "物理传感器数量显著低于真实手持终端。"));

        // Phase 3: TEE Hardware Trust Root, Bootloader/C8 & Widevine Parity
        m.put("tee_keybox_revoked", new EvidenceMeta("TEE 硬件证明密钥盒已吊销",
                "证书链序列号命中 Google 单调离线 CRL 吊销底线，疑似使用泄漏/滥用的盗版 Keybox（如 TrickyStore）。"));
        m.put("tee_chain_untrusted", new EvidenceMeta("TEE 证书链未锚定 Google 信任根",
                "硬件密钥证明证书链签名、约束、有效期或根证书 SPKI 未通过 Google Hardware Attestation Root 校验。"));
        m.put("tee_chain_signature_invalid", new EvidenceMeta("TEE 证书链密码学验签失败",
                "硬件证明证书链存在无效签名，疑似证书被篡改或伪造签发。"));
        m.put("tee_issuer_chain_invalid", new EvidenceMeta("TEE 证书链签发者链路断裂",
                "证书链 Subject/Issuer 或 RFC 5280 约束不连续，存在伪造证书链痕迹。"));
        m.put("tee_aosp_root_spoofed_hw", new EvidenceMeta("AOSP 软件根伪装硬件证明",
                "证书链锚定 AOSP 软件测试根却宣称 TEE/StrongBox 硬件安全级别，确认存在密钥证明伪造。"));
        m.put("tee_attestation_extension_invalid", new EvidenceMeta("OID .17 硬件证明扩展解析异常",
                "硬件密钥证明扩展 DER 结构非法或缺失关键字段，疑似伪造证明扩展。"));
        m.put("tee_challenge_mismatch", new EvidenceMeta("硬件证明随机挑战值不匹配",
                "证书扩展中的 attestationChallenge 与本次随机挑战不符，疑似重放缓存证明链。"));
        m.put("tee_leaf_extension_shadow", new EvidenceMeta("叶子证书尝试覆盖中间证书扩展",
                "证书链多级同时携带 OID .17 扩展，疑似在叶子证书层注入伪造扩展以遮蔽真实根状态。"));
        m.put("tee_rkp_extension_invalid", new EvidenceMeta("RKP 扩展 CBOR/厂商校验失败",
                "RKP OID .30 规范 CBOR 编码违规或厂商字段与叶子证书 tag 716 矛盾。"));
        m.put("tee_root_of_trust_unlocked", new EvidenceMeta("硬件 RootOfTrust 确认解锁",
                "TEE/StrongBox OID .17 硬件强制 RootOfTrust 报告 deviceLocked=false，Bootloader 处于解锁状态。"));
        m.put("tee_verified_boot_unverified", new EvidenceMeta("硬件 Verified Boot 状态异常",
                "TEE/StrongBox RootOfTrust 报告启动校验状态非官方 VERIFIED（绿态）。"));
        m.put("tee_leaf_der_anomaly", new EvidenceMeta("叶子证书 DER 结构伪造异常",
                "严格最小 DER 校验发现非最小 BER 长度或 32 位十六进制占位模板，疑似伪造密钥证明证书。"));
        m.put("tee_leaf_der_hex_template", new EvidenceMeta("叶子证书检出 32 位十六进制模板占位",
                "叶子证书 Subject/扩展含 32 位纯十六进制占位模板，疑似 TrickyStore 等工具静态模板伪造。"));
        m.put("tee_leaf_der_non_minimal_ber", new EvidenceMeta("叶子证书含非最小 BER 长度编码",
                "叶子证书 DER 长度字段违反严格最小编码规范，疑似手工修补证书字节流。"));
        m.put("tee_leaf_der_parity_mismatch", new EvidenceMeta("Java 与 Native 叶子 DER 校验矛盾",
                "Java 与 Native 双层对同一叶子证书 DER 的校验结果不一致，疑似存在运行期 Hook 拦截。"));
        m.put("tee_rkp_manufacturer_mismatch", new EvidenceMeta("RKP 厂商字段与证书不一致",
                "RKP OID .30 规范 CBOR map[3] 厂商字段与叶子证书 tag 716 矛盾，存在跨设备证明伪造。"));
        m.put("tee_rkp_cbor_anomaly", new EvidenceMeta("RKP 扩展 CBOR 编码违规",
                "RKP OID .30 扩展存在重复键、非规范整数或尾部多余字节，违反严格规范 CBOR 契约。"));
        m.put("tee_binder_maps_artifact", new EvidenceMeta("内存检出 TrickyStore / Keystore 拦截库",
                "/proc/self/maps 检出 TrickyStore 或 keystore_interceptor 相关模块痕迹。"));
        m.put("tee_tricky_maps", new EvidenceMeta("内存检出 TrickyStore / Keystore 拦截库",
                "/proc/self/maps 检出 TrickyStore 或 keystore_interceptor 相关模块痕迹。"));
        m.put("tee_binder_ioctl_hook", new EvidenceMeta("libbinder ioctl 被 Hook 篡改",
                "libbinder.so ioctl GOT/16 字节入口或 BINDER_VERSION 三路校验发现劫持，疑似拦截 Keystore2 Binder 通信。"));
        m.put("tee_binder_version_mismatch", new EvidenceMeta("BINDER_VERSION 三路调用矛盾",
                "Libc / 原始 syscall / 内联汇编对 BINDER_VERSION 的结果不一致，确认存在用户态 Binder 劫持。"));
        m.put("tee_binder_honeypot_latency", new EvidenceMeta("Binder 蜜罐轮换时序异常",
                "3 轮轮换顺序 Binder 蜜罐中位数/MAD 时序显著偏移，疑似存在用户态 Keystore2 代理转发。"));
        m.put("tee_binder_honeypot_timing", new EvidenceMeta("Binder 蜜罐轮换时序异常",
                "3 轮轮换顺序 Binder 蜜罐中位数/MAD 时序显著偏移，疑似存在用户态 Keystore2 代理转发。"));
        m.put("tee_grant_chain_split", new EvidenceMeta("Keystore2 Grant-Domain 跨 UID 链分裂",
                "Domain.APP 与隔离进程 Domain.GRANT 读取的证明链 SHA-256 分裂或丢失，击穿 TrickyStore 主 UID 拦截。"));
        m.put("tee_keystore2_tag_user_id", new EvidenceMeta("Keystore2 generateKey 尾包异常 TAG_USER_ID",
                "generateKey 返回 Parcel 尾部携带异常 SOFTWARE TAG_USER_ID (0x300001F5)，指向代理注入伪造。"));
        m.put("tee_generate_key_parcel_spoof", new EvidenceMeta("Keystore2 generateKey 尾包结构伪造",
                "generateKey 返回 Parcel 缺失原厂末尾 SOFTWARE TAG_USER_ID 特征，指向 TrickyStore/代理伪造。"));
        m.put("tee_generate_key_creation_level", new EvidenceMeta("Keystore2 创建时间安全级别异常",
                "generateKey 授权列表中的 CREATION_DATETIME 安全级别偏离原厂 Keystore2 语义。"));
        m.put("tee_post_processing_mismatch", new EvidenceMeta("API 35+ RKP 后处理证明矛盾",
                "RkpdProvisioned 与 PURPOSE_ATTEST_KEY 交叉采样的 RootOfTrust 结果不一致。"));
        m.put("tee_post_processing_rot_divergence", new EvidenceMeta("API 35+ RKP 后处理 RootOfTrust 分裂",
                "RkpdProvisioned 与 PURPOSE_ATTEST_KEY 两条证明路径返回的 RootOfTrust 互相矛盾。"));
        m.put("tee_post_processing_latency", new EvidenceMeta("API 35+ 密钥证明延迟分布异常",
                "RKP 与 ATTEST_KEY 交替采样的配对耗时呈现异常代理解析特征。"));
        m.put("tee_overwrite_cache_residue", new EvidenceMeta("覆写双读反缓存陷阱命中",
                "覆写临时密钥别名后仍读回旧证明链或序列号，暴露 TEE Simulator / TEES-RS 缓存伪造。"));
        m.put("tee_overwrite_stale_chain", new EvidenceMeta("覆写双读检出陈旧证明链缓存",
                "覆写临时密钥别名后仍读回旧证明链，确认存在 TEE Simulator / TEES-RS 证书缓存伪造。"));
        m.put("tee_lifecycle_stale_serial", new EvidenceMeta("密钥重建序列号陈旧异常",
                "删除并重新生成临时密钥后序列号或公钥未刷新，存在密钥生命周期缓存劫持。"));
        m.put("tee_strongbox_level_mismatch", new EvidenceMeta("StrongBox KeyInfo 与证明级别矛盾",
                "KeyInfo 报告的安全级别与硬件证明证书中的安全级别不一致。"));
        m.put("tee_strongbox_soft_emulation", new EvidenceMeta("StrongBox 软模拟耗时异常",
                "StrongBox 密钥生成或签名耗时异常偏低（<20ms / <2ms）或未拒绝非法大密钥参数，疑似软件模拟。"));
        m.put("tee_soft_strongbox", new EvidenceMeta("StrongBox 疑似软件模拟",
                "StrongBox 密钥生成/签名耗时过低或接受非法 RSA-4096/P-521 参数，疑似软件模拟实现。"));
        m.put("tee_vintf_hal_mismatch", new EvidenceMeta("VINTF KeyMint HAL 版本矛盾",
                "磁盘 VINTF 清单声明的 KeyMint HAL 版本与运行时观测安全级别或版本不一致。"));
        m.put("tee_operation_error_path_anomaly", new EvidenceMeta("KeyMint 异常路径行为违规",
                "超长输入（>0x8000）或 abort 后 updateOperation 未按规范拒绝，疑似伪造 KeyMint 实现。"));
        m.put("tee_keystore2_error_path_diverged", new EvidenceMeta("Keystore2 异常路径语义偏离",
                "超长输入（>0x8000）或 abort 后 update 未返回规范错误，疑似伪造 Keystore2 代理实现。"));
        m.put("tee_keymint_update_aad_accepted", new EvidenceMeta("KeyMint 非 AEAD updateAad 行为差异",
                "非 AEAD 签名操作接受了 updateAad 调用（部分厂商 KeyMint 存在该实现差异）。"));
        m.put("spoofed_verified_boot_props", new EvidenceMeta("启动链属性伪造绿态（C8）",
                "硬件 RootOfTrust 或 VBMeta 空摘要陷阱证实设备已解锁，但系统属性仍伪造 verifiedbootstate=green + flash.locked=1。"));
        m.put("spoofed_verified_boot", new EvidenceMeta("启动链绿态伪装（C8）",
                "硬件信任根与系统启动属性严重矛盾，确认存在 resetprop / Specter 绿态伪装。"));
        m.put("attested_vbmeta_all_zero", new EvidenceMeta("硬件 VBMeta 摘要全零异常",
                "硬件 RootOfTrust 宣称 VERIFIED 但 verifiedBootHash 为全零字节，存在启动校验摘要异常。"));
        m.put("attested_vbmeta_mismatch", new EvidenceMeta("硬件与系统 VBMeta 摘要矛盾",
                "硬件 RootOfTrust.verifiedBootHash 与系统属性 ro.boot.vbmeta.digest 不一致，疑似属性伪造。"));
        m.put("knox_warranty_void", new EvidenceMeta("Samsung Knox 保修熔丝已熔断",
                "三星设备 ro.boot.warranty_bit 非 0，表明硬件熔丝曾因解锁/刷机永久熔断。"));
        m.put("bootconfig_unlock_marker", new EvidenceMeta("/proc/bootconfig 启动链异常标记",
                "内核 /proc/bootconfig 或 /proc/cmdline 暴露非锁定启动参数。"));
        m.put("hw_root_of_trust_unlocked", new EvidenceMeta("硬件证明确认 Bootloader 已解锁",
                "硬件 RootOfTrust 证实设备处于解锁状态。"));
        m.put("hw_verified_boot_unverified", new EvidenceMeta("硬件证明确认启动校验未通过",
                "硬件 RootOfTrust 证实 Verified Boot 非 VERIFIED 状态。"));
        m.put("widevine_l1_sentinel_system_id", new EvidenceMeta("Widevine L1 哨兵 SystemId 异常",
                "Widevine 宣称 L1 但返回哨兵 systemId=2147483647，高度疑似 DRM 伪造或损坏。"));
        m.put("widevine_hw_secure_downgrade", new EvidenceMeta("Widevine 硬件安全等级降级",
                "Widevine 会话降级且不满足 HW_SECURE_ALL 硬件保护要求。"));
        m.put("widevine_hw_secure_all_downgrade", new EvidenceMeta("Widevine 硬件安全等级降级",
                "Widevine 宣称 L1 且支持 HW_SECURE_ALL，但实际会话安全等级发生降级。"));

        // Phase 4: 16th Converged Domain — Threat Apps, Official Cert Lineage & HMA Side-Channels
        m.put("threat_app_cert", new EvidenceMeta("检出已知 Root/高危工具官方签名",
                "应用签名证书或 v3/v3.1 轮换谱系命中内置官方发布证书（KernelSU / Magisk / APatch / HMA 等），Root 管理器自动归入 root_fw 家族去重。"));
        m.put("threat_app_custom_cert", new EvidenceMeta("命中策略自定义高危签名证书",
                "目标应用签名证书命中宿主 ThreatAppPolicy 配置的自定义高危证书指纹。"));
        m.put("threat_app_native_payload", new EvidenceMeta("检出 Root/高危工具原生守护载荷",
                "目标应用 nativeLibraryDir 含 libksud.so / libapd.so / libkpatch.so / libmagisk.so 等原生提权守护载荷，免疫包名伪装。"));
        m.put("threat_app_zygote_preload", new EvidenceMeta("检出高危应用 Zygote 预加载声明",
                "目标应用 AndroidManifest.xml 声明了 Root/注入框架特征 android:zygotePreloadName（如 .magica.AppZygotePreload）。"));
        m.put("threat_app_package", new EvidenceMeta("检出内置目录高危工具包名",
                "检测到内置目录声明的 Root 管理器、隐藏框架或改机/插桩工具包名（含自编译重签名变体）。"));
        m.put("threat_app_custom_pkg", new EvidenceMeta("命中策略自定义高危包名",
                "检测到宿主自定义 ThreatAppPolicy 声明的高危包名。"));
        m.put("threat_app_perm_combo", new EvidenceMeta("命中策略高危权限组合",
                "目标应用同时持有宿主策略声明的高危权限组合。"));
        m.put("hma_uid_visibility_hidden", new EvidenceMeta("HMA 隐藏活跃应用 UID 侧信道",
                "一次性子进程 getpriority(PRIO_USER) 检出的活跃应用 UID 在 Binder getPackagesForUid 中不可见，证实存在应用列表隐藏。"));
        m.put("hma_seccomp_foreign_listener", new EvidenceMeta("Seccomp 外部用户态监听器冲突",
                "SECCOMP_FILTER_FLAG_NEW_LISTENER 安装检出外部拦截监听器，存在内核可见性过滤对抗。"));
        m.put("hma_seccomp_query_trapped", new EvidenceMeta("Seccomp 探针查询被异常拦截",
                "一次性子进程执行 UID 可见性查询时触发异常陷阱，疑似被外部 Seccomp/Hook 拦截。"));
        m.put("hma_seccomp_suppressed", new EvidenceMeta("Seccomp 用户态通知回调遭抑制",
                "内核未将预期的 UID 查询通知投递至自建 Seccomp 监听器，疑似隐藏模块篡改可见性过滤路径。"));
        m.put("hma_cross_user_suppression", new EvidenceMeta("HMA 跨用户异常抑制侧信道",
                "跨用户 MATCH_ANY_USER 查询未返回标准 SecurityException 而是被抑制为 NameNotFoundException/null，暴露 HMA 挂钩。"));
        m.put("hma_ordered_broadcast_missing_result", new EvidenceMeta("HMA-OSS 有序广播 resultTo 丢失",
                "有序广播终态回调 resultTo 缺失而同轮宿主自检对照正常，命中 HMA-OSS #164 行为侧信道。"));
        m.put("hma_ordered_broadcast_semantic", new EvidenceMeta("HMA-OSS 有序广播语义标记泄漏",
                "非有序场景下异常暴露 isOrderedBroadcast()==true 而自检对照正常，命中 HMA-OSS #173 行为侧信道。"));
        m.put("hma_permission_service_diff", new EvidenceMeta("PermissionService 与 PM 列表差集异常",
                "Android 15+ PermissionService UID 权限查证与 getPackagesForUid 存在差集，暴露 HMA 隐藏目标。"));
        m.put("thanox_ipc_active", new EvidenceMeta("检出 Thanox 系统级隐藏框架",
                "dropbox Binder 服务返回 github.tornaco.android.thanos.core.IThanos 接口描述符，确认运行 Thanox 隐藏/管控框架。"));

        // Supplemental SDK Evidence Codes (100% parity with :riskengine-sdk detectors & probes)
        m.put("adb_tcp_port", new EvidenceMeta("ADB 网络调试端口监听",
                "设备开启了 TCP/Wi-Fi ADB 调试端口（如 5555），允许局域网直接发起 ADB 连接。"));
        m.put("adbd_process", new EvidenceMeta("检出活跃 adbd 守护进程",
                "系统存在运行中的 adbd 调试守护进程。"));
        m.put("adbd_pid_port", new EvidenceMeta("adbd 进程绑定网络调试端口",
                "adbd 守护进程正监听 TCP 调试端口。"));
        m.put("usb_function", new EvidenceMeta("USB 配置包含 ADB 功能",
                "系统 USB 功能配置属性包含 adb 调试通道。"));
        m.put("usb_state", new EvidenceMeta("USB 调试状态活跃",
                "系统 USB 状态节点报告处于调试连接态。"));
        m.put("su_binary", new EvidenceMeta("su 提权可执行文件",
                "系统路径检出 su 提权二进制文件，可突破应用沙箱隔离。"));
        m.put("busybox", new EvidenceMeta("检出 BusyBox 工具集",
                "系统路径检出常随 Root 环境安装的 BusyBox 二进制文件。"));
        m.put("test_keys", new EvidenceMeta("系统使用测试签名（test-keys）",
                "Build.TAGS 含 test-keys，表明系统镜像并非正式量产 release-keys 签名。"));
        m.put("magisk_artifact", new EvidenceMeta("Magisk 框架路径",
                "检出 Magisk Root 框架核心目录或组件痕迹。"));
        m.put("ksu_artifact", new EvidenceMeta("KernelSU 框架路径",
                "检出内核级 Root 方案 KernelSU 核心路径痕迹。"));
        m.put("apatch_artifact", new EvidenceMeta("APatch 内核补丁路径",
                "检出 APatch / KernelPatch 内核补丁组件路径。"));
        m.put("root_modules_dir", new EvidenceMeta("Root 模块目录",
                "检出 /data/adb/modules 等 Root 扩展模块目录。"));
        m.put("kernelpatch_truncate_hit", new EvidenceMeta("KernelPatch sys_truncate 驻留侧信道命中",
                "一次性子进程 sys_truncate + mincore 侧信道证实内核挂载了 KernelPatch/APatch 超级调用钩子。"));
        m.put("ksu_reboot_ioctl", new EvidenceMeta("KernelSU reboot/ioctl 协议响应",
                "内核响应 KernelSU 私有 reboot 魔数或 KSU_IOCTL_GET_INFO 接口，证实内核级 Root 存在。"));
        m.put("ksu_driver_fd", new EvidenceMeta("KernelSU 驱动匿名句柄",
                "进程或内核侧信道检出 KernelSU 驱动匿名文件描述符接口。"));
        m.put("ksu_prctl_timing_anomaly", new EvidenceMeta("KernelSU prctl 时序侧信道异常",
                "ARM64 硬件计数器观测到 prctl 路径存在显著 KernelSU 内核钩子拦截耗时特征。"));
        m.put("devpts_ksu_xattr", new EvidenceMeta("devpts 检出 KernelSU SELinux 扩展属性",
                "伪终端设备检出 KernelSU 注入的异常扩展属性标签。"));
        m.put("setresuid_unexpected_success", new EvidenceMeta("非特权进程 setresuid 异常成功",
                "一次性子进程在非 root 权限下调用 setresuid 异常成功，表明内核凭据校验被篡改。"));
        m.put("susfs_setresuid_sigkill", new EvidenceMeta("SUSFS 隐藏钩子触发异常信号",
                "一次性子进程在提权探针中触发 SUSFS/内核隐藏模块异常终止行为。"));
        m.put("netlink_link_leak", new EvidenceMeta("Netlink 链路接口权限异常暴露",
                "非特权上下文异常获取到受限 Netlink 链路表信息，疑似 SELinux 策略被篡改。"));
        m.put("netlink_neigh_leak", new EvidenceMeta("Netlink 邻居表权限异常暴露",
                "非特权上下文异常获取到受限 Netlink 邻居表信息，疑似 SELinux 策略被篡改。"));
        m.put("selinux_context_type_present", new EvidenceMeta("检出异常 SELinux 域类型",
                "系统暴露出 Magisk/KSU/APatch 注入的自定义 SELinux 安全上下文类型。"));
        m.put("selinux_status_abi_violation", new EvidenceMeta("SELinux 状态页 ABI 结构违规",
                "/sys/fs/selinux/status 二进制头违反内核 ABI 规范，疑似被伪造或 Hook。"));
        m.put("selinux_status_header_anomaly", new EvidenceMeta("SELinux 状态页头部异常",
                "/sys/fs/selinux/status 头部版本号或字段异常偏离内核标准。"));
        m.put("magisk_mount", new EvidenceMeta("检出 Magisk 挂载痕迹",
                "挂载表检出 Magisk magic_mount / worker 覆盖挂载项。"));
        m.put("kernelsu_mount", new EvidenceMeta("检出 KernelSU 挂载痕迹",
                "挂载表检出 KernelSU overlay / KSU 模块覆盖挂载项。"));
        m.put("module_mount", new EvidenceMeta("检出 Root 模块覆盖挂载",
                "系统目录被 /data/adb/modules 下的 Root 扩展模块覆盖挂载。"));
        m.put("mountinfo_magisk", new EvidenceMeta("mountinfo 检出 Magisk 挂载项",
                "/proc/self/mountinfo 暴露 Magisk 特征挂载源或挂载点。"));
        m.put("mountinfo_ksu", new EvidenceMeta("mountinfo 检出 KernelSU 挂载项",
                "/proc/self/mountinfo 暴露 KernelSU 特征挂载源或挂载点。"));
        m.put("debug_ramdisk_mount", new EvidenceMeta("检出 debug_ramdisk 异常挂载",
                "挂载表包含 /debug_ramdisk 挂载项，常见于 Magisk 或调试镜像启动环境。"));
        m.put("docker_mount", new EvidenceMeta("检出容器/Docker 挂载特征",
                "挂载表暴露容器文件系统特征，疑似运行在云机或容器化模拟环境。"));
        m.put("frida_port_open", new EvidenceMeta("Frida 默认监听端口开放",
                "本地回环检测到 Frida Server 监听端口，进程面临动态插桩风险。"));
        m.put("frida_pid", new EvidenceMeta("检出 Frida 守护进程",
                "系统存在活跃的 Frida Server 进程特征。"));
        m.put("frida_pid_port", new EvidenceMeta("Frida 进程绑定调试端口",
                "检出 Frida 守护进程正监听本地端口。"));
        m.put("frida_thread", new EvidenceMeta("进程内检出 Frida 注入线程",
                "/proc/self/task 检出 gum-js-loop / gmain / pool-frida 等 Frida 特征线程。"));
        m.put("xposed_class_found", new EvidenceMeta("检出 Xposed 框架类加载",
                "运行时类加载器检出 XposedBridge 等框架核心类。"));
        m.put("xposed_hooks_active", new EvidenceMeta("检出活跃 Xposed 方法挂钩",
                "XposedBridge 已在当前进程注册活跃的方法 Hook 回调。"));
        m.put("xposed_stack", new EvidenceMeta("调用栈检出 Xposed 钩子帧",
                "异常调用栈暴露 Xposed 框架代理执行帧。"));
        m.put("lsposed_all_threads_stack", new EvidenceMeta("全线程栈检出 LSPosed 帧",
                "遍历全线程调用栈发现 LSPosed/EdXposed 注入帧。"));
        m.put("lsposed_protected_api_stack", new EvidenceMeta("受保护 API 栈检出 LSPosed 钩子",
                "受保护系统 API 触发的异常栈暴露 LSPosed 拦截帧。"));
        m.put("lsposed_zygote_gid_mismatch", new EvidenceMeta("Zygote 附加 GID 权限异常",
                "进程 /proc/self/status Groups 存在与授权权限不符的异常附加 GID。"));
        m.put("zygisk_atexit_drift", new EvidenceMeta("Zygisk atexit 回调表基线漂移",
                "Bionic atexit 表项发生异常卸载或漂移，高度疑似 Zygisk 注入残留。"));
        m.put("partition_verity_disabled", new EvidenceMeta("系统分区 dm-verity 校验已关闭",
                "分区挂载或属性显示 dm-verity 完整性校验被禁用，系统镜像可能已遭修改。"));
        m.put("secureboot_disabled", new EvidenceMeta("Secure Boot 安全启动已关闭",
                "启动属性显示硬件安全启动校验未启用。"));
        m.put("verity_mode_disabled", new EvidenceMeta("AVB Verity 校验模式异常",
                "系统 veritymode 非 enforcing，启动分区完整性校验已降级或关闭。"));
        m.put("pif_maps_trace", new EvidenceMeta("进程内存检出 PlayIntegrityFix 模块",
                "/proc/self/maps 检出 PIF/PlayIntegrityFix 伪造注入库。"));
        m.put("pif_prop_active", new EvidenceMeta("PlayIntegrityFix 属性伪造已激活",
                "系统属性检出活跃的 PlayIntegrityFix 指纹伪造配置。"));
        m.put("pif_prop_disabled", new EvidenceMeta("检出已停用的 PlayIntegrityFix 属性",
                "系统属性残留已停用的 PlayIntegrityFix 伪造配置痕迹。"));
        m.put("pif_prop_present", new EvidenceMeta("检出 PlayIntegrityFix 属性痕迹",
                "系统属性暴露 PlayIntegrityFix / PIF 伪造模块配置项。"));
        m.put("prop_mismatch", new EvidenceMeta("系统属性跨层读数不一致",
                "Java 与 Native 读取的同一系统属性存在矛盾，疑似存在属性 Hook 伪造。"));
        m.put("abi_64bit_mismatch", new EvidenceMeta("64 位 ABI 声明与实际架构矛盾",
                "系统 64 位 ABI 列表与底层 CPU/ELF 架构读数不一致，疑似改机伪造。"));
        m.put("abi_arch_mismatch", new EvidenceMeta("ABI 与内核架构不一致",
                "ro.product.cpu.abi 与 uname 机器架构矛盾，存在二进制翻译或改机伪造。"));
        m.put("api_release_mismatch", new EvidenceMeta("Android API 等级与版本号矛盾",
                "Build.VERSION.SDK_INT 与 RELEASE 版本字符串不匹配，疑似系统属性被篡改。"));
        m.put("build_prop_mismatch", new EvidenceMeta("Build 常量与系统属性不一致",
                "android.os.Build 静态字段与底层 system_property 读数矛盾，存在改机 Hook。"));
        m.put("core_count_mismatch", new EvidenceMeta("CPU 核心数多源读数矛盾",
                "Java Runtime 与内核 sysfs/cpuinfo 报告的处理器核心数不一致。"));
        m.put("fingerprint_brand_mismatch", new EvidenceMeta("构建指纹与品牌型号矛盾",
                "ro.build.fingerprint 中的品牌/机型段与 Build.BRAND/MODEL 不一致，疑似改机。"));
        m.put("fingerprint_malformed", new EvidenceMeta("系统构建指纹格式非法",
                "ro.build.fingerprint 不符合标准 AOSP 段格式，疑似被非法篡改。"));
        m.put("kernel_java_os_version_mismatch", new EvidenceMeta("Java 与 Native 内核版本不一致",
                "System.getProperty(os.version) 与底层 uname 内核版本矛盾。"));
        m.put("kernel_proc_osrelease_version_mismatch", new EvidenceMeta("osrelease 与 /proc/version 内核版本矛盾",
                "/proc/sys/kernel/osrelease 与 /proc/version 内核版本不一致，疑似内核信息伪造。"));
        m.put("kernel_uname_kversion_mismatch", new EvidenceMeta("uname 与系统内核属性版本矛盾",
                "原始 uname 返回的内核版本与系统属性记录的内核版本不一致。"));
        m.put("kernel_version_banner_mismatch", new EvidenceMeta("内核版本横幅格式异常",
                "/proc/version 与标准内核版本横幅不一致，疑似被隐藏模块改写。"));
        m.put("partition_fingerprint_mismatch", new EvidenceMeta("多分区构建指纹严重矛盾",
                "system / vendor / product / bootimage 分区构建指纹不匹配，疑似混刷或改机伪造。"));
        m.put("partition_keytype_mismatch", new EvidenceMeta("分区签名密钥类型不一致",
                "各系统分区混用 release-keys 与 dev-keys/test-keys，存在刷机或篡改痕迹。"));
        EVIDENCE_META = Collections.unmodifiableMap(m);
    }

    private final StringResolver strings;

    public ReportFormatter(Context context) {
        this(new StringResolver() {
            @Override
            public String get(@StringRes int resId) {
                return context.getString(resId);
            }

            @Override
            public String get(@StringRes int resId, Object... formatArgs) {
                return context.getString(resId, formatArgs);
            }
        });
    }

    public ReportFormatter(StringResolver strings) {
        this.strings = strings;
    }

    /** Maps a normalized 0–100 score onto its ADR-0002 {@link RiskLevel} band. */
    public static RiskLevel riskLevelForScore(int score) {
        if (score >= RiskReport.DEADLY_THRESHOLD) return RiskLevel.DEADLY;
        if (score >= RiskReport.HIGH_THRESHOLD) return RiskLevel.HIGH;
        if (score >= RiskReport.MEDIUM_THRESHOLD) return RiskLevel.MEDIUM;
        if (score > 0) return RiskLevel.LOW;
        return RiskLevel.SAFE;
    }

    /** Returns the semantic foreground color resource matching a normalized 0–100 score band. */
    @ColorRes
    public static int scoreColorRes(int score) {
        return colorResForLevel(riskLevelForScore(score));
    }

    /** Returns the semantic background tint resource matching a normalized 0–100 score band. */
    @ColorRes
    public static int scoreBgRes(int score) {
        return bgResForLevel(riskLevelForScore(score));
    }

    @ColorRes
    private static int colorResForLevel(RiskLevel level) {
        if (level == null) return R.color.risk_unknown;
        switch (level) {
            case SAFE: return R.color.risk_safe;
            case LOW: return R.color.risk_low;
            case MEDIUM: return R.color.risk_medium;
            case HIGH: return R.color.risk_high;
            case DEADLY: return R.color.risk_deadly;
            case UNKNOWN:
            default: return R.color.risk_unknown;
        }
    }

    @ColorRes
    private static int bgResForLevel(RiskLevel level) {
        if (level == null) return R.color.risk_unknown_bg;
        switch (level) {
            case SAFE: return R.color.risk_safe_bg;
            case LOW: return R.color.risk_low_bg;
            case MEDIUM: return R.color.risk_medium_bg;
            case HIGH: return R.color.risk_high_bg;
            case DEADLY: return R.color.risk_deadly_bg;
            case UNKNOWN:
            default: return R.color.risk_unknown_bg;
        }
    }

    public List<DetectionResult> environmentDetections(RiskReport report) {
        List<DetectionResult> list = new ArrayList<>();
        for (DetectionResult d : report.getDetections()) {
            if (!d.getDetectorName().startsWith("collector:")) {
                list.add(d);
            }
        }
        list.sort((a, b) -> Integer.compare(detectionPriority(a), detectionPriority(b)));
        return list;
    }

    public int countCollectorCoverageGaps(RiskReport report) {
        int count = 0;
        for (DetectionResult d : report.getDetections()) {
            if (d.getDetectorName().startsWith("collector:")) {
                count++;
            }
        }
        return count;
    }

    public int countActionableAttention(List<DetectionResult> detections) {
        int count = 0;
        for (DetectionResult d : detections) {
            if (isActionableRisk(d)) {
                count++;
            }
        }
        return count;
    }

    public boolean isActionableRisk(DetectionResult d) {
        return !d.isInformational()
                && (d.getStatus() == DetectionStatus.DANGER || d.getStatus() == DetectionStatus.WARNING);
    }

    public boolean isInformationalItem(DetectionResult d) {
        return d.isInformational()
                && (d.getStatus() == DetectionStatus.DANGER || d.getStatus() == DetectionStatus.WARNING);
    }

    public boolean isIncompleteItem(DetectionResult d) {
        switch (d.getExecutionStatus()) {
            case PARTIAL:
            case UNAVAILABLE:
            case TIMEOUT:
            case ERROR:
                return d.getStatus() == DetectionStatus.UNKNOWN || d.getStatus() == DetectionStatus.NORMAL;
            default:
                return false;
        }
    }

    public boolean isCleanNormal(DetectionResult d) {
        return d.getStatus() == DetectionStatus.NORMAL
                && d.getExecutionStatus() == DetectionExecutionStatus.SAFE;
    }

    public int detectionPriority(DetectionResult detection) {
        switch (detection.getStatus()) {
            case DANGER:
                return detection.isInformational() ? 2 : 0;
            case WARNING:
                return detection.isInformational() ? 3 : 1;
            case UNKNOWN:
                return 4;
            case NORMAL:
            default:
                return detection.getExecutionStatus() == DetectionExecutionStatus.PARTIAL ? 5 : 6;
        }
    }

    public boolean isSyntheticCollector(String name) {
        return "fingerprint_id".equals(name)
                || "hook_memory_signals".equals(name)
                || "runtime_integrity_score_inputs".equals(name);
    }

    public String formatElapsed(long elapsedMs) {
        if (elapsedMs < 1000L) {
            return elapsedMs + " ms";
        }
        return String.format(Locale.getDefault(), "%.2f s", elapsedMs / 1000f);
    }

    /** Formats a compact DevicePosture summary line for hero metadata & redacted export. */
    public String postureCompactSummary(DevicePosture posture) {
        if (posture == null) return "";
        List<String> tags = new ArrayList<>();
        DevicePosture.KeystoreSecurityLevel ks = posture.getKeystoreSecurityLevel();
        if (ks == DevicePosture.KeystoreSecurityLevel.STRONGBOX) {
            tags.add("StrongBox");
        } else if (ks == DevicePosture.KeystoreSecurityLevel.TEE) {
            tags.add("TEE");
        }
        if (Boolean.TRUE.equals(posture.getDeviceSecure())) {
            tags.add("已设锁屏");
        }
        if (posture.isStorageEncrypted()) {
            tags.add("存储加密");
        }
        if (Boolean.TRUE.equals(posture.getSystemVpn())) {
            tags.add("VPN");
        }
        if (Boolean.TRUE.equals(posture.getUnofficialStore())) {
            tags.add("非官方源");
        }
        return String.join(" · ", tags);
    }

    public String heroSubtitle(RiskReport report) {
        DetectionResult primary = primaryDetection(report);
        if (primary != null && !primary.isInformational()) {
            return detectorTitle(primary.getDetectorName()) + " · " + primaryReadableEvidence(primary);
        }
        return riskDescription(report.getOverallRiskLevel());
    }

    public DetectionResult primaryDetection(RiskReport report) {
        List<DetectionResult> candidates = environmentDetections(report);
        DetectionResult informational = null;
        for (DetectionResult d : candidates) {
            if (d.getStatus() == DetectionStatus.NORMAL
                    || d.getStatus() == DetectionStatus.UNKNOWN
                    || (d.getDetails().isEmpty() && d.getEvidenceItems().isEmpty())) {
                continue;
            }
            if (!d.isInformational()) {
                return d;
            }
            if (informational == null) {
                informational = d;
            }
        }
        return informational;
    }

    public String detectionSummary(DetectionResult detection) {
        if (detection.getStatus() == DetectionStatus.UNKNOWN) {
            String reason = firstReadableFailure(detection);
            if (reason != null) {
                return strings.get(R.string.detection_unavailable_reason_summary, reason);
            }
            return strings.get(R.string.detection_unavailable_summary,
                    executionStatusLabel(detection));
        }
        if (detection.getStatus() == DetectionStatus.NORMAL) {
            return detection.getExecutionStatus() == DetectionExecutionStatus.PARTIAL
                    ? strings.get(R.string.detection_partial_safe_summary,
                            detection.getChecksSucceeded(), detection.getChecksAttempted())
                    : strings.get(R.string.detection_normal_summary);
        }
        String reason = primaryReadableEvidence(detection);
        if (detection.isInformational()) {
            if (detection.getDetails().contains("deduped:corroborating_evidence")) {
                return strings.get(R.string.detection_duplicate_summary, reason);
            }
            return strings.get(R.string.detection_informational_summary, reason);
        }
        if (detection.getStatus() == DetectionStatus.DANGER) {
            return strings.get(R.string.detection_danger_summary, reason);
        }
        return strings.get(R.string.detection_warning_summary, reason);
    }

    public List<EvidenceDetail> detectionRiskFindings(DetectionResult detection) {
        return collectEvidenceDetails(detection, false);
    }

    public List<EvidenceDetail> detectionDiagnosticItems(DetectionResult detection) {
        return collectEvidenceDetails(detection, true);
    }

    /**
     * Structured rendering path driven by {@link DetectionResult#getEvidenceItems()} across all
     * 16/16 converged Detection Domains, with diagnostic execution context tokens separated cleanly.
     */
    private List<EvidenceDetail> collectEvidenceDetails(DetectionResult detection, boolean diagnosticOnly) {
        Map<String, EvidenceDetail> merged = new LinkedHashMap<>();

        // 1. Primary structured EvidenceItem path (16/16 converged domains + correlation rules),
        // ordered by EvidenceItem.Rank descending (STRONG > MEDIUM > WEAK > INFO) so Hero and list
        // row summaries always highlight the highest-severity evidence first.
        List<EvidenceItem> orderedItems = new ArrayList<>(detection.getEvidenceItems());
        orderedItems.sort((a, b) -> Integer.compare(evidenceRankWeight(b), evidenceRankWeight(a)));
        for (EvidenceItem item : orderedItems) {
            if (item == null) continue;
            boolean isDiag = item.getRank() == EvidenceItem.Rank.INFO
                    && !"debuggable_flag".equals(item.getCode());
            if (isDiag != diagnosticOnly) continue;
            mergeEvidenceDetail(merged, fromEvidenceItem(item, isDiag));
        }

        // 2. Diagnostic execution context tokens (diagnosticOnly=true) or aggregator-synthesized summaries
        if (diagnosticOnly) {
            for (String rawDetail : detection.getDetails()) {
                if (rawDetail == null || rawDetail.isBlank() || isInternalExecutionToken(rawDetail)) {
                    continue;
                }
                EvidenceDetail diagItem = parseDiagnosticContextToken(rawDetail);
                if (diagItem != null) {
                    mergeEvidenceDetail(merged, diagItem);
                }
            }
        } else if (merged.isEmpty() && isSyntheticAggregatorDetector(detection.getDetectorName())) {
            for (String rawDetail : detection.getDetails()) {
                if (rawDetail == null || rawDetail.isBlank() || isInternalExecutionToken(rawDetail)) {
                    continue;
                }
                if (parseDiagnosticContextToken(rawDetail) != null) continue;
                mergeEvidenceDetail(merged, fromSyntheticDetail(detection.getDetectorName(), rawDetail));
            }
        }
        return new ArrayList<>(merged.values());
    }

    private static int evidenceRankWeight(EvidenceItem item) {
        if (item == null || item.getRank() == null) {
            return 0;
        }
        switch (item.getRank()) {
            case STRONG:
                return 4;
            case MEDIUM:
                return 3;
            case WEAK:
                return 2;
            case INFO:
            default:
                return 1;
        }
    }

    private static boolean isSyntheticAggregatorDetector(String name) {
        return "signal_correlation".equals(name) || "multi_source_validation".equals(name);
    }

    private EvidenceDetail fromSyntheticDetail(String detectorName, String raw) {
        String detail = raw.trim();
        String sourceTag = "signal_correlation".equals(detectorName) ? "交叉规则" : "多源校验";
        if ("signal_correlation".equals(detectorName)) {
            String title = correlationRuleLabel(detail);
            String desc = correlationRuleDescription(detail);
            return new EvidenceDetail(title, sourceTag, detectorName, detail,
                    desc, title, false, "synth|" + detail);
        }
        return new EvidenceDetail(detail, sourceTag, detectorName, detail,
                "聚合引擎交叉校验发现跨信号异常，建议结合业务场景综合处置。",
                detail, false, "synth|" + detail);
    }

    /** Formats a compact human-readable summary of a Phase 3 {@link SignedRiskEnvelope}. */
    public String formatSignedEnvelopeSummary(SignedRiskEnvelope envelope) {
        if (envelope == null) {
            return "未签发硬件风控信封";
        }
        String modeLabel;
        switch (envelope.getAttestationMode()) {
            case FRESH_ATTESTATION:
                modeLabel = "强挑战新鲜证明";
                break;
            case PERSISTENT_KEY:
                modeLabel = "持久硬件密钥";
                break;
            case SOFTWARE_FALLBACK:
            default:
                modeLabel = "软件降级（无硬件背书）";
                break;
        }
        return modeLabel + " · " + envelope.getKeySecurityLevel().name()
                + " · " + envelope.getSigningLatencyMs() + " ms";
    }

    private static void mergeEvidenceDetail(Map<String, EvidenceDetail> merged, EvidenceDetail item) {
        String key = item.mergeKey != null ? item.mergeKey : (item.location + "|" + item.content);
        EvidenceDetail existing = merged.get(key);
        if (existing == null) {
            merged.put(key, item);
        } else if (!existing.sourceTag.equals(item.sourceTag)
                && !existing.sourceTag.contains(item.sourceTag)) {
            merged.put(key, existing.withSourceTag(combineSourceTags(existing.sourceTag, item.sourceTag)));
        }
    }

    private EvidenceDetail fromEvidenceItem(EvidenceItem item, boolean diagnosticOnly) {
        String code = item.getCode();
        String value = item.getValue();
        if (diagnosticOnly) {
            EvidenceDetail canonicalDiag = parseDiagnosticContextToken(value);
            if (canonicalDiag == null && code != null && !code.isEmpty()) {
                canonicalDiag = parseDiagnosticContextToken(code + ":" + value);
            }
            if (canonicalDiag != null) {
                return canonicalDiag;
            }
        }
        EvidenceMeta meta = EVIDENCE_META.get(code);
        String title = meta != null ? meta.title : humanizeCode(code);
        String riskDesc = meta != null ? meta.risk
                : "该结构化证据指示当前运行环境存在偏差，建议结合风险等级与业务场景综合评估。";
        String sourceTag = formatSourceLayers(item.getMergedSources());
        String location = item.getLocation().isEmpty() ? code : item.getLocation();
        String content;
        String inline;
        if ("proxy_tool_cert".equals(code)
                && "official_cert_match".equals(value)
                && !item.getLocation().isEmpty()) {
            content = title + "（" + item.getLocation() + " · 官方签名核验）";
            inline = title + "：" + shortenValue(item.getLocation());
        } else {
            content = value.isEmpty() ? title : (title + "（" + value + "）");
            inline = value.isEmpty() ? title : (title + "：" + shortenValue(value));
        }
        String mergeKey = code + "|" + location;
        return new EvidenceDetail(title, sourceTag, location, content,
                diagnosticOnly ? "" : riskDesc, inline, diagnosticOnly, mergeKey);
    }

    private static EvidenceDetail parseDiagnosticContextToken(String raw) {
        String detail = raw.trim();
        if (detail.startsWith("loader_depth:")) {
            String depth = detail.substring("loader_depth:".length());
            return diag("类加载器链深度", "环境诊断", "应用 ClassLoader 继承链",
                    "当前类加载器共 " + depth + " 层（处于正常范围）", "类加载器层级：" + depth + " 层");
        }
        if (detail.startsWith("passes:")) {
            String passes = detail.substring("passes:".length());
            return diag("后台完整性巡检", "后台守护", "Native 周期监控线程",
                    "自初始化以来已完成 " + passes + " 轮后台巡检", "后台巡检已完成 " + passes + " 轮");
        }
        if ("art_native_flag:invoke".equals(detail)) {
            return diag("系统原生反射方法", "环境诊断", "java.lang.reflect.Method.invoke",
                    "系统 libcore 原生实现 Method.invoke（正常特征，不计分）", "Method.invoke 为系统原生实现");
        }
        if ("deduped:corroborating_evidence".equals(detail)) {
            return diag("同源证据已去重", "评分策略", "风险聚合与去重引擎",
                    "本项证据与前置检测项同源，仅作交叉佐证，不重复叠分", "与前置检测项同源，已去重");
        }
        return null;
    }

    private static String formatSourceLayers(Set<EvidenceItem.SourceLayer> layers) {
        if (layers == null || layers.isEmpty()) return "Java 层";
        boolean hasJava = layers.contains(EvidenceItem.SourceLayer.JAVA);
        boolean hasNative = layers.contains(EvidenceItem.SourceLayer.NATIVE);
        List<String> labels = new ArrayList<>();
        if (hasJava && hasNative) {
            labels.add("Java + Native");
        } else if (hasJava) {
            labels.add("Java 层");
        } else if (hasNative) {
            labels.add("Native 层");
        }
        if (layers.contains(EvidenceItem.SourceLayer.HARDWARE)) labels.add("硬件层");
        if (layers.contains(EvidenceItem.SourceLayer.ISOLATED)) labels.add("隔离进程");
        if (layers.contains(EvidenceItem.SourceLayer.CORRELATION)) labels.add("交叉规则");
        return labels.isEmpty() ? "Java 层" : String.join(" · ", labels);
    }

    private static String combineSourceTags(String first, String second) {
        if (("Java 层".equals(first) && "Native 层".equals(second))
                || ("Native 层".equals(first) && "Java 层".equals(second))) {
            return "Java + Native";
        }
        return first + " · " + second;
    }

    private static String humanizeCode(String code) {
        if (code == null || code.isBlank()) return "检出异常环境信号";
        return code.replace('_', ' ');
    }

    private static EvidenceDetail diag(String title, String sourceTag, String location,
                                       String content, String inlineSummary) {
        return new EvidenceDetail(title, sourceTag, location, content, "", inlineSummary, true,
                "diag:" + title);
    }

    public List<FailureDetail> detectionFailureDetails(DetectionResult detection) {
        List<FailureDetail> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String reason : detection.getFailureReasons()) {
            if (reason == null || reason.isBlank()) continue;
            FailureDetail fd = parseFailureDetail(reason);
            String key = fd.target + "|" + fd.reason;
            if (seen.add(key)) out.add(fd);
        }
        for (String detail : detection.getDetails()) {
            if (detail != null && isInternalExecutionToken(detail)) {
                int sep = detail.indexOf(':');
                String payload = sep >= 0 ? detail.substring(sep + 1) : detail;
                FailureDetail fd = parseFailureDetail(payload);
                String key = fd.target + "|" + fd.reason;
                if (seen.add(key)) out.add(fd);
            }
        }
        return out;
    }

    public String formatFindingsForCopy(DetectionResult detection) {
        List<EvidenceDetail> findings = detectionRiskFindings(detection);
        List<FailureDetail> failures = detectionFailureDetails(detection);
        if (findings.isEmpty() && failures.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("【").append(detectorTitle(detection.getDetectorName()))
                .append(" · ").append(detectionStatusLabel(detection)).append("】");
        int idx = 1;
        for (EvidenceDetail item : findings) {
            sb.append("\n\n").append(idx++).append(". ").append(item.title);
            if (!item.sourceTag.isEmpty()) sb.append(" [").append(item.sourceTag).append("]");
            sb.append("\n   检出位置：").append(item.location);
            sb.append("\n   检出内容：").append(item.content);
            sb.append("\n   风险说明：").append(item.risk);
        }
        if (!failures.isEmpty()) {
            sb.append("\n\n未完成子项：");
            for (FailureDetail f : failures) {
                sb.append("\n- ").append(f.target).append("：").append(f.reason);
            }
        }
        return sb.toString();
    }

    public String primaryReadableEvidence(DetectionResult detection) {
        List<EvidenceDetail> findings = detectionRiskFindings(detection);
        if (!findings.isEmpty()) return findings.get(0).inlineSummary;
        List<EvidenceDetail> diagnostics = detectionDiagnosticItems(detection);
        if (!diagnostics.isEmpty()) return diagnostics.get(0).inlineSummary;
        return strings.get(R.string.no_specific_evidence);
    }

    private String primaryRedactedEvidence(DetectionResult detection) {
        List<EvidenceDetail> findings = detectionRiskFindings(detection);
        if (!findings.isEmpty()) return findings.get(0).title;
        List<EvidenceDetail> diagnostics = detectionDiagnosticItems(detection);
        if (!diagnostics.isEmpty()) return diagnostics.get(0).title;
        return strings.get(R.string.no_specific_evidence);
    }

    private String firstReadableFailure(DetectionResult detection) {
        List<FailureDetail> failures = detectionFailureDetails(detection);
        if (!failures.isEmpty()) {
            FailureDetail f = failures.get(0);
            return f.target.isEmpty() ? f.reason : f.target + "（" + f.reason + "）";
        }
        return null;
    }

    public String detectionStatusLabel(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE: return strings.get(R.string.execution_unavailable);
            case DISABLED: return strings.get(R.string.execution_disabled);
            case TIMEOUT: return strings.get(R.string.execution_timeout);
            case ERROR: return strings.get(R.string.execution_error);
            case PARTIAL:
                if (detection.getStatus() == DetectionStatus.NORMAL) {
                    return strings.get(R.string.execution_partial);
                }
                String partialBase = detection.isInformational()
                        ? strings.get(R.string.status_information)
                        : riskLabel(detection.getRiskLevel());
                return strings.get(R.string.risk_partial, partialBase);
            default:
                break;
        }
        if (detection.getStatus() == DetectionStatus.NORMAL) {
            return strings.get(R.string.status_normal);
        }
        if (detection.isInformational()) {
            return strings.get(R.string.status_information);
        }
        return riskLabel(detection.getRiskLevel());
    }

    public String executionStatusLabel(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case SAFE:
            case RISK: return strings.get(R.string.execution_complete);
            case PARTIAL: return strings.get(R.string.execution_partial);
            case UNAVAILABLE: return strings.get(R.string.execution_unavailable);
            case DISABLED: return strings.get(R.string.execution_disabled);
            case TIMEOUT: return strings.get(R.string.execution_timeout);
            case ERROR:
            default: return strings.get(R.string.execution_error);
        }
    }

    @ColorRes
    public int detectionStatusColorRes(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE:
            case DISABLED:
            case TIMEOUT:
            case ERROR:
                return R.color.risk_unknown;
            case PARTIAL:
                return detection.getStatus() == DetectionStatus.NORMAL
                        ? R.color.risk_unknown
                        : riskColorRes(detection.getRiskLevel());
            default:
                return riskColorRes(detection.getRiskLevel());
        }
    }

    @ColorRes
    public int detectionStatusBgRes(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE:
            case DISABLED:
            case TIMEOUT:
            case ERROR:
                return R.color.risk_unknown_bg;
            case PARTIAL:
                return detection.getStatus() == DetectionStatus.NORMAL
                        ? R.color.risk_unknown_bg
                        : riskBgRes(detection.getRiskLevel());
            default:
                return riskBgRes(detection.getRiskLevel());
        }
    }

    public String riskLabel(RiskLevel level) {
        switch (level) {
            case SAFE: return strings.get(R.string.risk_safe);
            case LOW: return strings.get(R.string.risk_low);
            case MEDIUM: return strings.get(R.string.risk_medium);
            case HIGH: return strings.get(R.string.risk_high);
            case DEADLY: return strings.get(R.string.risk_deadly);
            case UNKNOWN:
            default: return strings.get(R.string.risk_unknown);
        }
    }

    public String riskDescription(RiskLevel level) {
        switch (level) {
            case SAFE: return strings.get(R.string.risk_description_safe);
            case LOW: return strings.get(R.string.risk_description_low);
            case MEDIUM: return strings.get(R.string.risk_description_medium);
            case HIGH: return strings.get(R.string.risk_description_high);
            case DEADLY: return strings.get(R.string.risk_description_deadly);
            case UNKNOWN:
            default: return strings.get(R.string.risk_description_unknown);
        }
    }

    @ColorRes
    public int riskColorRes(RiskLevel level) {
        switch (level) {
            case SAFE: return R.color.risk_safe;
            case LOW: return R.color.risk_low;
            case MEDIUM: return R.color.risk_medium;
            case HIGH: return R.color.risk_high;
            case DEADLY: return R.color.risk_deadly;
            case UNKNOWN:
            default: return R.color.risk_unknown;
        }
    }

    @ColorRes
    public int riskBgRes(RiskLevel level) {
        return bgResForLevel(level);
    }

    /** Returns the semantic foreground color for tier-weighted Assessment Confidence. */
    @ColorRes
    public static int confidenceColorRes(int confidencePercent) {
        if (confidencePercent >= 70) return R.color.text_primary;
        if (confidencePercent >= 40) return R.color.risk_medium;
        return R.color.risk_high;
    }

    public String riskActionLabel(RiskAction action) {
        if (action == null) return strings.get(R.string.action_review);
        switch (action) {
            case ALLOW: return strings.get(R.string.action_allow);
            case CHALLENGE: return strings.get(R.string.action_challenge);
            case RESTRICT: return strings.get(R.string.action_restrict);
            case BLOCK: return strings.get(R.string.action_block);
            case REVIEW:
            default: return strings.get(R.string.action_review);
        }
    }

    public String riskActionDescription(RiskAction action) {
        if (action == null) return strings.get(R.string.action_desc_review);
        switch (action) {
            case ALLOW: return strings.get(R.string.action_desc_allow);
            case CHALLENGE: return strings.get(R.string.action_desc_challenge);
            case RESTRICT: return strings.get(R.string.action_desc_restrict);
            case BLOCK: return strings.get(R.string.action_desc_block);
            case REVIEW:
            default: return strings.get(R.string.action_desc_review);
        }
    }

    @ColorRes
    public int riskActionColorRes(RiskAction action) {
        if (action == null) return R.color.risk_unknown;
        switch (action) {
            case ALLOW: return R.color.risk_safe;
            case CHALLENGE: return R.color.risk_medium;
            case RESTRICT: return R.color.risk_high;
            case BLOCK: return R.color.risk_deadly;
            case REVIEW:
            default: return R.color.risk_unknown;
        }
    }

    @ColorRes
    public int riskActionBgRes(RiskAction action) {
        if (action == null) return R.color.risk_unknown_bg;
        switch (action) {
            case ALLOW: return R.color.risk_safe_bg;
            case CHALLENGE: return R.color.risk_medium_bg;
            case RESTRICT: return R.color.risk_high_bg;
            case BLOCK: return R.color.risk_deadly_bg;
            case REVIEW:
            default: return R.color.risk_unknown_bg;
        }
    }

    public String dimensionLabel(RiskDimension dimension) {
        if (dimension == null) return strings.get(R.string.status_unknown);
        switch (dimension) {
            case TAMPERING: return strings.get(R.string.dimension_tampering);
            case PRIVILEGE: return strings.get(R.string.dimension_privilege);
            case ENVIRONMENT: return strings.get(R.string.dimension_environment);
            case FRAUD_CONTEXT: return strings.get(R.string.dimension_fraud_context);
            default: return dimension.name();
        }
    }

    public String dimensionDescription(RiskDimension dimension) {
        if (dimension == null) return "";
        switch (dimension) {
            case TAMPERING: return strings.get(R.string.dimension_desc_tampering);
            case PRIVILEGE: return strings.get(R.string.dimension_desc_privilege);
            case ENVIRONMENT: return strings.get(R.string.dimension_desc_environment);
            case FRAUD_CONTEXT: return strings.get(R.string.dimension_desc_fraud_context);
            default: return "";
        }
    }

    public String collectSceneLabel(CollectScene scene) {
        if (scene == null) return strings.get(R.string.scene_standard);
        switch (scene) {
            case LOGIN: return strings.get(R.string.scene_login);
            case PAYMENT: return strings.get(R.string.scene_payment);
            case DIAGNOSTIC: return strings.get(R.string.scene_diagnostic);
            case STANDARD:
            default: return strings.get(R.string.scene_standard);
        }
    }

    /** Formats a canonical Evidence Family key (all 21 families) into a readable Chinese label. */
    public String evidenceFamilyLabel(String family) {
        if (family == null || family.isBlank()) return "其他证据家族";
        String key = family.trim().toLowerCase(Locale.ROOT);
        switch (key) {
            case "app_tamper": return "应用重打包与签名篡改";
            case "hook_integrity": return "底层代码与 Hook 完整性";
            case "frida": return "Frida 动态插桩";
            case "xposed": return "Xposed / LSPosed 框架";
            case "debugger": return "调试器附加与反调试";
            case "tee_tamper": return "TEE 硬件信任根篡改";
            case "root_fw": return "Root 提权与挂载篡改";
            case "boot_integrity": return "启动链与 Verified Boot";
            case "prop_tamper": return "系统属性区篡改（Bionic/PIF）";
            case "hw_spoof": return "硬件标识与多源伪造";
            case "hma_hiding": return "应用列表隐藏对抗（HMA/Thanox）";
            case "device_binding": return "设备硬件绑定与锚点漂移";
            case "custom_rom": return "第三方社区 ROM";
            case "adb": return "ADB 调试桥";
            case "emulator": return "模拟器与云手机虚拟化";
            case "virtual_container": return "虚拟多开容器";
            case "threat_app": return "高危工具应用";
            case "network_mitm": return "网络代理与中间人";
            case "location_spoof": return "定位模拟与位置劫持";
            case "screen_control": return "屏幕远控与无障碍接管";
            case "fraud_context": return "电诈通话与异常上下文";
            default:
                if (key.startsWith("detector:")) {
                    return detectorTitle(key.substring("detector:".length()));
                }
                return humanizeCode(family);
        }
    }

    private static final Map<String, EvidenceMeta> CORRELATION_RULE_META;
    static {
        Map<String, EvidenceMeta> rules = new LinkedHashMap<>();
        rules.put("C1:", new EvidenceMeta("C1 · 模拟器弱特征簇聚",
                "多项独立模拟器弱信号同时命中，指向虚拟化模拟环境。"));
        rules.put("C2:", new EvidenceMeta("C2 · 强模拟器 + 虚拟化特征",
                "模拟器强特征叠加 Hypervisor/硬件虚拟化信号。"));
        rules.put("C3:", new EvidenceMeta("C3 · Inline Hook + Frida 联合注入",
                "Native 代码层 Inline Hook 与 Frida 动态插桩同时活跃，已触发高危联判。"));
        rules.put("C4:", new EvidenceMeta("C4 · 隐蔽 Root 隐藏对抗",
                "常规 Root 痕迹被隐藏但底层系统调用/挂载侧信道暴露矛盾。"));
        rules.put("C5:", new EvidenceMeta("C5 · resetprop 属性指纹篡改",
                "Bionic 只读属性区篡改痕迹与属性指纹异常交叉印证。"));
        rules.put("C6:", new EvidenceMeta("C6 · 底层自检与 Java 层严重矛盾",
                "Native 自完整性检出篡改而 Java 层回报正常，存在隐蔽 Hook 欺骗。"));
        rules.put("C7:", new EvidenceMeta("C7 · 云手机弱特征簇聚",
                "登录/支付场景下多项云手机硬件与网络特征同时聚集。"));
        rules.put("C8:", new EvidenceMeta("C8 · 启动链绿态伪装",
                "硬件 RootOfTrust 或 VBMeta 空摘要陷阱证实设备未锁定，但系统属性伪造绿态。"));
        rules.put("C9:", new EvidenceMeta("C9 · 隐蔽 Root 伴随挂载卸载",
                "隔离进程挂载视图或属性区暴露被主进程卸载隐藏的 Root 环境。"));
        rules.put("C10:", new EvidenceMeta("C10 · 支付通话叠加远控（反电诈）",
                "支付场景下通话状态叠加投屏/录屏或第三方无障碍远控，高度疑似电诈风险。"));
        CORRELATION_RULE_META = Collections.unmodifiableMap(rules);
    }

    private static EvidenceMeta lookupCorrelationRuleMeta(String ruleKey) {
        if (ruleKey == null || ruleKey.isBlank()) {
            return null;
        }
        String norm = ruleKey.trim();
        for (Map.Entry<String, EvidenceMeta> entry : CORRELATION_RULE_META.entrySet()) {
            if (norm.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    /** Formats a Correlation Rule key (C1–C10) into a readable Chinese title. */
    public String correlationRuleLabel(String ruleKey) {
        if (ruleKey == null || ruleKey.isBlank()) return "交叉关联规则";
        EvidenceMeta meta = lookupCorrelationRuleMeta(ruleKey);
        return meta != null ? meta.title : ruleKey.trim();
    }

    private String correlationRuleDescription(String ruleKey) {
        EvidenceMeta meta = lookupCorrelationRuleMeta(ruleKey);
        return meta != null
                ? meta.risk
                : "聚合引擎交叉校验发现跨信号异常，建议结合业务场景综合处置。";
    }

    /** Formats a corroboration source token such as {@code layers:JAVA,NATIVE} or {@code domains:root,mount_analysis}. */
    public String formatCorroborationSource(String source) {
        if (source == null || source.isBlank()) return "多源印证";
        String trimmed = source.trim();
        if (trimmed.startsWith("layers:")) {
            String payload = trimmed.substring("layers:".length());
            String[] parts = payload.split("[,+]");
            List<String> labels = new ArrayList<>();
            boolean hasJava = false;
            boolean hasNative = false;
            for (String p : parts) {
                String token = p.trim().toUpperCase(Locale.ROOT);
                if ("JAVA".equals(token)) hasJava = true;
                else if ("NATIVE".equals(token)) hasNative = true;
                else if ("HARDWARE".equals(token)) labels.add("硬件层");
                else if ("ISOLATED".equals(token)) labels.add("隔离进程");
                else if ("CORRELATION".equals(token)) labels.add("交叉规则");
                else if (!token.isEmpty()) labels.add(token);
            }
            if (hasJava && hasNative) {
                labels.add(0, "Java + Native");
            } else if (hasJava) {
                labels.add(0, "Java 层");
            } else if (hasNative) {
                labels.add(0, "Native 层");
            }
            return "跨层印证：" + String.join(" · ", labels);
        }
        if (trimmed.startsWith("domains:")) {
            String payload = trimmed.substring("domains:".length());
            String[] parts = payload.split(",");
            List<String> labels = new ArrayList<>();
            for (String p : parts) {
                String d = p.trim();
                if (!d.isEmpty()) {
                    labels.add(detectorTitle(d));
                }
            }
            return "跨域印证：" + String.join(" + ", labels);
        }
        return detectorTitle(trimmed);
    }

    /** Formats an authoritative Hard Trigger code into a readable label while preserving the raw code. */
    public String formatHardTriggerLabel(String code) {
        if (code == null || code.isBlank()) return "";
        String norm = code.trim();
        int sep = norm.indexOf(':');
        String prefix = sep > 0 ? norm.substring(0, sep) : norm;
        EvidenceMeta meta = EVIDENCE_META.get(norm);
        if (meta == null) {
            meta = EVIDENCE_META.get(prefix);
        }
        if (meta != null) {
            return meta.title + "（" + norm + "）";
        }
        if (norm.startsWith("C3:") || norm.startsWith("C6:") || norm.startsWith("C8:")) {
            return correlationRuleLabel(norm) + "（" + norm + "）";
        }
        return norm;
    }

    /** Converts all {@link ScoreBreakdown.Entry} items into readable attribution cards. */
    public List<BreakdownItem> formatScoreBreakdown(ScoreBreakdown breakdown) {
        if (breakdown == null || breakdown.isEmpty()) {
            return Collections.emptyList();
        }
        List<BreakdownItem> out = new ArrayList<>(breakdown.getEntries().size());
        for (ScoreBreakdown.Entry entry : breakdown.getEntries()) {
            if (entry != null) {
                out.add(toBreakdownItem(entry, breakdown));
            }
        }
        return out;
    }

    /** Returns formatted {@link ScoreBreakdown} items attributable to a specific Detection Domain. */
    public List<BreakdownItem> breakdownItemsForDetector(RiskReport report, String detectorName) {
        if (report == null || detectorName == null || detectorName.isBlank()) {
            return Collections.emptyList();
        }
        ScoreBreakdown breakdown = report.getScoreBreakdown();
        if (breakdown == null || breakdown.isEmpty()) {
            return Collections.emptyList();
        }
        Set<String> matchedFamilies = new LinkedHashSet<>();
        List<BreakdownItem> out = new ArrayList<>();
        for (ScoreBreakdown.Entry entry : breakdown.getEntries()) {
            if (entry == null) continue;
            if (entry.getCategory() == ScoreBreakdown.Category.FAMILY
                    && detectorName.equals(entry.getSource())) {
                matchedFamilies.add(entry.getKey());
                out.add(toBreakdownItem(entry, breakdown));
            } else if (entry.getCategory() == ScoreBreakdown.Category.CORROBORATION_LIFT) {
                String src = entry.getSource();
                boolean domainMatch = src != null && src.startsWith("domains:")
                        && containsCsvToken(src.substring("domains:".length()), detectorName);
                if (domainMatch || matchedFamilies.contains(entry.getKey())) {
                    out.add(toBreakdownItem(entry, breakdown));
                }
            } else if (entry.getCategory() == ScoreBreakdown.Category.CORRELATION_RULE
                    && "signal_correlation".equals(detectorName)) {
                out.add(toBreakdownItem(entry, breakdown));
            }
        }
        return out;
    }

    private static boolean containsCsvToken(String csv, String target) {
        for (String part : csv.split(",")) {
            if (target.equals(part.trim())) {
                return true;
            }
        }
        return false;
    }

    private BreakdownItem toBreakdownItem(ScoreBreakdown.Entry entry, ScoreBreakdown breakdown) {
        String dimLabel = entry.getDimension() != null
                ? dimensionLabel(entry.getDimension())
                : strings.get(R.string.breakdown_cross_dimension);
        switch (entry.getCategory()) {
            case FAMILY: {
                String familyTitle = evidenceFamilyLabel(entry.getKey());
                String src = entry.getSource().isEmpty()
                        ? ""
                        : "主来源：" + detectorTitle(entry.getSource());
                String detail = "证据家族：" + entry.getKey() + "（家族取最强单源强度，顺序无关）";
                return new BreakdownItem(
                        ScoreBreakdown.Category.FAMILY,
                        strings.get(R.string.breakdown_cat_family),
                        familyTitle,
                        detail,
                        dimLabel,
                        src,
                        "+" + entry.getPoints(),
                        scoreColorRes(entry.getPoints()),
                        scoreBgRes(entry.getPoints()));
            }
            case CORROBORATION_LIFT: {
                String familyTitle = evidenceFamilyLabel(entry.getKey()) + " · 交叉印证";
                String src = formatCorroborationSource(entry.getSource());
                String detail = "同一证据家族获多检测层或跨域独立印证，施加有界加权（上限 0.95）。";
                return new BreakdownItem(
                        ScoreBreakdown.Category.CORROBORATION_LIFT,
                        strings.get(R.string.breakdown_cat_corroboration),
                        familyTitle,
                        detail,
                        dimLabel,
                        src,
                        "+" + entry.getPoints(),
                        R.color.accent,
                        R.color.accent_soft);
            }
            case CORRELATION_RULE: {
                String title = correlationRuleLabel(entry.getKey());
                String detail = correlationRuleDescription(entry.getKey());
                return new BreakdownItem(
                        ScoreBreakdown.Category.CORRELATION_RULE,
                        strings.get(R.string.breakdown_cat_correlation),
                        title,
                        detail,
                        dimLabel,
                        "来源：" + detectorTitle("signal_correlation"),
                        "+" + entry.getPoints(),
                        scoreColorRes(entry.getPoints()),
                        scoreBgRes(entry.getPoints()));
            }
            case HARD_TRIGGER_FLOOR:
            default: {
                String triggers = entry.getKey().replace(",", " · ");
                int pre = breakdown != null ? breakdown.getPreFloorScore() : 0;
                int fin = breakdown != null ? breakdown.getFinalScore() : Math.max(95, entry.getPoints());
                String detail = "命中规则：" + triggers + "（保底前 " + pre + " → 终分 " + fin + "）";
                String ptsLabel = entry.getPoints() > 0 ? ("+" + entry.getPoints()) : ("保底 " + fin);
                return new BreakdownItem(
                        ScoreBreakdown.Category.HARD_TRIGGER_FLOOR,
                        strings.get(R.string.breakdown_cat_hard_trigger),
                        "Hard Trigger 强制保底",
                        detail,
                        dimLabel,
                        "权威硬触发裁决",
                        ptsLabel,
                        R.color.risk_deadly,
                        R.color.risk_deadly_bg);
            }
        }
    }

    /** One-line summary shown in the Hero card to invite expanding the Score Breakdown sheet. */
    public String breakdownSummaryLine(RiskReport report) {
        if (report == null) return "";
        if (!report.getHardTriggers().isEmpty()) {
            return strings.get(R.string.breakdown_summary_hard_trigger,
                    report.getHardTriggers().size(), report.getRiskScore());
        }
        ScoreBreakdown breakdown = report.getScoreBreakdown();
        if (breakdown != null && !breakdown.isEmpty()) {
            return strings.get(R.string.breakdown_summary_entries, breakdown.getEntries().size());
        }
        if (report.getOverallRiskLevel() == RiskLevel.UNKNOWN) {
            return strings.get(R.string.breakdown_summary_unknown);
        }
        if (report.getOverallRiskLevel() == RiskLevel.LOW) {
            return strings.get(R.string.breakdown_summary_info);
        }
        return strings.get(R.string.breakdown_summary_clean);
    }

    /** Formats the full Score Breakdown for one-tap clipboard copy inside the detail drawer. */
    public String formatScoreBreakdownForCopy(RiskReport report) {
        if (report == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("【RiskEngine 评分归因与决策】\n")
                .append("综合风险分：").append(report.getRiskScore()).append(" / ")
                .append(report.getMaxRiskScore()).append("（")
                .append(riskLabel(report.getOverallRiskLevel())).append("）\n")
                .append("推荐处置动作：").append(riskActionLabel(report.getRecommendedAction()))
                .append(" (").append(report.getRecommendedAction().name()).append(")\n")
                .append("评估置信度：").append(report.getConfidencePercent()).append("%")
                .append(" · 覆盖率：").append(report.getCoveragePercent()).append("%\n")
                .append("评估场景：").append(collectSceneLabel(report.getCollectScene())).append("\n")
                .append("四维子分：");
        RiskDimension[] dims = RiskDimension.values();
        for (int i = 0; i < dims.length; i++) {
            if (i > 0) sb.append(" · ");
            sb.append(dimensionLabel(dims[i])).append(" ").append(report.getDimensionScore(dims[i]));
        }
        if (!report.getHardTriggers().isEmpty()) {
            sb.append("\nHard Triggers：").append(String.join(", ", report.getHardTriggers()));
        }
        List<BreakdownItem> items = formatScoreBreakdown(report.getScoreBreakdown());
        if (!items.isEmpty()) {
            sb.append("\n\nScore Breakdown 逐项归因：");
            int idx = 1;
            for (BreakdownItem item : items) {
                sb.append("\n").append(idx++).append(". [").append(item.categoryLabel).append("] ")
                        .append(item.title).append(" (").append(item.pointsLabel).append(" · ")
                        .append(item.dimensionLabel).append(")");
                if (!item.sourceSummary.isEmpty()) {
                    sb.append("\n   ").append(item.sourceSummary);
                }
                if (!item.detail.isEmpty()) {
                    sb.append("\n   ").append(item.detail);
                }
            }
        }
        return sb.toString();
    }

    public String detectorTitle(String name) {
        if (name == null) return strings.get(R.string.detector_other);
        switch (name) {
            case "root": return strings.get(R.string.detector_root);
            case "mount_analysis": return strings.get(R.string.detector_mount);
            case "hook_framework": return strings.get(R.string.detector_hook);
            case "adb": return strings.get(R.string.detector_adb);
            case "emulator": return strings.get(R.string.detector_emulator);
            case "debug": return strings.get(R.string.detector_debug);
            case "cloud_phone": return strings.get(R.string.detector_cloud_phone);
            case "custom_rom": return strings.get(R.string.detector_custom_rom);
            case "app_integrity": return strings.get(R.string.detector_app_integrity);
            case "multi_instance": return strings.get(R.string.detector_multi_instance);
            case "network_risk": return strings.get(R.string.detector_network_risk);
            case "location_risk": return strings.get(R.string.detector_location_risk);
            case "screen_and_fraud": return strings.get(R.string.detector_screen_and_fraud);
            case "tee_integrity": return strings.get(R.string.detector_tee_integrity);
            case "threat_apps": return strings.get(R.string.detector_threat_apps);
            case "multi_source_validation": return strings.get(R.string.detector_multi_source);
            case "signal_correlation": return strings.get(R.string.detector_correlation);
            case "consistency": return strings.get(R.string.detector_consistency);
            case "fingerprint_continuity": return strings.get(R.string.detector_fingerprint_continuity);
            default:
                if (name.startsWith("collector:")) {
                    return strings.get(R.string.detector_collector_coverage,
                            collectorTitle(name.substring("collector:".length())));
                }
                return strings.get(R.string.detector_other);
        }
    }

    public String collectorTitle(String name) {
        switch (name) {
            case "android_id": return strings.get(R.string.collector_android_id);
            case "build_props": return strings.get(R.string.collector_build_props);
            case "screen_info": return strings.get(R.string.collector_screen);
            case "apk_signature": return strings.get(R.string.collector_signature);
            case "bluetooth_info": return strings.get(R.string.collector_bluetooth);
            case "wifi_info": return strings.get(R.string.collector_wifi);
            case "telephony": return strings.get(R.string.collector_telephony);
            case "settings": return strings.get(R.string.collector_settings);
            case "adb_state": return strings.get(R.string.collector_adb);
            case "container_signals": return strings.get(R.string.collector_container);
            case "gpu_info": return strings.get(R.string.collector_gpu);
            case "sensor_fingerprint": return strings.get(R.string.collector_sensor);
            case "cpu_topology": return strings.get(R.string.collector_cpu_topology);
            case "hardware_profile": return strings.get(R.string.collector_hardware_profile);
            case "partition_fingerprints": return strings.get(R.string.collector_partition_fingerprints);
            case "codec_info": return strings.get(R.string.collector_codec_info);
            case "input_devices": return strings.get(R.string.collector_input_devices);
            case "security_posture": return strings.get(R.string.collector_security_posture);
            case "drm_id": return strings.get(R.string.collector_drm);
            case "boot_id": return strings.get(R.string.collector_boot);
            case "system_properties_native": return strings.get(R.string.collector_properties);
            case "cpu_info": return strings.get(R.string.collector_cpu);
            case "disk_size": return strings.get(R.string.collector_disk);
            case "kernel_info": return strings.get(R.string.collector_kernel);
            case "fingerprint_id": return strings.get(R.string.collector_fingerprint_id);
            case "hook_memory_signals": return strings.get(R.string.collector_hook_memory);
            case "runtime_integrity_score_inputs": return strings.get(R.string.collector_score_inputs);
            default: return strings.get(R.string.collector_other);
        }
    }

    public String collectorSensitivityLabel(String name) {
        if ("android_id".equals(name) || "drm_id".equals(name)
                || "boot_id".equals(name) || "apk_signature".equals(name)) {
            return strings.get(R.string.sensitivity_pseudonymous);
        }
        if (isSyntheticCollector(name) || "system_properties_native".equals(name)
                || "cpu_info".equals(name) || "kernel_info".equals(name)) {
            return strings.get(R.string.sensitivity_technical);
        }
        return strings.get(R.string.sensitivity_non_sensitive);
    }

    public String collectorStatusLabel(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return strings.get(R.string.collector_status_success);
            case EMPTY: return strings.get(R.string.collector_status_empty);
            case ERROR: return strings.get(R.string.collector_status_error);
            case UNSUPPORTED: return strings.get(R.string.collector_status_unsupported);
            default: return strings.get(R.string.status_unknown);
        }
    }

    @ColorRes
    public int collectorStatusColorRes(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return R.color.risk_safe;
            case ERROR: return R.color.risk_deadly;
            case EMPTY:
            case UNSUPPORTED:
            default: return R.color.risk_unknown;
        }
    }

    @ColorRes
    public int collectorStatusBgRes(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return R.color.risk_safe_bg;
            case ERROR: return R.color.risk_deadly_bg;
            case EMPTY:
            case UNSUPPORTED:
            default: return R.color.risk_unknown_bg;
        }
    }

    public String collectorSummary(CollectorResult result) {
        switch (result.getStatus()) {
            case EMPTY: return strings.get(R.string.collector_empty);
            case ERROR:
                return strings.get(R.string.collector_failed,
                        humanizeFailureReason(result.getError()));
            case UNSUPPORTED: return strings.get(R.string.collector_unsupported);
            case SUCCESS:
            default:
                if (result.isCompareSources() && result.getValues().size() > 1) {
                    return result.isConsistent()
                            ? strings.get(R.string.collector_sources_consistent, result.getValues().size())
                            : strings.get(R.string.collector_sources_inconsistent, result.getValues().size());
                }
                if (result.getValues().isEmpty()) {
                    return strings.get(R.string.collector_no_display_data);
                }
                StringBuilder summary = new StringBuilder();
                int count = 0;
                for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
                    if (count > 0) summary.append(" · ");
                    summary.append(collectorValueLabel(result.getFieldName(), entry.getKey()))
                            .append(" ")
                            .append(formatCollectorValue(result.getFieldName(),
                                    entry.getKey(), entry.getValue(), true));
                    if (++count == 2) break;
                }
                return summary.toString();
        }
    }

    public Map<String, String> collectorFormattedEntries(CollectorResult result) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
            out.put(
                    collectorValueLabel(result.getFieldName(), entry.getKey()),
                    formatCollectorValue(result.getFieldName(), entry.getKey(), entry.getValue(), false)
            );
        }
        return out;
    }

    public String shortenHash(String value) {
        if (value == null || value.isBlank()) return strings.get(R.string.value_none);
        String trimmed = value.trim();
        if (trimmed.length() <= 18) return trimmed;
        return trimmed.substring(0, 10) + "…" + trimmed.substring(trimmed.length() - 6);
    }

    public String shortenValue(String value) {
        if (value == null || value.isBlank()) return strings.get(R.string.value_none);
        String trimmed = value.trim();
        if (trimmed.length() <= 44) return trimmed;
        return trimmed.substring(0, 24) + "…" + trimmed.substring(trimmed.length() - 10);
    }

    public String collectorValueLabel(String field, String key) {
        switch (key) {
            case "summary": return strings.get(R.string.value_summary);
            case "status": return strings.get(R.string.value_status);
            case "supported": return strings.get(R.string.value_supported);
            case "low_energy_supported": return strings.get(R.string.value_bluetooth_le);
            case "wifi_direct_supported": return strings.get(R.string.value_wifi_direct);
            case "development_settings_enabled": return strings.get(R.string.value_developer_options);
            case "checks_completed": return strings.get(R.string.value_checks_completed);
            case "check_failures": return strings.get(R.string.value_check_failures);
            case "phone_type": return strings.get(R.string.value_phone_type);
            case "sim_state": return strings.get(R.string.value_sim_state);
            case "signing_cert_sha256": return strings.get(R.string.value_signing_cert);
            case "native": return strings.get(R.string.value_native_source);
            case "tcp_port": return strings.get(R.string.value_tcp_port);
            case "signals": return strings.get(R.string.value_signals);
            case "count": return strings.get(R.string.value_count);
            case "width":
            case "width_px": return strings.get(R.string.value_width);
            case "height":
            case "height_px": return strings.get(R.string.value_height);
            case "density":
            case "density_dpi": return strings.get(R.string.value_density);
            case "xdpi": return strings.get(R.string.value_xdpi);
            case "ydpi": return strings.get(R.string.value_ydpi);
            case "native_data": return strings.get(R.string.value_data_capacity);
            case "native_storage": return strings.get(R.string.value_storage_capacity);
            case "settings_api": return strings.get(R.string.value_settings_api);
            case "content_resolver": return strings.get(R.string.value_content_resolver);
            case "content_query": return strings.get(R.string.value_content_query);
            case "egl_version": return strings.get(R.string.value_egl_version);
            case "vendor": return strings.get(R.string.value_gpu_vendor);
            case "renderer": return strings.get(R.string.value_gpu_renderer);
            case "extensions_hash": return strings.get(R.string.value_gpu_extensions);
            case "tuple_hash": return strings.get(R.string.value_sensor_tuple_hash);
            case "runtime_processors": return strings.get(R.string.value_runtime_processors);
            case "sysfs_cores": return strings.get(R.string.value_sysfs_cores);
            case "clusters": return strings.get(R.string.value_cpu_clusters);
            case "ram_total_mb_bucket": return strings.get(R.string.value_ram_bucket);
            case "low_ram_device": return strings.get(R.string.value_low_ram);
            case "supported_abis": return strings.get(R.string.value_abis);
            case "composite_id": return strings.get(R.string.value_composite_id);
            case "hardware_id": return strings.get(R.string.value_hardware_id);
            case "system_id": return strings.get(R.string.value_system_id);
            case "volatile_id": return strings.get(R.string.value_volatile_id);
            case "brand": return strings.get(R.string.value_brand);
            case "model": return strings.get(R.string.value_model);
            case "device": return strings.get(R.string.value_device);
            case "manufacturer": return strings.get(R.string.value_manufacturer);
            case "hardware": return strings.get(R.string.value_hardware);
            case "board": return strings.get(R.string.value_board);
            case "fingerprint": return strings.get(R.string.value_fingerprint);
            default:
                if (key.startsWith("ro.")) return strings.get(R.string.value_system_property, key);
                return key.replace('_', ' ');
        }
    }

    public String formatCollectorValue(String field, String key, String value, boolean summary) {
        if (value == null || value.isBlank()) return strings.get(R.string.value_none);
        if ("disk_size".equals(field) && ("native_data".equals(key) || "native_storage".equals(key))) {
            try {
                double gib = Long.parseLong(value) / (1024d * 1024d * 1024d);
                return String.format(Locale.getDefault(), "%.1f GB", gib);
            } catch (NumberFormatException ignored) {}
        }
        if ("ram_total_mb_bucket".equals(key)) {
            try {
                long mb = Long.parseLong(value);
                if (mb >= 1024) return String.format(Locale.getDefault(), "%.1f GB", mb / 1024d);
                return mb + " MB";
            } catch (NumberFormatException ignored) {}
        }
        if ("phone_type".equals(key)) return phoneTypeLabel(value);
        if ("sim_state".equals(key)) return simStateLabel(value);
        if ("mount_overlay".equals(value)) return strings.get(R.string.value_mount_overlay);
        if ("summary".equals(key)) {
            if ("present".equalsIgnoreCase(value)) return strings.get(R.string.value_present);
            if ("none".equalsIgnoreCase(value)) return strings.get(R.string.value_none);
            if ("enabled_wifi".equals(value)) return strings.get(R.string.value_adb_wifi_on);
            if ("enabled".equals(value)) return strings.get(R.string.value_adb_on);
        }
        if ("true".equalsIgnoreCase(value)) return strings.get(R.string.yes);
        if ("false".equalsIgnoreCase(value)) return strings.get(R.string.no);
        if (summary && (field.endsWith("_id") || key.contains("hash") || key.endsWith("_id"))
                && value.length() > 16) {
            return value.substring(0, 8) + "…" + value.substring(value.length() - 4);
        }
        return summary ? shortenValue(value) : value;
    }

    private String phoneTypeLabel(String value) {
        switch (value) {
            case "0": return strings.get(R.string.phone_type_none);
            case "1": return strings.get(R.string.phone_type_gsm);
            case "2": return strings.get(R.string.phone_type_cdma);
            case "3": return strings.get(R.string.phone_type_sip);
            default: return value;
        }
    }

    private String simStateLabel(String value) {
        switch (value) {
            case "0": return strings.get(R.string.sim_state_unknown);
            case "1": return strings.get(R.string.sim_state_absent);
            case "2": return strings.get(R.string.sim_state_pin);
            case "3": return strings.get(R.string.sim_state_puk);
            case "4": return strings.get(R.string.sim_state_network_locked);
            case "5": return strings.get(R.string.sim_state_ready);
            case "6": return strings.get(R.string.sim_state_not_ready);
            case "7": return strings.get(R.string.sim_state_perm_disabled);
            case "8": return strings.get(R.string.sim_state_card_io_error);
            case "9": return strings.get(R.string.sim_state_card_restricted);
            case "10": return strings.get(R.string.sim_state_loaded);
            default: return value;
        }
    }

    public String buildRedactedSummary(RiskReport report) {
        StringBuilder summary = new StringBuilder();
        summary.append(strings.get(R.string.redacted_report_header,
                report.getSdkVersion(),
                riskLabel(report.getOverallRiskLevel()),
                report.getRiskScore(),
                report.getMaxRiskScore(),
                riskActionLabel(report.getRecommendedAction()),
                report.getConfidencePercent(),
                report.getCompletedCheckCount(),
                report.getCheckCount(),
                report.getDangerCount(),
                report.getWarningCount(),
                report.getIncompleteCheckCount()));
        summary.append("\n四维子分：");
        RiskDimension[] dims = RiskDimension.values();
        for (int i = 0; i < dims.length; i++) {
            if (i > 0) summary.append(" · ");
            summary.append(dimensionLabel(dims[i])).append(" ").append(report.getDimensionScore(dims[i]));
        }
        if (!report.getHardTriggers().isEmpty()) {
            summary.append("\nHard Triggers：").append(report.getHardTriggers().size()).append(" 项触发");
        }
        List<BreakdownItem> breakdownItems = formatScoreBreakdown(report.getScoreBreakdown());
        if (!breakdownItems.isEmpty()) {
            summary.append("\n评分归因：");
            for (BreakdownItem item : breakdownItems) {
                summary.append("\n- [").append(item.categoryLabel).append("] ")
                        .append(item.title).append("（").append(item.pointsLabel)
                        .append(" · ").append(item.dimensionLabel).append("）");
            }
        }
        String postureLine = postureCompactSummary(report.getDevicePosture());
        if (!postureLine.isEmpty()) {
            summary.append("\n设备态势：").append(postureLine)
                    .append("（TrustTier: ").append(report.getTrustTier().name()).append("）");
        }
        summary.append("\n检测结果：");
        for (DetectionResult detection : report.getDetections()) {
            if (detection.getDetectorName().startsWith("collector:")) continue;
            summary.append(strings.get(R.string.redacted_report_item,
                    detectorTitle(detection.getDetectorName()), detectionStatusLabel(detection)));
            if (!detectionRiskFindings(detection).isEmpty()) {
                summary.append(strings.get(R.string.redacted_report_reason,
                        primaryRedactedEvidence(detection)));
            }
        }
        summary.append(strings.get(R.string.redacted_report_footer));
        return summary.toString();
    }

    private FailureDetail parseFailureDetail(String raw) {
        String normalized = raw.trim();
        if (normalized.startsWith("unavailable:")) {
            normalized = normalized.substring("unavailable:".length());
        }
        if (normalized.startsWith("detection_unavailable:")) {
            normalized = normalized.substring("detection_unavailable:".length());
        }
        int sep = normalized.indexOf(':');
        if (sep > 0 && sep < normalized.length() - 1) {
            return new FailureDetail(
                    normalized.substring(0, sep).replace('_', ' '),
                    humanizeFailureReason(normalized.substring(sep + 1)));
        }
        return new FailureDetail("子检查执行受限", humanizeFailureReason(normalized));
    }

    private boolean isInternalExecutionToken(String detail) {
        return detail.startsWith("unavailable:")
                || detail.startsWith("timeout:")
                || detail.startsWith("error:")
                || detail.startsWith("disabled:")
                || detail.startsWith("detection_unavailable:");
    }

    /** Result model for the fingerprint continuity card's device_binding status row. */
    public static final class DeviceBindingDisplay {
        public final String label;
        @ColorRes
        public final int colorRes;
        public final boolean broken;

        DeviceBindingDisplay(String label, @ColorRes int colorRes, boolean broken) {
            this.label = label;
            this.colorRes = colorRes;
            this.broken = broken;
        }
    }

    public String fingerprintVersionLabel(FingerprintVersion version) {
        if (version == null) return "V2";
        return version.resolve().name();
    }

    public String fingerprintStabilityLabel(FingerprintStability stability) {
        if (stability == null) return "OPTIMAL";
        switch (stability) {
            case STABLE:
                return "STABLE（仅硬件层）";
            case UNIQUE:
                return "UNIQUE（含易变层）";
            case OPTIMAL:
            default:
                return "OPTIMAL（硬件+系统）";
        }
    }

    public String hardwareBucketLabel(String bucketKey) {
        if (bucketKey == null) return "";
        switch (bucketKey) {
            case "gpu":
                return strings.get(R.string.bucket_gpu);
            case "cpu":
                return strings.get(R.string.bucket_cpu);
            case "sensor":
                return strings.get(R.string.bucket_sensor);
            case "camera":
                return strings.get(R.string.bucket_camera);
            case "memory_battery":
                return strings.get(R.string.bucket_memory_battery);
            default:
                return bucketKey.replace('_', ' ');
        }
    }

    public DeviceBindingDisplay deviceBindingStatus(RiskReport report) {
        if (report == null) {
            return new DeviceBindingDisplay(
                    strings.get(R.string.status_unknown), R.color.risk_unknown, false);
        }
        boolean broken = false;
        for (DetectionResult detection : report.getDetections()) {
            if ("fingerprint_continuity".equals(detection.getDetectorName())) {
                for (EvidenceItem item : detection.getEvidenceItems()) {
                    if ("device_binding_broken".equals(item.getCode())) {
                        broken = true;
                        break;
                    }
                }
                if (!broken) {
                    for (String detail : detection.getDetails()) {
                        if (detail != null && detail.contains("device_binding_broken")) {
                            broken = true;
                            break;
                        }
                    }
                }
            }
        }
        if (broken) {
            return new DeviceBindingDisplay(
                    strings.get(R.string.identity_binding_broken), R.color.risk_deadly, true);
        }
        DevicePosture posture = report.getDevicePosture();
        if (posture != null && posture.isLockscreenOrBiometricReset()) {
            return new DeviceBindingDisplay(
                    strings.get(R.string.identity_binding_reset), R.color.risk_medium, false);
        }
        if (posture != null && posture.getKeystoreSecurityLevel() != null
                && posture.getKeystoreSecurityLevel() != DevicePosture.KeystoreSecurityLevel.UNKNOWN) {
            String ks = posture.getKeystoreSecurityLevel().name();
            return new DeviceBindingDisplay(
                    strings.get(R.string.identity_binding_ok, ks), R.color.risk_safe, false);
        }
        return new DeviceBindingDisplay(
                strings.get(R.string.identity_binding_ok_generic), R.color.risk_safe, false);
    }

    public String threatEventSummary(ThreatEvent event) {
        if (event == null) {
            return strings.get(R.string.no_specific_evidence);
        }
        List<EvidenceItem> items = event.getEvidenceItems();
        if (items != null && !items.isEmpty()) {
            List<EvidenceItem> ordered = new ArrayList<>(items);
            ordered.sort((a, b) -> Integer.compare(evidenceRankWeight(b), evidenceRankWeight(a)));
            EvidenceItem top = ordered.get(0);
            if (top != null) {
                EvidenceMeta meta = EVIDENCE_META.get(top.getCode());
                String title = meta != null ? meta.title : humanizeCode(top.getCode());
                if (top.getValue() != null && !top.getValue().isBlank()) {
                    return title + "：" + shortenValue(top.getValue());
                }
                return title;
            }
        }
        if (event.getEvidence() != null && !event.getEvidence().isBlank()) {
            return shortenValue(event.getEvidence());
        }
        return strings.get(R.string.no_specific_evidence);
    }

    public Map<String, String> postureDetailRows(DevicePosture posture) {
        Map<String, String> rows = new LinkedHashMap<>();
        if (posture == null) {
            return rows;
        }
        rows.put("Keystore 安全级别", posture.getKeystoreSecurityLevel().name());
        rows.put("锁屏安全保护", triStateLabel(posture.getDeviceSecure()));
        rows.put("存储加密状态", posture.getStorageEncryptionStatus().name());
        rows.put("生物识别状态", posture.getBiometricStatus().name());
        rows.put("开发者选项", triStateLabel(posture.getDeveloperOptionsEnabled()));
        rows.put("ADB 调试开关", triStateLabel(posture.getAdbEnabled()));
        rows.put("系统 VPN 状态", triStateLabel(posture.getSystemVpn()));
        rows.put("非官方来源安装", triStateLabel(posture.getUnofficialStore()));
        rows.put("锁屏/生物识别重置", posture.isLockscreenOrBiometricReset()
                ? strings.get(R.string.yes) : strings.get(R.string.no));
        return rows;
    }

    private String triStateLabel(Boolean value) {
        if (value == null) return strings.get(R.string.status_unknown);
        return value ? strings.get(R.string.yes) : strings.get(R.string.no);
    }

    public String humanizeFailureReason(String reason) {
        if (reason == null || reason.isBlank()) return strings.get(R.string.unknown_error);
        String normalized = reason;
        if (normalized.startsWith("unavailable:")) {
            normalized = normalized.substring("unavailable:".length());
        }
        String lower = normalized.toLowerCase(Locale.ROOT);
        if (lower.contains("timeout") || lower.contains("deadline")) return strings.get(R.string.failure_timeout);
        if (lower.contains("securityexception")) return strings.get(R.string.failure_access_denied);
        if (lower.contains("native_library_unavailable") || lower.contains("native_unavailable")) {
            return strings.get(R.string.failure_native_unavailable);
        }
        if (lower.contains("unsupported")) return strings.get(R.string.failure_unsupported);
        if (lower.contains("disabled")) return strings.get(R.string.failure_disabled);
        if (lower.contains("file_unreadable") || lower.contains("procfs_unavailable")) {
            return strings.get(R.string.failure_file_unreadable);
        }
        if (lower.contains("service_unavailable")) return strings.get(R.string.failure_service_unavailable);
        return normalized.replace('_', ' ');
    }
}
