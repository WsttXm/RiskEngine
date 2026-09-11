package com.wsttxm.riskenginesdk.generated;

/**
 * Single-source artifact lists.
 *
 * These mirror {@code src/main/resources/lists/artifact_paths.ini} and the
 * native {@code generated/detection_lists.h}. All three are asserted equal by
 * {@code RootPathListConsistencyTest}; update every one together.
 */
public final class DetectionLists {
    private DetectionLists() {}

    public static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su",
            "/apex/com.android.runtime/bin/su",
            "/system/bin/.ext/su", "/system/usr/we-need-root/su",
            "/cache/su", "/data/su", "/dev/su"
    };

    public static final String[] MAGISK_PATHS = {
            "/sbin/.magisk", "/data/adb/magisk",
            "/data/adb/magisk.db", "/cache/.disable_magisk",
            "/debug_ramdisk/.magisk", "/debug_ramdisk/magisk"
    };

    public static final String[] KERNELSU_PATHS = {
            "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ksu/bin/ksud",
            "/data/adb/ksu/modules"
    };

    public static final String[] APATCH_PATHS = {
            "/data/adb/ap", "/data/adb/ap/bin/apd", "/data/adb/kpatch"
    };

    public static final String[] MODULE_PATHS = {
            "/data/adb/modules"
    };

    public static final String[] EMULATOR_PACKAGES = {
            "com.google.android.launcher.layouts.genymotion",
            "com.bluestacks",
            "com.bignox.app",
            "com.ldmnq.launcher3",
            "com.ldmnq",
            "com.mumu.launcher",
            "com.netease.mumu",
            "com.microvirt.launcher",
            "com.tencent.tinput"
    };

    public static final String[] CLOUD_PACKAGES = {
            "com.redfinger.app",
            "com.redfinger.virtualphone",
            "com.vmos.pro",
            "com.vmos.app",
            "com.cloudphone.client",
            "com.armcloud.sdk",
            "com.baidu.cloudphone",
            "com.huaweicloud.cph"
    };

    public static final String[] SANDBOX_PACKAGES = {
            "com.lbe.parallel",
            "com.excelliance.dualaid",
            "com.parallel.space",
            "com.lody.virtual",
            "io.virtualapp",
            "com.qihoo.magic",
            "com.qihoo.magic.xposed",
            "com.excelliance.multiaccounts",
            "com.coloros.oppomultiapp",
            "com.parallel.space.lite",
            "com.ludashi.dualspace",
            "com.ludashi.multspace",
            "com.rinzz.avatar",
            "com.rinzz.wdf",
            "com.applisto.appcloner",
            "info.red.virtual",
            "com.jiubang.commerce.gomultiple",
            "multi.parallel.dualspace.cloner"
    };

    /** Device-modification tool artifacts. Presence indicates a spoofing toolkit. */
    public static final String[] TAMPER_TOOL_PATHS = {
            "/sdcard/.f22",
            "/sdcard/.f22/PhoneInfo.f22",
            "/data/local/tmp/tc/mobileagent",
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server"
    };

    public static final String[] ALLOWED_PROPERTIES = {
            "service.adb.tcp.port", "persist.adb.tcp.port",
            "ro.build.fingerprint", "ro.build.display.id", "ro.product.model",
            "ro.product.brand", "ro.product.device", "ro.product.manufacturer",
            "ro.hardware", "ro.board.platform", "persist.sys.timezone",
            "gsm.version.baseband", "ro.lineage.version", "ro.cm.version",
            "ro.mokee.version", "ro.rr.version", "ro.pixelexperience.version",
            "ro.modversion", "ro.kernel.qemu", "ro.hardware.virtual",
            "ro.boot.qemu", "ro.secure", "ro.debuggable", "ro.build.type",
            "ro.build.characteristics",
            "ro.system.build.fingerprint", "ro.vendor.build.fingerprint",
            "ro.odm.build.fingerprint", "ro.product.build.fingerprint",
            "ro.system_ext.build.fingerprint", "ro.bootimage.build.fingerprint",
            "ro.boot.vbmeta.digest", "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked", "ro.oem_unlock_supported",
            "ro.build.version.incremental", "ro.build.date.utc", "ro.build.tags",
            "ro.soc.model", "ro.soc.manufacturer",
            "ro.hardware.egl", "ro.hardware.gralloc",
            "ro.boot.hardware", "ro.product.system.name",
            "ro.boot.cloudphone", "persist.sys.cloudphone", "ro.redfinger",
            "ro.armcloud", "ro.cloud.model", "ro.vendor.cloudphone",
            "ro.boot.redroid"
    };

    /** Build fingerprint properties compared against each other for spoofing. */
    public static final String[] PARTITION_FINGERPRINT_PROPERTIES = {
            "ro.build.fingerprint",
            "ro.system.build.fingerprint",
            "ro.vendor.build.fingerprint",
            "ro.odm.build.fingerprint",
            "ro.product.build.fingerprint",
            "ro.system_ext.build.fingerprint",
            "ro.bootimage.build.fingerprint"
    };

    /** Properties whose mere presence indicates a cloud-phone host. */
    public static final String[] CLOUD_PHONE_PROPERTIES = {
            "ro.boot.cloudphone", "persist.sys.cloudphone", "ro.redfinger",
            "ro.armcloud", "ro.cloud.model", "ro.vendor.cloudphone"
    };

    /** GPU renderer/vendor substrings that indicate virtualized graphics. */
    public static final String[] VIRTUAL_GPU_MARKERS = {
            "virgl", "virtio", "llvmpipe", "swiftshader", "angle",
            "pastel", "pixel-soft", "mesa", "vgem", "gallium"
    };

    public static final String[] PROCESS_TOKENS = {
            "frida", "frida-server", "frida-agent", "frida_helper",
            "xposed", "edxposed", "lsposed", "lspd",
            "magisk", "magiskd", "ksud", "apd", "zygisk",
            "gdb", "gdbserver", "lldb-server", "android_server", "android_server64"
    };
}
