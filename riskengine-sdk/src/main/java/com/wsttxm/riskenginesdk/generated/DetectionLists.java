package com.wsttxm.riskenginesdk.generated;

/** Single-source artifact lists mirrored by native generated/detection_lists.h. */
public final class DetectionLists {
    private DetectionLists() {}

    public static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su",
            "/apex/com.android.runtime/bin/su"
    };

    public static final String[] MAGISK_PATHS = {
            "/sbin/.magisk", "/data/adb/magisk",
            "/data/adb/magisk.db", "/cache/.disable_magisk",
            "/debug_ramdisk/.magisk", "/debug_ramdisk/magisk"
    };

    public static final String[] KERNELSU_PATHS = {
            "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ksu/bin/ksud"
    };

    public static final String[] APATCH_PATHS = {
            "/data/adb/ap", "/data/adb/ap/bin/apd"
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
            "com.vmos.app"
    };

    public static final String[] SANDBOX_PACKAGES = {
            "com.lbe.parallel",
            "com.excelliance.dualaid",
            "com.parallel.space"
    };

    public static final String[] ALLOWED_PROPERTIES = {
            "service.adb.tcp.port", "persist.adb.tcp.port",
            "ro.build.fingerprint", "ro.build.display.id", "ro.product.model",
            "ro.product.brand", "ro.product.device", "ro.product.manufacturer",
            "ro.hardware", "ro.board.platform", "persist.sys.timezone",
            "gsm.version.baseband", "ro.lineage.version", "ro.cm.version",
            "ro.mokee.version", "ro.rr.version", "ro.pixelexperience.version",
            "ro.modversion", "ro.kernel.qemu", "ro.hardware.virtual",
            "ro.boot.qemu", "ro.secure", "ro.debuggable", "ro.build.type"
    };

    public static final String[] PROCESS_TOKENS = {
            "frida", "frida-server", "frida-agent", "frida_helper",
            "xposed", "edxposed", "lsposed", "lspd",
            "magisk", "magiskd", "ksud", "apd", "zygisk",
            "gdb", "gdbserver", "lldb-server", "android_server", "android_server64"
    };
}
