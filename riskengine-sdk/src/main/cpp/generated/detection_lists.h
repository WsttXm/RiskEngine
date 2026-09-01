#ifndef RISKENGINE_DETECTION_LISTS_H
#define RISKENGINE_DETECTION_LISTS_H

#include "../util/obf_str.h"
#include <string>
#include <vector>

inline std::vector<std::string> list_su_paths() {
    return {
            OBF("/system/bin/su"), OBF("/system/xbin/su"), OBF("/sbin/su"),
            OBF("/data/local/xbin/su"), OBF("/data/local/bin/su"),
            OBF("/system/sd/xbin/su"), OBF("/system/bin/failsafe/su"),
            OBF("/data/local/su"), OBF("/su/bin/su"),
            OBF("/apex/com.android.runtime/bin/su")
    };
}

inline std::vector<std::string> list_magisk_paths() {
    return {
            OBF("/sbin/.magisk"), OBF("/data/adb/magisk"),
            OBF("/data/adb/magisk.db"), OBF("/cache/.disable_magisk"),
            OBF("/debug_ramdisk/.magisk"), OBF("/debug_ramdisk/magisk")
    };
}

inline std::vector<std::string> list_kernelsu_paths() {
    return {
            OBF("/data/adb/ksu"), OBF("/data/adb/ksud"),
            OBF("/data/adb/ksu/bin/ksud")
    };
}

inline std::vector<std::string> list_apatch_paths() {
    return {
            OBF("/data/adb/ap"), OBF("/data/adb/ap/bin/apd")
    };
}

inline std::vector<std::string> list_module_paths() {
    return {OBF("/data/adb/modules")};
}

inline std::vector<std::string> list_emulator_files() {
    return {
            OBF("/system/bin/androVM-prop"),
            OBF("/system/bin/microvirt-prop"),
            OBF("/system/lib/libdroid4x.so"),
            OBF("/system/bin/windroyed"),
            OBF("/system/bin/nox-prop"),
            OBF("/system/lib/libnoxspeedup.so"),
            OBF("/system/bin/ttVM-prop"),
            OBF("/data/.bluestacks.prop"),
            OBF("/system/bin/duosconfig"),
            OBF("/system/etc/xxzs_prop.sh"),
            OBF("/system/etc/mumu-configs/device-prop-configs/mumu.config"),
            OBF("/system/etc/mumu-configs"),
            OBF("/system/priv-app/ldAppStore"),
            OBF("/system/lib/libc_malloc_debug_qemu.so"),
            OBF("/dev/qemu_pipe"),
            OBF("/dev/goldfish_pipe"),
            OBF("/sys/qemu_trace"),
            OBF("/dev/socket/qemud"),
            OBF("/system/bin/ldinit"),
            OBF("/system/lib64/libldutils.so"),
            OBF("/system/bin/bstconf")
    };
}

inline std::vector<std::string> list_allowed_properties() {
    return {
            OBF("service.adb.tcp.port"), OBF("persist.adb.tcp.port"),
            OBF("ro.build.fingerprint"), OBF("ro.build.display.id"),
            OBF("ro.product.model"), OBF("ro.product.brand"),
            OBF("ro.product.device"), OBF("ro.product.manufacturer"),
            OBF("ro.hardware"), OBF("ro.board.platform"),
            OBF("persist.sys.timezone"), OBF("gsm.version.baseband"),
            OBF("ro.lineage.version"), OBF("ro.cm.version"),
            OBF("ro.mokee.version"), OBF("ro.rr.version"),
            OBF("ro.pixelexperience.version"), OBF("ro.modversion"),
            OBF("ro.kernel.qemu"), OBF("ro.hardware.virtual"),
            OBF("ro.boot.qemu"), OBF("ro.secure"),
            OBF("ro.debuggable"), OBF("ro.build.type")
    };
}

inline std::vector<std::string> list_process_tokens() {
    return {
            OBF("frida"), OBF("frida-server"), OBF("frida-agent"),
            OBF("frida_helper"), OBF("xposed"), OBF("edxposed"),
            OBF("lsposed"), OBF("lspd"), OBF("magisk"), OBF("magiskd"),
            OBF("ksud"), OBF("apd"), OBF("zygisk"),
            OBF("gdb"), OBF("gdbserver"), OBF("lldb-server"),
            OBF("android_server"), OBF("android_server64")
    };
}

#endif
