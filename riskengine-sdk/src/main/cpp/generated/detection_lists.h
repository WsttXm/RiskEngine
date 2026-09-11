#ifndef RISKENGINE_DETECTION_LISTS_H
#define RISKENGINE_DETECTION_LISTS_H

// Mirrors src/main/resources/lists/artifact_paths.ini and the Java
// DetectionLists. RootPathListConsistencyTest asserts all three agree.

#include "../util/obf_str.h"
#include <string>
#include <vector>

inline std::vector<std::string> list_su_paths() {
    return {
            OBF("/system/bin/su"), OBF("/system/xbin/su"), OBF("/sbin/su"),
            OBF("/data/local/xbin/su"), OBF("/data/local/bin/su"),
            OBF("/system/sd/xbin/su"), OBF("/system/bin/failsafe/su"),
            OBF("/data/local/su"), OBF("/su/bin/su"),
            OBF("/apex/com.android.runtime/bin/su"),
            OBF("/system/bin/.ext/su"), OBF("/system/usr/we-need-root/su"),
            OBF("/cache/su"), OBF("/data/su"), OBF("/dev/su")
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
            OBF("/data/adb/ksu/bin/ksud"), OBF("/data/adb/ksu/modules")
    };
}

inline std::vector<std::string> list_apatch_paths() {
    return {
            OBF("/data/adb/ap"), OBF("/data/adb/ap/bin/apd"),
            OBF("/data/adb/kpatch")
    };
}

inline std::vector<std::string> list_module_paths() {
    return {OBF("/data/adb/modules")};
}

inline std::vector<std::string> list_tamper_tool_paths() {
    return {
            OBF("/sdcard/.f22"), OBF("/sdcard/.f22/PhoneInfo.f22"),
            OBF("/data/local/tmp/tc/mobileagent"),
            OBF("/data/local/tmp/frida-server"),
            OBF("/data/local/tmp/re.frida.server")
    };
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
            OBF("/system/bin/bstconf"),
            OBF("/dev/vboxuser"),
            OBF("/dev/vboxguest"),
            OBF("/dev/socket/genyd"),
            OBF("/dev/socket/baseband_genyd"),
            OBF("/system/bin/genybaseband"),
            OBF("/system/bin/qemu-props"),
            OBF("/system/bin/microvirtd"),
            OBF("/system/bin/droid4x-prop"),
            OBF("/system/bin/ldmountsf"),
            OBF("/system/app/AntStore"),
            OBF("/system/app/AntLauncher"),
            OBF("/dev/.redroid"),
            OBF("/dev/redroid")
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
            OBF("ro.debuggable"), OBF("ro.build.type"),
            OBF("ro.build.characteristics"),
            OBF("ro.system.build.fingerprint"), OBF("ro.vendor.build.fingerprint"),
            OBF("ro.odm.build.fingerprint"), OBF("ro.product.build.fingerprint"),
            OBF("ro.system_ext.build.fingerprint"),
            OBF("ro.bootimage.build.fingerprint"),
            OBF("ro.boot.vbmeta.digest"), OBF("ro.boot.verifiedbootstate"),
            OBF("ro.boot.flash.locked"), OBF("ro.oem_unlock_supported"),
            OBF("ro.build.version.incremental"), OBF("ro.build.date.utc"),
            OBF("ro.build.tags"),
            OBF("ro.soc.model"), OBF("ro.soc.manufacturer"),
            OBF("ro.hardware.egl"), OBF("ro.hardware.gralloc"),
            OBF("ro.boot.hardware"), OBF("ro.product.system.name"),
            OBF("ro.boot.cloudphone"), OBF("persist.sys.cloudphone"),
            OBF("ro.redfinger"), OBF("ro.armcloud"), OBF("ro.cloud.model"),
            OBF("ro.vendor.cloudphone"), OBF("ro.boot.redroid")
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

/** libc symbols whose PLT/GOT and prologue are checked for redirection. */
inline std::vector<std::string> list_monitored_libc_symbols() {
    return {
            OBF("openat"), OBF("faccessat"), OBF("read"), OBF("connect"),
            OBF("ptrace"), OBF("fopen"), OBF("readlinkat"), OBF("getdents64"),
            OBF("statfs"), OBF("uname"), OBF("mmap"), OBF("prctl"),
            OBF("__system_property_get"), OBF("dlopen"), OBF("dlsym"),
            OBF("pthread_create"), OBF("openat64"), OBF("fstatat")
    };
}

#endif
