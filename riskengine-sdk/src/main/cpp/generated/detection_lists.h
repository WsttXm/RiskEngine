#ifndef RISKENGINE_DETECTION_LISTS_H
#define RISKENGINE_DETECTION_LISTS_H

// Generated from src/main/resources/lists/artifact_paths.ini via
// :riskengine-sdk:generateDetectionLists.

#include "../util/obf_str.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct AllowedPropertyHash {
    uint64_t hash;
    uint16_t len;
};

inline constexpr uint64_t fnv1a_64_bytes(const char *data, size_t len) noexcept {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(data[i]);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static_assert(fnv1a_64_bytes("", 0) == 0xcbf29ce484222325ULL, "FNV-1a empty mismatch");
static_assert(fnv1a_64_bytes("foobar", 6) == 0x85944171f73967e8ULL, "FNV-1a vector mismatch");

inline constexpr AllowedPropertyHash kAllowedPropertyHashes[] = {
        {0x020cc6c5ae09b35fULL, 15u},
        {0x07d24bb5ee4105feULL, 24u},
        {0x0841369017998659ULL, 22u},
        {0x124fd42c4a4ab682ULL, 14u},
        {0x163323f035ed0f28ULL, 13u},
        {0x1af4d2392f0e8665ULL, 30u},
        {0x1edcd05150508ed6ULL, 29u},
        {0x23c89bcc537493f8ULL, 13u},
        {0x32513ab51a176139ULL, 14u},
        {0x39a4322f2d436604ULL, 24u},
        {0x39bdd47fe70835deULL, 15u},
        {0x3a8a27ad28074e72ULL, 26u},
        {0x3cbba77b48094cdfULL, 11u},
        {0x3d536b563a431526ULL, 17u},
        {0x3f9369591715253dULL, 23u},
        {0x4a9ceb48c68a4c77ULL, 22u},
        {0x4c59d4fb127a9ba6ULL, 12u},
        {0x4cb4eb2e4c777910ULL, 28u},
        {0x4ed99c55063eddc5ULL, 18u},
        {0x5076d17d07931005ULL, 20u},
        {0x53cc13b88a60b937ULL, 19u},
        {0x553c5603c8699933ULL, 13u},
        {0x55f4bcf0a7acfda4ULL, 20u},
        {0x56977b35fb4b9484ULL, 20u},
        {0x5953ba858d9fd05aULL, 13u},
        {0x7299fc57c7a36cceULL, 20u},
        {0x78122a85ed110016ULL, 16u},
        {0x7acc22ac0ab2cd77ULL, 14u},
        {0x82ffe9b26aaf904aULL, 27u},
        {0x8438840351b5480aULL, 13u},
        {0x853125a8179488b4ULL, 16u},
        {0x853b8f3473e8cc30ULL, 16u},
        {0x862f21c62fa982cbULL, 28u},
        {0x8762b9e068c2dc56ULL, 19u},
        {0x8a135d09c442d0eeULL, 20u},
        {0x8e0d40508711b26aULL, 23u},
        {0x8f56de0226099cc3ULL, 25u},
        {0x90432d008731f95fULL, 20u},
        {0x92a3be5b1e1c09d1ULL, 17u},
        {0x956812e71bb243aaULL, 12u},
        {0x98db4e376486ac8aULL, 15u},
        {0xaee17632d693afb9ULL, 9u},
        {0xb4a7279649e4354cULL, 19u},
        {0xb5a7a3bb05203cd9ULL, 31u},
        {0xbcd46a573f1bcf2bULL, 19u},
        {0xbf514b56a99442b9ULL, 17u},
        {0xbfe94d2aa3c9bc62ULL, 20u},
        {0xc1f9575441c1b198ULL, 11u},
        {0xc2a0251df8bd1443ULL, 20u},
        {0xc44d1b4d01518f7dULL, 19u},
        {0xc4e86a3d107987d9ULL, 19u},
        {0xcf15e48dfb86b979ULL, 27u},
        {0xd30900b9e941f874ULL, 12u},
        {0xd91b7fc84f77524aULL, 13u},
        {0xe3a89f3f4948f09bULL, 21u},
        {0xe5088bf9ceb08dd9ULL, 16u},
        {0xf2ee370473f709cbULL, 18u}
};

inline bool is_allowed_property_name(const char *name, size_t len) noexcept {
    if (name == nullptr || len == 0 || len > 0xFFFFu) {
        return false;
    }
    const uint64_t target = fnv1a_64_bytes(name, len);
    size_t lo = 0;
    size_t hi = sizeof(kAllowedPropertyHashes) / sizeof(kAllowedPropertyHashes[0]);
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const uint64_t midHash = kAllowedPropertyHashes[mid].hash;
        if (midHash < target) {
            lo = mid + 1;
        } else if (midHash > target) {
            hi = mid;
        } else {
            return kAllowedPropertyHashes[mid].len == static_cast<uint16_t>(len);
        }
    }
    return false;
}

static inline std::vector<std::string> list_su_paths() {
    return {
            OBF("/system/bin/su"),
            OBF("/system/xbin/su"),
            OBF("/system_ext/bin/su"),
            OBF("/sbin/su"),
            OBF("/data/local/xbin/su"),
            OBF("/data/local/bin/su"),
            OBF("/system/sd/xbin/su"),
            OBF("/system/bin/failsafe/su"),
            OBF("/data/local/su"),
            OBF("/su/bin/su"),
            OBF("/apex/com.android.runtime/bin/su"),
            OBF("/system/bin/.ext/su"),
            OBF("/system/usr/we-need-root/su"),
            OBF("/cache/su"),
            OBF("/data/su"),
            OBF("/dev/su")
    };
}

static inline std::vector<std::string> list_magisk_paths() {
    return {
            OBF("/sbin/.magisk"),
            OBF("/data/adb/magisk"),
            OBF("/data/adb/magisk.db"),
            OBF("/cache/.disable_magisk"),
            OBF("/debug_ramdisk/.magisk"),
            OBF("/debug_ramdisk/magisk")
    };
}

static inline std::vector<std::string> list_kernelsu_paths() {
    return {
            OBF("/data/adb/ksu"),
            OBF("/data/adb/ksud"),
            OBF("/data/adb/ksu/bin/ksud"),
            OBF("/data/adb/ksu/modules")
    };
}

static inline std::vector<std::string> list_apatch_paths() {
    return {
            OBF("/data/adb/ap"),
            OBF("/data/adb/ap/bin/apd"),
            OBF("/data/adb/kpatch")
    };
}

static inline std::vector<std::string> list_module_paths() {
    return {
            OBF("/data/adb/modules")
    };
}

static inline std::vector<std::string> list_tamper_tool_paths() {
    return {
            OBF("/sdcard/.f22"),
            OBF("/sdcard/.f22/PhoneInfo.f22"),
            OBF("/data/local/tmp/tc/mobileagent"),
            OBF("/data/local/tmp/frida-server"),
            OBF("/data/local/tmp/re.frida.server")
    };
}

static inline std::vector<std::string> list_emulator_files() {
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
            OBF("/dev/redroid"),
            OBF("/dev/waydroid"),
            OBF("/system/bin/waydroid"),
            OBF("/vendor/etc/init/waydroid.rc"),
            OBF("/vendor/etc/init/init.cutf_cvm.rc"),
            OBF("/system/bin/cuttlefish_config"),
            OBF("/vendor/bin/cuttlefish_config"),
            OBF("/dev/cf_vsock"),
            OBF("/system/lib64/libwsa.so"),
            OBF("/system/etc/init/init.wsa.rc"),
            OBF("/vendor/etc/init/init.windows_x86_64.rc"),
            OBF("/dev/corellium"),
            OBF("/system/bin/corelliumd"),
            OBF("/system/bin/ld9init"),
            OBF("/system/lib64/libld9.so"),
            OBF("/system/priv-app/ld9AppStore"),
            OBF("/system/bin/mumud"),
            OBF("/system/bin/mumu12-prop"),
            OBF("/system/lib64/libmumu.so")
    };
}

static inline std::vector<std::string> list_allowed_properties() {
    return {
            OBF("service.adb.tcp.port"),
            OBF("persist.adb.tcp.port"),
            OBF("ro.build.fingerprint"),
            OBF("ro.build.display.id"),
            OBF("ro.product.model"),
            OBF("ro.product.brand"),
            OBF("ro.product.device"),
            OBF("ro.product.manufacturer"),
            OBF("ro.hardware"),
            OBF("ro.board.platform"),
            OBF("persist.sys.timezone"),
            OBF("gsm.version.baseband"),
            OBF("ro.lineage.version"),
            OBF("ro.cm.version"),
            OBF("ro.mokee.version"),
            OBF("ro.rr.version"),
            OBF("ro.pixelexperience.version"),
            OBF("ro.modversion"),
            OBF("ro.kernel.qemu"),
            OBF("ro.hardware.virtual"),
            OBF("ro.boot.qemu"),
            OBF("ro.secure"),
            OBF("ro.debuggable"),
            OBF("ro.build.type"),
            OBF("ro.build.characteristics"),
            OBF("ro.system.build.fingerprint"),
            OBF("ro.vendor.build.fingerprint"),
            OBF("ro.odm.build.fingerprint"),
            OBF("ro.product.build.fingerprint"),
            OBF("ro.system_ext.build.fingerprint"),
            OBF("ro.bootimage.build.fingerprint"),
            OBF("ro.boot.vbmeta.digest"),
            OBF("ro.boot.verifiedbootstate"),
            OBF("ro.boot.flash.locked"),
            OBF("ro.oem_unlock_supported"),
            OBF("ro.build.version.incremental"),
            OBF("ro.build.date.utc"),
            OBF("ro.build.tags"),
            OBF("ro.soc.model"),
            OBF("ro.soc.manufacturer"),
            OBF("ro.hardware.egl"),
            OBF("ro.hardware.gralloc"),
            OBF("ro.boot.hardware"),
            OBF("ro.product.system.name"),
            OBF("ro.boot.cloudphone"),
            OBF("persist.sys.cloudphone"),
            OBF("ro.redfinger"),
            OBF("ro.armcloud"),
            OBF("ro.cloud.model"),
            OBF("ro.vendor.cloudphone"),
            OBF("ro.boot.redroid"),
            OBF("ro.waydroid.version"),
            OBF("ro.wsa.version"),
            OBF("ro.corellium.version"),
            OBF("ro.ldplayer.version"),
            OBF("ro.mumu.version"),
            OBF("ro.boot.microdroid.debuggable")
    };
}

static inline std::vector<std::string> list_monitored_libc_symbols() {
    return {
            OBF("openat"),
            OBF("faccessat"),
            OBF("read"),
            OBF("connect"),
            OBF("ptrace"),
            OBF("fopen"),
            OBF("readlinkat"),
            OBF("getdents64"),
            OBF("statfs"),
            OBF("uname"),
            OBF("mmap"),
            OBF("prctl"),
            OBF("__system_property_get"),
            OBF("dlopen"),
            OBF("dlsym"),
            OBF("pthread_create"),
            OBF("openat64"),
            OBF("fstatat")
    };
}

#endif
