#include "riskengine_jni.h"
#include "util/crypto_mini.h"
#include "util/custom_jni_register.h"
#include "util/maps_parser.h"
#include "util/obf_str.h"
#include "util/syscall_wrapper.h"
#include "collector/drm_collector.h"
#include "collector/boot_id_collector.h"
#include "collector/system_property_collector.h"
#include "collector/cpu_info_collector.h"
#include "collector/disk_size_collector.h"
#include "collector/kernel_info_collector.h"
#include "detector/native_root_detector.h"
#include "detector/native_hook_detector.h"
#include "detector/native_emulator_detector.h"
#include "detector/native_debug_detector.h"
#include "detector/native_integrity.h"
#include "detector/runtime_arch_checker.h"
#include "detector/mount_namespace_diff.h"
#include "detector/kernel_su_probe.h"
#include "detector/sealed_verdict.h"
#include "detector/periodic_monitor.h"
#include "generated/detection_lists.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <vector>

namespace {

constexpr size_t kMaxRegisteredMethods = 32;
std::mutex g_reg_mutex;
uintptr_t g_ptr_mask = 0;
size_t g_registered_count = 0;
std::array<uintptr_t, kMaxRegisteredMethods> g_masked_ptrs = {};
std::array<uint64_t, kMaxRegisteredMethods> g_expected_prologues = {};

uintptr_t generate_ptr_mask() {
    uintptr_t mask = 0;
    int fd = static_cast<int>(my_openat(AT_FDCWD, OBF("/dev/urandom").c_str(),
                                        O_RDONLY | O_CLOEXEC, 0));
    if (fd >= 0) {
        my_read(fd, &mask, sizeof(mask));
        my_close(fd);
    }
    if (mask == 0) {
        mask = reinterpret_cast<uintptr_t>(&g_masked_ptrs) ^ static_cast<uintptr_t>(0xA5A55A5Au);
    }
    return mask;
}

void snapshot_registered_table(const std::vector<JNINativeMethod> &table) {
    std::lock_guard<std::mutex> lock(g_reg_mutex);
    g_ptr_mask = generate_ptr_mask();
    g_registered_count = std::min(table.size(), kMaxRegisteredMethods);
    for (size_t i = 0; i < g_registered_count; ++i) {
        const auto addr = reinterpret_cast<uintptr_t>(table[i].fnPtr);
        g_masked_ptrs[i] = addr ^ g_ptr_mask;
        g_expected_prologues[i] = native_hash_fn_prologue(table[i].fnPtr);
    }
}

void copy_registered_table(std::vector<const void *> &ptrs,
                           std::vector<uint64_t> &prologues) {
    std::lock_guard<std::mutex> lock(g_reg_mutex);
    ptrs.resize(g_registered_count);
    prologues.resize(g_registered_count);
    for (size_t i = 0; i < g_registered_count; ++i) {
        ptrs[i] = reinterpret_cast<const void *>(g_masked_ptrs[i] ^ g_ptr_mask);
        prologues[i] = g_expected_prologues[i];
    }
}

}  // namespace

static jstring toJString(JNIEnv *env, const std::string &str) {
    if (env == nullptr || env->ExceptionCheck()) {
        return nullptr;
    }

    try {
        constexpr size_t kMaxInputBytes = 1024 * 1024;
        const size_t limit = std::min(str.size(), kMaxInputBytes);
        std::vector<jchar> utf16;
        utf16.reserve(limit);
        size_t index = 0;
        while (index < limit) {
            const auto first = static_cast<uint8_t>(str[index]);
            uint32_t codepoint = 0;
            size_t length = 0;
            if (first < 0x80) {
                codepoint = first;
                length = 1;
            } else if ((first & 0xE0) == 0xC0) {
                codepoint = first & 0x1F;
                length = 2;
            } else if ((first & 0xF0) == 0xE0) {
                codepoint = first & 0x0F;
                length = 3;
            } else if ((first & 0xF8) == 0xF0) {
                codepoint = first & 0x07;
                length = 4;
            } else {
                utf16.push_back(0xFFFD);
                ++index;
                continue;
            }

            bool valid = index + length <= limit;
            for (size_t offset = 1; valid && offset < length; ++offset) {
                const auto continuation = static_cast<uint8_t>(str[index + offset]);
                if ((continuation & 0xC0) != 0x80) {
                    valid = false;
                } else {
                    codepoint = (codepoint << 6) | (continuation & 0x3F);
                }
            }
            const bool overlong = (length == 2 && codepoint < 0x80)
                    || (length == 3 && codepoint < 0x800)
                    || (length == 4 && codepoint < 0x10000);
            if (!valid || overlong || codepoint > 0x10FFFF
                    || (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
                utf16.push_back(0xFFFD);
                ++index;
                continue;
            }

            if (codepoint <= 0xFFFF) {
                utf16.push_back(static_cast<jchar>(codepoint));
            } else {
                codepoint -= 0x10000;
                utf16.push_back(static_cast<jchar>(0xD800 + (codepoint >> 10)));
                utf16.push_back(static_cast<jchar>(0xDC00 + (codepoint & 0x3FF)));
            }
            index += length;
        }

        jstring result = env->NewString(
                utf16.empty() ? nullptr : utf16.data(),
                static_cast<jsize>(utf16.size()));
        if (result == nullptr && env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return result;
    } catch (...) {
        const jchar emptyValue = 0;
        jstring empty = env->NewString(&emptyValue, 0);
        if (empty == nullptr && env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return empty;
    }
}

static void clearPendingException(JNIEnv *env) {
    if (env != nullptr && env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static bool isAllowedSystemProperty(const std::string &name) {
    for (const auto &allowed : list_allowed_properties()) {
        if (allowed == name) return true;
    }
    return false;
}

// ==================== Collector JNI Methods ====================

static jstring jni_getDrmId(JNIEnv *env, jclass) {
    return toJString(env, get_drm_id(env));
}

static jstring jni_getBootId(JNIEnv *env, jclass) {
    return toJString(env, get_boot_id());
}

static jstring jni_getSystemProperty(JNIEnv *env, jclass, jstring jname) {
    if (jname == nullptr) return toJString(env, "");
    const char *name = env->GetStringUTFChars(jname, nullptr);
    if (name == nullptr) {
        clearPendingException(env);
        return toJString(env, "");
    }
    std::string propertyName(name);
    env->ReleaseStringUTFChars(jname, name);
    if (!isAllowedSystemProperty(propertyName)) {
        return toJString(env, "");
    }
    std::string value = get_system_property(propertyName.c_str());
    return toJString(env, value);
}

static jstring jni_getCpuInfo(JNIEnv *env, jclass) {
    return toJString(env, get_cpu_info());
}

static jlong jni_getDiskSize(JNIEnv *env, jclass, jstring jpath) {
    if (jpath == nullptr) return static_cast<jlong>(-1);
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) {
        clearPendingException(env);
        return static_cast<jlong>(-1);
    }
    long long size = get_disk_total_size(path);
    env->ReleaseStringUTFChars(jpath, path);
    return (jlong) size;
}

static jstring jni_getKernelInfo(JNIEnv *env, jclass) {
    return toJString(env, get_kernel_info());
}

// ==================== Detector JNI Methods ====================

static jboolean jni_checkRoot(JNIEnv *, jclass) {
    return (jboolean) native_check_root();
}

static jstring jni_getRootEvidence(JNIEnv *env, jclass) {
    return toJString(env, native_get_root_evidence());
}

static jstring jni_getHookEvidence(JNIEnv *env, jclass) {
    return toJString(env, native_get_hook_evidence(env));
}

static jint jni_getSelinuxEnforce(JNIEnv *, jclass) {
    return (jint) native_get_selinux_enforce();
}

static jstring jni_getBuildPropFingerprint(JNIEnv *env, jclass) {
    return toJString(env, native_get_build_prop_fingerprint());
}

static jstring jni_getProcCmdlineBootProps(JNIEnv *env, jclass) {
    return toJString(env, native_get_proc_cmdline_boot_props());
}

static jstring jni_scanProcessTokens(JNIEnv *env, jclass) {
    return toJString(env, native_scan_process_tokens());
}

static jstring jni_getSoIntegrity(JNIEnv *env, jclass) {
    return toJString(env, native_get_so_integrity_evidence());
}

static jstring jni_checkEmulatorFiles(JNIEnv *env, jclass) {
    return toJString(env, check_emulator_files());
}

static jint jni_getThermalZoneCount(JNIEnv *, jclass) {
    return (jint) get_thermal_zone_count();
}

static jstring jni_getRuntimeArch(JNIEnv *env, jclass) {
    return toJString(env, get_runtime_arch());
}

static jint jni_getTracerPid(JNIEnv *, jclass) {
    return (jint) get_tracer_pid();
}

static jstring jni_getMountNamespaceEvidence(JNIEnv *env, jclass) {
    return toJString(env, native_get_mount_namespace_evidence());
}

static jstring jni_getKernelRootEvidence(JNIEnv *env, jclass) {
    return toJString(env, native_get_kernel_root_evidence());
}

static jstring jni_getSealedVerdict(JNIEnv *env, jclass) {
    std::vector<const void *> ptrs;
    std::vector<uint64_t> prologues;
    copy_registered_table(ptrs, prologues);
    return toJString(env, native_build_sealed_verdict(
            env, ptrs.data(), prologues.data(), ptrs.size(), 0));
}

static jstring jni_getSealedVerdictWithChallenge(JNIEnv *env, jclass, jlong challenge) {
    std::vector<const void *> ptrs;
    std::vector<uint64_t> prologues;
    copy_registered_table(ptrs, prologues);
    return toJString(env, native_build_sealed_verdict(
            env, ptrs.data(), prologues.data(), ptrs.size(),
            static_cast<uint64_t>(challenge)));
}

static jint jni_verifySealedVerdict(JNIEnv *env, jclass, jstring jblob) {
    if (jblob == nullptr) return -1;
    const char *chars = env->GetStringUTFChars(jblob, nullptr);
    if (chars == nullptr) {
        clearPendingException(env);
        return -1;
    }
    std::string blob(chars);
    env->ReleaseStringUTFChars(jblob, chars);
    return static_cast<jint>(native_verify_sealed_verdict(blob));
}

static jint jni_verifySealedVerdictFlags(JNIEnv *env, jclass, jstring jblob) {
    if (jblob == nullptr) return -1;
    const char *chars = env->GetStringUTFChars(jblob, nullptr);
    if (chars == nullptr) {
        clearPendingException(env);
        return -1;
    }
    std::string blob(chars);
    env->ReleaseStringUTFChars(jblob, chars);
    return static_cast<jint>(native_verify_sealed_verdict_flags(blob));
}

static jlong jni_verifySealedVerdictPacked(JNIEnv *env, jclass, jstring jblob, jlong challenge) {
    if (jblob == nullptr) return static_cast<jlong>(-1);
    const char *chars = env->GetStringUTFChars(jblob, nullptr);
    if (chars == nullptr) {
        clearPendingException(env);
        return static_cast<jlong>(-1);
    }
    std::string blob(chars);
    env->ReleaseStringUTFChars(jblob, chars);
    return static_cast<jlong>(native_verify_sealed_verdict_packed(
            blob, static_cast<uint64_t>(challenge), true));
}

static jstring jni_getMonitorFindings(JNIEnv *env, jclass) {
    return toJString(env, native_monitor_findings());
}

static void jni_startMonitor(JNIEnv *env, jclass) {
    JavaVM *vm = nullptr;
    if (env != nullptr && env->GetJavaVM(&vm) == JNI_OK && vm != nullptr) {
        native_monitor_start(vm);
    }
}

static void jni_stopMonitor(JNIEnv *, jclass) {
    native_monitor_stop();
}

static jstring jni_getJniSelfIntegrity(JNIEnv *env, jclass) {
    std::vector<const void *> ptrs;
    std::vector<uint64_t> prologues;
    copy_registered_table(ptrs, prologues);
    auto maps = read_self_maps();
    return toJString(env, native_get_jni_self_table_evidence(
            env, ptrs.data(), prologues.data(), ptrs.size(), maps));
}

// ==================== Dynamic Obfuscated Registration ====================

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    struct DynamicEntry {
        std::string name;
        std::string sig;
        void *fn;
    };

    const std::string kSigStr = OBF("()Ljava/lang/String;");
    const std::string kSigStrToStr = OBF("(Ljava/lang/String;)Ljava/lang/String;");
    const std::string kSigStrToLong = OBF("(Ljava/lang/String;)J");
    const std::string kSigStrToInt = OBF("(Ljava/lang/String;)I");
    const std::string kSigBool = OBF("()Z");
    const std::string kSigInt = OBF("()I");
    const std::string kSigVoid = OBF("()V");
    const std::string kSigLongToStr = OBF("(J)Ljava/lang/String;");
    const std::string kSigStrLongToLong = OBF("(Ljava/lang/String;J)J");

    std::vector<DynamicEntry> entries = {
            // Collectors
            {OBF("nativeGetDrmId"),                   kSigStr,          reinterpret_cast<void *>(jni_getDrmId)},
            {OBF("nativeGetBootId"),                  kSigStr,          reinterpret_cast<void *>(jni_getBootId)},
            {OBF("nativeGetSystemPropertyRaw"),       kSigStrToStr,     reinterpret_cast<void *>(jni_getSystemProperty)},
            {OBF("nativeGetCpuInfo"),                 kSigStr,          reinterpret_cast<void *>(jni_getCpuInfo)},
            {OBF("nativeGetDiskSize"),                kSigStrToLong,    reinterpret_cast<void *>(jni_getDiskSize)},
            {OBF("nativeGetKernelInfo"),              kSigStr,          reinterpret_cast<void *>(jni_getKernelInfo)},

            // Detectors
            {OBF("nativeCheckRootRaw"),               kSigBool,         reinterpret_cast<void *>(jni_checkRoot)},
            {OBF("nativeGetRootEvidenceRaw"),         kSigStr,          reinterpret_cast<void *>(jni_getRootEvidence)},
            {OBF("nativeGetHookEvidenceRaw"),         kSigStr,          reinterpret_cast<void *>(jni_getHookEvidence)},
            {OBF("nativeCheckEmulatorFilesRaw"),      kSigStr,          reinterpret_cast<void *>(jni_checkEmulatorFiles)},
            {OBF("nativeGetThermalZoneCountRaw"),     kSigInt,          reinterpret_cast<void *>(jni_getThermalZoneCount)},
            {OBF("nativeGetRuntimeArchRaw"),          kSigStr,          reinterpret_cast<void *>(jni_getRuntimeArch)},
            {OBF("nativeGetTracerPidRaw"),            kSigInt,          reinterpret_cast<void *>(jni_getTracerPid)},
            {OBF("nGetSelinuxEnforceRaw"),            kSigInt,          reinterpret_cast<void *>(jni_getSelinuxEnforce)},
            {OBF("nGetBuildPropFingerprintRaw"),      kSigStr,          reinterpret_cast<void *>(jni_getBuildPropFingerprint)},
            {OBF("nGetProcCmdlineBootPropsRaw"),      kSigStr,          reinterpret_cast<void *>(jni_getProcCmdlineBootProps)},
            {OBF("nScanProcessTokensRaw"),            kSigStr,          reinterpret_cast<void *>(jni_scanProcessTokens)},
            {OBF("nGetSoIntegrityRaw"),               kSigStr,          reinterpret_cast<void *>(jni_getSoIntegrity)},
            {OBF("nGetMountNsEvidenceRaw"),           kSigStr,          reinterpret_cast<void *>(jni_getMountNamespaceEvidence)},
            {OBF("nGetKernelRootEvidenceRaw"),        kSigStr,          reinterpret_cast<void *>(jni_getKernelRootEvidence)},
            {OBF("nGetSealedVerdictRaw"),             kSigStr,          reinterpret_cast<void *>(jni_getSealedVerdict)},
            {OBF("nGetSealedVerdictWithChallengeRaw"),kSigLongToStr,    reinterpret_cast<void *>(jni_getSealedVerdictWithChallenge)},
            {OBF("nVerifySealedVerdictRaw"),          kSigStrToInt,     reinterpret_cast<void *>(jni_verifySealedVerdict)},
            {OBF("nVerifySealedVerdictFlagsRaw"),     kSigStrToInt,     reinterpret_cast<void *>(jni_verifySealedVerdictFlags)},
            {OBF("nVerifySealedVerdictPackedRaw"),    kSigStrLongToLong,reinterpret_cast<void *>(jni_verifySealedVerdictPacked)},
            {OBF("nGetJniSelfIntegrityRaw"),          kSigStr,          reinterpret_cast<void *>(jni_getJniSelfIntegrity)},
            {OBF("nGetMonitorFindingsRaw"),           kSigStr,          reinterpret_cast<void *>(jni_getMonitorFindings)},
            {OBF("nStartMonitorRaw"),                 kSigVoid,         reinterpret_cast<void *>(jni_startMonitor)},
            {OBF("nStopMonitorRaw"),                  kSigVoid,         reinterpret_cast<void *>(jni_stopMonitor)},
    };

    std::vector<JNINativeMethod> methods;
    methods.reserve(entries.size());
    for (const auto &entry : entries) {
        methods.push_back({entry.name.c_str(), entry.sig.c_str(), entry.fn});
    }

    std::string bridge_class = OBF(
            "com/wsttxm/riskenginesdk/collector/native_layer/NativeCollectorBridge");
    bool ok = custom_register_natives(
            env, bridge_class.c_str(), methods.data(), static_cast<int>(methods.size()));
    if (ok) {
        snapshot_registered_table(methods);
    }

    // Zero decoded names/signatures on the stack/heap after registration.
    crypto_mini::secure_zero(bridge_class.data(), bridge_class.size());
    for (auto &entry : entries) {
        crypto_mini::secure_zero(entry.name.data(), entry.name.size());
        crypto_mini::secure_zero(entry.sig.data(), entry.sig.size());
    }

    if (!ok) {
        return JNI_ERR;
    }

    native_monitor_start(vm);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(JavaVM *, void *) {
    native_monitor_stop();
}
