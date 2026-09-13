#include "riskengine_jni.h"
#include "util/custom_jni_register.h"
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
#include <string>
#include <vector>

static jstring toJString(JNIEnv *env, const std::string &str) {
    if (env == nullptr || env->ExceptionCheck()) {
        return nullptr;
    }

    try {
    // NewStringUTF expects JNI modified UTF-8 and may abort under CheckJNI when
    // procfs or hooked inputs contain malformed bytes. Decode standard UTF-8
    // ourselves and replace malformed sequences before crossing the JNI edge.
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
        // Native collectors are best-effort. Never leave a pending JNI
        // exception that would abort a subsequent framework call.
        env->ExceptionClear();
    }
    return result;
    } catch (...) {
        // Never let a C++ allocation failure cross the JNI boundary.
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

// Forward declarations; both functions inspect the registration table below.
static jstring jni_getSealedVerdict(JNIEnv *env, jclass);

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

static jstring jni_getJniSelfIntegrity(JNIEnv *env, jclass);

// ==================== Registration ====================

static const char *BRIDGE_CLASS =
        "com/wsttxm/riskenginesdk/collector/native_layer/NativeCollectorBridge";

static JNINativeMethod methods[] = {
        // Collectors
        {"nativeGetDrmId",              "()Ljava/lang/String;",                  (void *) jni_getDrmId},
        {"nativeGetBootId",             "()Ljava/lang/String;",                  (void *) jni_getBootId},
        {"nativeGetSystemPropertyRaw",  "(Ljava/lang/String;)Ljava/lang/String;", (void *) jni_getSystemProperty},
        {"nativeGetCpuInfo",            "()Ljava/lang/String;",                  (void *) jni_getCpuInfo},
        {"nativeGetDiskSize",           "(Ljava/lang/String;)J",                 (void *) jni_getDiskSize},
        {"nativeGetKernelInfo",         "()Ljava/lang/String;",                  (void *) jni_getKernelInfo},

        // Detectors
        {"nativeCheckRootRaw",          "()Z",                                   (void *) jni_checkRoot},
        {"nativeGetRootEvidenceRaw",    "()Ljava/lang/String;",                  (void *) jni_getRootEvidence},
        {"nativeGetHookEvidenceRaw",    "()Ljava/lang/String;",                  (void *) jni_getHookEvidence},
        {"nativeCheckEmulatorFilesRaw", "()Ljava/lang/String;",                  (void *) jni_checkEmulatorFiles},
        {"nativeGetThermalZoneCountRaw","()I",                                   (void *) jni_getThermalZoneCount},
        {"nativeGetRuntimeArchRaw",     "()Ljava/lang/String;",                  (void *) jni_getRuntimeArch},
        {"nativeGetTracerPidRaw",       "()I",                                   (void *) jni_getTracerPid},
        {"nGetSelinuxEnforceRaw",       "()I",                                   (void *) jni_getSelinuxEnforce},
        {"nGetBuildPropFingerprintRaw", "()Ljava/lang/String;",                  (void *) jni_getBuildPropFingerprint},
        {"nScanProcessTokensRaw",       "()Ljava/lang/String;",                  (void *) jni_scanProcessTokens},
        {"nGetSoIntegrityRaw",          "()Ljava/lang/String;",                  (void *) jni_getSoIntegrity},
        {"nGetMountNsEvidenceRaw",      "()Ljava/lang/String;",                  (void *) jni_getMountNamespaceEvidence},
        {"nGetKernelRootEvidenceRaw",   "()Ljava/lang/String;",                  (void *) jni_getKernelRootEvidence},
        {"nGetSealedVerdictRaw",        "()Ljava/lang/String;",                  (void *) jni_getSealedVerdict},
        {"nVerifySealedVerdictRaw",     "(Ljava/lang/String;)I",                 (void *) jni_verifySealedVerdict},
        {"nVerifySealedVerdictFlagsRaw","(Ljava/lang/String;)I",                 (void *) jni_verifySealedVerdictFlags},
        {"nGetJniSelfIntegrityRaw",     "()Ljava/lang/String;",                  (void *) jni_getJniSelfIntegrity},
        {"nGetMonitorFindingsRaw",      "()Ljava/lang/String;",                  (void *) jni_getMonitorFindings},
        {"nStartMonitorRaw",            "()V",                                   (void *) jni_startMonitor},
        {"nStopMonitorRaw",             "()V",                                   (void *) jni_stopMonitor},
};

static jstring jni_getSealedVerdict(JNIEnv *env, jclass) {
    constexpr size_t kCount = sizeof(methods) / sizeof(methods[0]);
    const void *pointers[kCount];
    for (size_t i = 0; i < kCount; ++i) {
        pointers[i] = methods[i].fnPtr;
    }
    return toJString(env, native_build_sealed_verdict(env, pointers, kCount));
}

static jstring jni_getJniSelfIntegrity(JNIEnv *env, jclass) {
    // Verify that every pointer this library registered still resolves inside
    // this library. Checks the bridge that all other results travel through.
    constexpr size_t kCount = sizeof(methods) / sizeof(methods[0]);
    const void *pointers[kCount];
    for (size_t i = 0; i < kCount; ++i) {
        pointers[i] = methods[i].fnPtr;
    }
    return toJString(env,
                     native_get_jni_self_table_evidence(env, pointers, kCount));
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    int numMethods = sizeof(methods) / sizeof(methods[0]);
    if (!custom_register_natives(env, BRIDGE_CLASS, methods, numMethods)) {
        return JNI_ERR;
    }

    // Continuous re-verification. Started here rather than on first collect so
    // that a hook installed between library load and the first report is still
    // caught by a later pass.
    native_monitor_start(vm);

    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(JavaVM *, void *) {
    // A custom ClassLoader can unload this library without the Java engine's
    // shutdown hook running. Join the monitor before its code is unmapped.
    native_monitor_stop();
}
