#include "riskengine_jni.h"
#include "util/crypto_mini.h"
#include "util/custom_jni_register.h"
#include "util/obf_str.h"
#include "collector/drm_collector.h"
#include "collector/boot_id_collector.h"
#include "collector/system_property_collector.h"
#include "collector/cpu_info_collector.h"
#include "collector/disk_size_collector.h"
#include "collector/kernel_info_collector.h"
#include "detector/native_root_detector.h"
#include "detector/native_hook_detector.h"
#include "detector/native_integrity.h"
#include "detector/native_emulator_detector.h"
#include "detector/native_debug_detector.h"
#include "detector/runtime_arch_checker.h"
#include "detector/kernel_su_probe.h"
#include "detector/periodic_monitor.h"
#include "detector/apk_sig_native.h"
#include "detector/bionic_prop_area.h"
#include "detector/hardware_cpu_identity.h"
#include "detector/custom_rom_probe.h"
#include "detector/kernel_sidechannel.h"
#include "detector/selinux_audit_probe.h"
#include "detector/mount_forensics.h"
#include "detector/zygisk_atexit_probe.h"
#include "detector/virtualization_traps.h"
#include "detector/widevine_ndk_probe.h"
#include "detector/tee_binder_probe.h"
#include "detector/hma_uid_probe.h"
#include "generated/detection_lists.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <vector>

static jstring newEmptyJString(JNIEnv *env) {
    const jchar emptyValue = 0;
    jstring empty = env->NewString(&emptyValue, 0);
    if (empty == nullptr && env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    return empty;
}

static jstring toJString(JNIEnv *env, const std::string &str) {
    if (env == nullptr || env->ExceptionCheck()) {
        return nullptr;
    }

    constexpr size_t kMaxInputBytes = 1024 * 1024;
    const size_t limit = std::min(str.size(), kMaxInputBytes);
    if (limit == 0) {
        return newEmptyJString(env);
    }

    std::unique_ptr<jchar[]> utf16(new (std::nothrow) jchar[limit]);
    if (!utf16) {
        return newEmptyJString(env);
    }

    size_t outLen = 0;
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
            if (outLen < limit) utf16[outLen++] = 0xFFFD;
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
            if (outLen < limit) utf16[outLen++] = 0xFFFD;
            ++index;
            continue;
        }

        if (codepoint <= 0xFFFF) {
            if (outLen < limit) utf16[outLen++] = static_cast<jchar>(codepoint);
        } else {
            codepoint -= 0x10000;
            if (outLen + 1 < limit) {
                utf16[outLen++] = static_cast<jchar>(0xD800 + (codepoint >> 10));
                utf16[outLen++] = static_cast<jchar>(0xDC00 + (codepoint & 0x3FF));
            }
        }
        index += length;
    }

    jstring result = env->NewString(utf16.get(), static_cast<jsize>(outLen));
    if (result == nullptr && env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    return result;
}

static void clearPendingException(JNIEnv *env) {
    if (env != nullptr && env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static bool isAllowedSystemProperty(const char *name, size_t len) noexcept {
    return is_allowed_property_name(name, len);
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
    const size_t nameLen = std::strlen(name);
    if (!isAllowedSystemProperty(name, nameLen)) {
        env->ReleaseStringUTFChars(jname, name);
        return toJString(env, "");
    }
    std::string value = get_system_property(name);
    env->ReleaseStringUTFChars(jname, name);
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

static jstring jni_getDebugEvidence(JNIEnv *env, jclass) {
    return toJString(env, native_get_debug_evidence());
}

static jboolean jni_setAntiDumpable(JNIEnv *, jclass, jboolean enable) {
    return (jboolean) (native_set_anti_dumpable(enable == JNI_TRUE) ? JNI_TRUE : JNI_FALSE);
}

static jstring jni_getAdbProtocolEvidence(JNIEnv *env, jclass) {
    return toJString(env, native_get_adb_protocol_evidence());
}

static jstring jni_getKernelRootEvidence(JNIEnv *env, jclass) {
    return toJString(env, native_get_kernel_root_evidence());
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

static void jni_setMonitorBackground(JNIEnv *, jclass, jboolean background) {
    native_monitor_set_background(background == JNI_TRUE);
}

static jstring jni_getApkSigningInfo(JNIEnv *env, jclass, jstring jfallback) {
    if (jfallback == nullptr) {
        return toJString(env, native_get_apk_signing_info(""));
    }
    const char *fallback = env->GetStringUTFChars(jfallback, nullptr);
    if (fallback == nullptr) {
        clearPendingException(env);
        return toJString(env, native_get_apk_signing_info(""));
    }
    std::string payload = native_get_apk_signing_info(fallback);
    env->ReleaseStringUTFChars(jfallback, fallback);
    return toJString(env, payload);
}

static jstring jni_getBionicPropForensics(JNIEnv *env, jclass) {
    return toJString(env, native_get_bionic_prop_forensics());
}

static jstring jni_getHardwareCpuIdentity(JNIEnv *env, jclass) {
    return toJString(env, native_get_hardware_cpu_identity());
}

static jstring jni_getKernelConsistency(JNIEnv *env, jclass) {
    return toJString(env, native_get_kernel_consistency());
}

static jstring jni_getPifProperties(JNIEnv *env, jclass) {
    return toJString(env, native_get_pif_properties());
}

static jstring jni_getCustomRomProbe(JNIEnv *env, jclass) {
    return toJString(env, native_get_custom_rom_probe());
}

static jstring jni_getKernelSidechannel(JNIEnv *env, jclass, jboolean includePostponedTiming) {
    return toJString(env, native_get_kernel_sidechannel(includePostponedTiming == JNI_TRUE));
}

static jstring jni_getSelinuxAudit(JNIEnv *env, jclass, jint apiLevel, jint targetSdk) {
    return toJString(env, native_get_selinux_audit(
            static_cast<int>(apiLevel), static_cast<int>(targetSdk)));
}

static jstring jni_getMountForensics(JNIEnv *env, jclass) {
    return toJString(env, native_get_mount_forensics());
}

static jstring jni_getZygiskAtexitProbe(JNIEnv *env, jclass) {
    return toJString(env, native_get_zygisk_atexit_probe());
}

static jstring jni_getVirtualizationTraps(JNIEnv *env, jclass, jboolean includePostponedTraps) {
    return toJString(env, native_get_virtualization_traps(includePostponedTraps == JNI_TRUE));
}

static jstring jni_getActiveNetInterfaces(JNIEnv *env, jclass) {
    return toJString(env, native_get_active_net_interfaces());
}

static jstring jni_getWidevineNdkProbe(JNIEnv *env, jclass) {
    return toJString(env, native_get_widevine_ndk_probe());
}

static jstring jni_getTeeBinderProbe(JNIEnv *env, jclass, jboolean includeHoneypotTiming) {
    return toJString(env, native_get_tee_binder_probe(includeHoneypotTiming == JNI_TRUE));
}

static jstring jni_inspectLeafDer(JNIEnv *env, jclass, jbyteArray jder) {
    if (env == nullptr || jder == nullptr) {
        return toJString(env, native_inspect_leaf_der(nullptr, 0));
    }
    const jsize len = env->GetArrayLength(jder);
    if (len <= 0 || len > 256 * 1024) {
        return toJString(env, native_inspect_leaf_der(nullptr, 0));
    }
    jbyte *ptr = env->GetByteArrayElements(jder, nullptr);
    if (ptr == nullptr) {
        clearPendingException(env);
        return toJString(env, native_inspect_leaf_der(nullptr, 0));
    }
    std::string res = native_inspect_leaf_der(
            reinterpret_cast<const uint8_t *>(ptr), static_cast<size_t>(len));
    env->ReleaseByteArrayElements(jder, ptr, JNI_ABORT);
    return toJString(env, res);
}

static jstring jni_scanActiveAppUids(JNIEnv *env, jclass, jint firstUid, jint lastUid) {
    return toJString(env, native_scan_active_app_uids(
            static_cast<int>(firstUid), static_cast<int>(lastUid)));
}

static jstring jni_probeSeccompUidFilter(JNIEnv *env, jclass, jint firstUid, jint lastUid) {
    return toJString(env, native_probe_seccomp_uid_filter(
            static_cast<int>(firstUid), static_cast<int>(lastUid)));
}

// ==================== Dynamic Obfuscated Registration ====================

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    struct DynamicEntry {
        std::string name;
        const char *sig;
        void *fn;
    };

    const auto kSigStr = OBF("()Ljava/lang/String;");
    const auto kSigStrToStr = OBF("(Ljava/lang/String;)Ljava/lang/String;");
    const auto kSigStrToLong = OBF("(Ljava/lang/String;)J");
    const auto kSigBool = OBF("()Z");
    const auto kSigBoolToBool = OBF("(Z)Z");
    const auto kSigBoolToStr = OBF("(Z)Ljava/lang/String;");
    const auto kSigBytesToStr = OBF("([B)Ljava/lang/String;");
    const auto kSigIntIntToStr = OBF("(II)Ljava/lang/String;");
    const auto kSigBoolToVoid = OBF("(Z)V");
    const auto kSigInt = OBF("()I");
    const auto kSigVoid = OBF("()V");

    std::vector<DynamicEntry> entries = {
            // Collectors
            {OBF("nativeGetDrmId"),                   kSigStr.c_str(),          reinterpret_cast<void *>(jni_getDrmId)},
            {OBF("nativeGetBootId"),                  kSigStr.c_str(),          reinterpret_cast<void *>(jni_getBootId)},
            {OBF("nativeGetSystemPropertyRaw"),       kSigStrToStr.c_str(),     reinterpret_cast<void *>(jni_getSystemProperty)},
            {OBF("nativeGetCpuInfo"),                 kSigStr.c_str(),          reinterpret_cast<void *>(jni_getCpuInfo)},
            {OBF("nativeGetDiskSize"),                kSigStrToLong.c_str(),    reinterpret_cast<void *>(jni_getDiskSize)},
            {OBF("nativeGetKernelInfo"),              kSigStr.c_str(),          reinterpret_cast<void *>(jni_getKernelInfo)},

            // Detectors
            {OBF("nativeCheckRootRaw"),               kSigBool.c_str(),         reinterpret_cast<void *>(jni_checkRoot)},
            {OBF("nativeGetRootEvidenceRaw"),         kSigStr.c_str(),          reinterpret_cast<void *>(jni_getRootEvidence)},
            {OBF("nativeGetHookEvidenceRaw"),         kSigStr.c_str(),          reinterpret_cast<void *>(jni_getHookEvidence)},
            {OBF("nativeCheckEmulatorFilesRaw"),      kSigStr.c_str(),          reinterpret_cast<void *>(jni_checkEmulatorFiles)},
            {OBF("nativeGetThermalZoneCountRaw"),     kSigInt.c_str(),          reinterpret_cast<void *>(jni_getThermalZoneCount)},
            {OBF("nativeGetRuntimeArchRaw"),          kSigStr.c_str(),          reinterpret_cast<void *>(jni_getRuntimeArch)},
            {OBF("nativeGetTracerPidRaw"),            kSigInt.c_str(),          reinterpret_cast<void *>(jni_getTracerPid)},
            {OBF("nGetDebugEvidenceRaw"),             kSigStr.c_str(),          reinterpret_cast<void *>(jni_getDebugEvidence)},
            {OBF("nSetAntiDumpableRaw"),              kSigBoolToBool.c_str(),   reinterpret_cast<void *>(jni_setAntiDumpable)},
            {OBF("nGetAdbProtocolEvidenceRaw"),       kSigStr.c_str(),          reinterpret_cast<void *>(jni_getAdbProtocolEvidence)},
            {OBF("nGetSelinuxEnforceRaw"),            kSigInt.c_str(),          reinterpret_cast<void *>(jni_getSelinuxEnforce)},
            {OBF("nGetBuildPropFingerprintRaw"),      kSigStr.c_str(),          reinterpret_cast<void *>(jni_getBuildPropFingerprint)},
            {OBF("nGetProcCmdlineBootPropsRaw"),      kSigStr.c_str(),          reinterpret_cast<void *>(jni_getProcCmdlineBootProps)},
            {OBF("nGetKernelRootEvidenceRaw"),        kSigStr.c_str(),          reinterpret_cast<void *>(jni_getKernelRootEvidence)},
            {OBF("nGetMonitorFindingsRaw"),           kSigStr.c_str(),          reinterpret_cast<void *>(jni_getMonitorFindings)},
            {OBF("nStartMonitorRaw"),                 kSigVoid.c_str(),         reinterpret_cast<void *>(jni_startMonitor)},
            {OBF("nStopMonitorRaw"),                  kSigVoid.c_str(),         reinterpret_cast<void *>(jni_stopMonitor)},
            {OBF("nSetMonitorBackgroundRaw"),         kSigBoolToVoid.c_str(),   reinterpret_cast<void *>(jni_setMonitorBackground)},
            {OBF("nGetApkSigningInfoRaw"),            kSigStrToStr.c_str(),     reinterpret_cast<void *>(jni_getApkSigningInfo)},
            {OBF("nGetBionicPropForensicsRaw"),       kSigStr.c_str(),          reinterpret_cast<void *>(jni_getBionicPropForensics)},
            {OBF("nGetHardwareCpuIdentityRaw"),       kSigStr.c_str(),          reinterpret_cast<void *>(jni_getHardwareCpuIdentity)},
            {OBF("nGetKernelConsistencyRaw"),         kSigStr.c_str(),          reinterpret_cast<void *>(jni_getKernelConsistency)},
            {OBF("nGetPifPropertiesRaw"),             kSigStr.c_str(),          reinterpret_cast<void *>(jni_getPifProperties)},
            {OBF("nGetCustomRomProbeRaw"),            kSigStr.c_str(),          reinterpret_cast<void *>(jni_getCustomRomProbe)},
            {OBF("nGetKernelSidechannelRaw"),         kSigBoolToStr.c_str(),    reinterpret_cast<void *>(jni_getKernelSidechannel)},
            {OBF("nGetSelinuxAuditRaw"),              kSigIntIntToStr.c_str(),  reinterpret_cast<void *>(jni_getSelinuxAudit)},
            {OBF("nGetMountForensicsRaw"),            kSigStr.c_str(),          reinterpret_cast<void *>(jni_getMountForensics)},
            {OBF("nGetZygiskAtexitProbeRaw"),         kSigStr.c_str(),          reinterpret_cast<void *>(jni_getZygiskAtexitProbe)},
            {OBF("nGetVirtualizationTrapsRaw"),       kSigBoolToStr.c_str(),    reinterpret_cast<void *>(jni_getVirtualizationTraps)},
            {OBF("nGetActiveNetInterfacesRaw"),       kSigStr.c_str(),          reinterpret_cast<void *>(jni_getActiveNetInterfaces)},
            {OBF("nGetWidevineNdkProbeRaw"),          kSigStr.c_str(),          reinterpret_cast<void *>(jni_getWidevineNdkProbe)},
            {OBF("nGetTeeBinderProbeRaw"),            kSigBoolToStr.c_str(),    reinterpret_cast<void *>(jni_getTeeBinderProbe)},
            {OBF("nInspectLeafDerRaw"),               kSigBytesToStr.c_str(),   reinterpret_cast<void *>(jni_inspectLeafDer)},
            {OBF("nScanActiveAppUidsRaw"),            kSigIntIntToStr.c_str(),  reinterpret_cast<void *>(jni_scanActiveAppUids)},
            {OBF("nProbeSeccompUidFilterRaw"),        kSigIntIntToStr.c_str(),  reinterpret_cast<void *>(jni_probeSeccompUidFilter)},
    };

    std::vector<JNINativeMethod> methods;
    methods.reserve(entries.size());
    for (const auto &entry : entries) {
        methods.push_back({entry.name.c_str(), entry.sig, entry.fn});
    }

    const auto bridge_class = OBF(
            "com/wsttxm/riskenginesdk/collector/native_layer/NativeCollectorBridge");
    bool ok = custom_register_natives(
            env, bridge_class.c_str(), methods.data(), static_cast<int>(methods.size()));

    if (ok) {
        native_integrity_record_jni_table(methods.data(), static_cast<int>(methods.size()));
        native_integrity_record_core_fn(
                OBF("root_ev").c_str(),
                reinterpret_cast<const void *>(&native_get_root_evidence));
        native_integrity_record_core_fn(
                OBF("hook_ev").c_str(),
                reinterpret_cast<const void *>(
                        static_cast<std::string (*)(JNIEnv *)>(&native_get_hook_evidence)));
        native_integrity_record_core_fn(
                OBF("tracer_pid").c_str(),
                reinterpret_cast<const void *>(&get_tracer_pid));
        native_integrity_record_core_fn(
                OBF("integrity_ev").c_str(),
                reinterpret_cast<const void *>(
                        static_cast<std::string (*)(JNIEnv *)>(&native_get_integrity_evidence)));
    }

    // Zero decoded names on heap after registration; kSig* and bridge_class wipe on scope exit.
    for (auto &entry : entries) {
        crypto_mini::secure_zero(entry.name.data(), entry.name.size());
    }

    if (!ok) {
        return JNI_ERR;
    }

    // Pre-cache NativeMonitorDispatcher jclass GlobalRef + jmethodID here; do NOT
    // auto-start the monitor thread so RiskEngineConfig.enablePeriodicMonitor(false)
    // is strictly respected.
    native_monitor_init_dispatcher(env, vm);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *) {
    // Stop and join monitor thread BEFORE freeing dispatcher GlobalRef.
    native_monitor_stop();
    JNIEnv *env = nullptr;
    if (vm != nullptr && vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) == JNI_OK) {
        native_monitor_cleanup_dispatcher(env);
    } else {
        native_monitor_cleanup_dispatcher(nullptr);
    }
}

// libc++abi's default_terminate_handler references __cxa_demangle, pulling ~140 KB
// of Itanium demangler code and vtable relocations into static c++_static builds.
// With -fno-exceptions -fno-rtti and hidden symbol visibility, release-like links
// wrap __cxa_demangle so --gc-sections drops the unused demangler cleanly.
extern "C" __attribute__((visibility("hidden")))
char *__wrap___cxa_demangle(const char *, char *, size_t *, int *status) {
    if (status != nullptr) {
        *status = -2;
    }
    return nullptr;
}
