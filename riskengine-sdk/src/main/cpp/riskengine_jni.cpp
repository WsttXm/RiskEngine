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
#include "detector/runtime_arch_checker.h"

#include <algorithm>
#include <array>
#include <string>

static jstring toJString(JNIEnv *env, const std::string &str) {
    return env->NewStringUTF(str.c_str());
}

static bool isAllowedSystemProperty(const std::string &name) {
    static constexpr std::array<const char *, 18> allowed = {
            "service.adb.tcp.port", "persist.adb.tcp.port",
            "ro.build.fingerprint", "ro.build.display.id", "ro.product.model",
            "ro.product.brand", "ro.product.device", "ro.product.manufacturer",
            "ro.hardware", "ro.board.platform", "persist.sys.timezone",
            "gsm.version.baseband", "ro.lineage.version", "ro.cm.version",
            "ro.mokee.version", "ro.rr.version", "ro.pixelexperience.version",
            "ro.modversion"
    };
    return std::find(allowed.begin(), allowed.end(), name) != allowed.end();
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
    if (name == nullptr) return toJString(env, "");
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
    if (path == nullptr) return static_cast<jlong>(-1);
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
    return toJString(env, native_get_hook_evidence());
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
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    int numMethods = sizeof(methods) / sizeof(methods[0]);
    if (!custom_register_natives(env, BRIDGE_CLASS, methods, numMethods)) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
