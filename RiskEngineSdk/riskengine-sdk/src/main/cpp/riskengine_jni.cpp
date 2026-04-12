#include "riskengine_jni.h"
#include "antitamper/custom_jni_register.h"
#include "antitamper/memory_crc_checker.h"
#include "antitamper/maps_monitor.h"
#include "collector/drm_collector.h"
#include "collector/boot_id_collector.h"
#include "collector/system_property_collector.h"
#include "collector/cpu_info_collector.h"
#include "collector/disk_size_collector.h"
#include "collector/mac_netlink_collector.h"
#include "collector/kernel_info_collector.h"
#include "detector/native_root_detector.h"
#include "detector/native_hook_detector.h"
#include "detector/native_emulator_detector.h"
#include "detector/native_debug_detector.h"
#include "detector/native_signature_checker.h"
#include "detector/seccomp_arch_checker.h"

#include <android/log.h>
#include <string>

#define LOG_TAG "RiskEngine:JNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static JavaVM *g_jvm = nullptr;

static jstring toJString(JNIEnv *env, const std::string &str) {
    return env->NewStringUTF(str.c_str());
}

// ==================== Collector JNI Methods ====================

static jstring jni_getDrmId(JNIEnv *env, jclass) {
    return toJString(env, get_drm_id(env));
}

static jstring jni_getBootId(JNIEnv *env, jclass) {
    return toJString(env, get_boot_id());
}

static jstring jni_getSystemProperty(JNIEnv *env, jclass, jstring jname) {
    const char *name = env->GetStringUTFChars(jname, nullptr);
    std::string value = get_system_property(name);
    env->ReleaseStringUTFChars(jname, name);
    return toJString(env, value);
}

static jstring jni_getAllSystemProperties(JNIEnv *env, jclass) {
    // Return a summary of key properties
    std::string result;
    const char *props[] = {
            "ro.build.fingerprint", "ro.product.model", "ro.product.brand",
            "ro.product.device", "ro.product.manufacturer", "ro.hardware",
            "ro.serialno", "ro.boot.serialno", nullptr
    };
    for (int i = 0; props[i]; i++) {
        std::string val = get_system_property(props[i]);
        if (!val.empty()) {
            if (!result.empty()) result += "|";
            result += std::string(props[i]) + "=" + val;
        }
    }
    return toJString(env, result);
}

static jstring jni_getCpuInfo(JNIEnv *env, jclass) {
    return toJString(env, get_cpu_info());
}

static jlong jni_getDiskSize(JNIEnv *env, jclass, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    long long size = get_disk_total_size(path);
    env->ReleaseStringUTFChars(jpath, path);
    return (jlong) size;
}

static jstring jni_getMacAddress(JNIEnv *env, jclass) {
    return toJString(env, get_mac_via_netlink());
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

static jboolean jni_checkHooks(JNIEnv *, jclass) {
    return (jboolean) native_check_hooks();
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

static jstring jni_checkSeccompArch(JNIEnv *env, jclass) {
    return toJString(env, check_arch_by_seccomp());
}

static jint jni_getTracerPid(JNIEnv *, jclass) {
    return (jint) get_tracer_pid();
}

static jboolean jni_checkPtrace(JNIEnv *, jclass) {
    return (jboolean) check_ptrace();
}

static jstring jni_verifyApkSignature(JNIEnv *env, jclass, jstring japkPath) {
    const char *path = env->GetStringUTFChars(japkPath, nullptr);
    std::string result = verify_apk_signature(path);
    env->ReleaseStringUTFChars(japkPath, path);
    return toJString(env, result);
}

// ==================== Anti-Tamper JNI Methods ====================

static jboolean jni_initMemoryCrc(JNIEnv *, jclass) {
    // Get path to our own .so from /proc/self/maps
    // For simplicity, use a known path pattern
    return (jboolean) init_memory_crc("libriskengine.so");
}

static jboolean jni_checkMemoryCrc(JNIEnv *, jclass) {
    return (jboolean) check_memory_crc();
}

static jboolean jni_checkMapsRedirect(JNIEnv *, jclass) {
    return (jboolean) check_maps_redirect();
}

// ==================== Registration ====================

static const char *BRIDGE_CLASS =
        "com/wsttxm/riskenginesdk/collector/native_layer/NativeCollectorBridge";

static JNINativeMethod methods[] = {
        // Collectors
        {"nativeGetDrmId",              "()Ljava/lang/String;",                  (void *) jni_getDrmId},
        {"nativeGetBootId",             "()Ljava/lang/String;",                  (void *) jni_getBootId},
        {"nativeGetSystemProperty",     "(Ljava/lang/String;)Ljava/lang/String;", (void *) jni_getSystemProperty},
        {"nativeGetAllSystemProperties","()Ljava/lang/String;",                  (void *) jni_getAllSystemProperties},
        {"nativeGetCpuInfo",            "()Ljava/lang/String;",                  (void *) jni_getCpuInfo},
        {"nativeGetDiskSize",           "(Ljava/lang/String;)J",                 (void *) jni_getDiskSize},
        {"nativeGetMacAddress",         "()Ljava/lang/String;",                  (void *) jni_getMacAddress},
        {"nativeGetKernelInfo",         "()Ljava/lang/String;",                  (void *) jni_getKernelInfo},

        // Detectors
        {"nativeCheckRoot",             "()Z",                                   (void *) jni_checkRoot},
        {"nativeGetRootEvidence",       "()Ljava/lang/String;",                  (void *) jni_getRootEvidence},
        {"nativeCheckHooks",            "()Z",                                   (void *) jni_checkHooks},
        {"nativeGetHookEvidence",       "()Ljava/lang/String;",                  (void *) jni_getHookEvidence},
        {"nativeCheckEmulatorFiles",    "()Ljava/lang/String;",                  (void *) jni_checkEmulatorFiles},
        {"nativeGetThermalZoneCount",   "()I",                                   (void *) jni_getThermalZoneCount},
        {"nativeCheckSeccompArch",      "()Ljava/lang/String;",                  (void *) jni_checkSeccompArch},
        {"nativeGetTracerPid",          "()I",                                   (void *) jni_getTracerPid},
        {"nativeCheckPtrace",           "()Z",                                   (void *) jni_checkPtrace},
        {"nativeVerifyApkSignature",    "(Ljava/lang/String;)Ljava/lang/String;", (void *) jni_verifyApkSignature},

        // Anti-tamper
        {"nativeInitMemoryCrc",         "()Z",                                   (void *) jni_initMemoryCrc},
        {"nativeCheckMemoryCrc",        "()Z",                                   (void *) jni_checkMemoryCrc},
        {"nativeCheckMapsRedirect",     "()Z",                                   (void *) jni_checkMapsRedirect},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    g_jvm = vm;
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    int numMethods = sizeof(methods) / sizeof(methods[0]);
    if (!custom_register_natives(env, BRIDGE_CLASS, methods, numMethods)) {
        LOGD("Failed to register native methods");
        return JNI_ERR;
    }

    LOGD("RiskEngine native library loaded successfully");
    return JNI_VERSION_1_6;
}
