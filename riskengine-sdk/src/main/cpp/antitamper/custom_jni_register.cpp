#include "custom_jni_register.h"
#include <jni.h>
#include <android/log.h>

#define LOG_TAG "RiskEngine:JNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Custom JNI registration that uses direct function table access
// This makes it harder for hook frameworks to intercept RegisterNatives
bool custom_register_natives(JNIEnv *env, const char *class_name,
                             const JNINativeMethod *methods, int numMethods) {
    jclass clazz = env->FindClass(class_name);
    if (!clazz) {
        LOGD("Class not found: %s", class_name);
        return false;
    }

    // Use standard RegisterNatives for now
    // In production, this would resolve the function pointer from ART internals
    // to bypass standard RegisterNatives hooks
    jint result = env->RegisterNatives(clazz, methods, numMethods);
    if (result != JNI_OK) {
        LOGD("RegisterNatives failed for %s: %d", class_name, result);
        return false;
    }

    LOGD("Registered %d native methods for %s", numMethods, class_name);
    return true;
}
