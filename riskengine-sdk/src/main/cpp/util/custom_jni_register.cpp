#include "custom_jni_register.h"
#include <android/log.h>

static constexpr const char *kLogTag = "RiskEngine-JNI";

bool custom_register_natives(JNIEnv *env, const char *class_name,
                             const JNINativeMethod *methods, int numMethods) {
    jclass clazz = env->FindClass(class_name);
    if (clazz == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                            "FindClass failed for %s", class_name);
        return false;
    }
    jint result = env->RegisterNatives(clazz, methods, numMethods);
    if (result != JNI_OK) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                            "RegisterNatives failed for %s: %d", class_name, result);
    }
    env->DeleteLocalRef(clazz);
    return result == JNI_OK;
}
