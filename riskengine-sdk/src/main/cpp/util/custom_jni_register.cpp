#include "custom_jni_register.h"
#include "obf_str.h"
#include <android/log.h>

bool custom_register_natives(JNIEnv *env, const char *class_name,
                             const JNINativeMethod *methods, int numMethods) {
    jclass clazz = env->FindClass(class_name);
    if (clazz == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        __android_log_print(ANDROID_LOG_ERROR, OBF("RiskEngine-JNI").c_str(),
                            "%s", OBF("FindClass failed").c_str());
        return false;
    }
    jint result = env->RegisterNatives(clazz, methods, numMethods);
    if (result != JNI_OK) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        __android_log_print(ANDROID_LOG_ERROR, OBF("RiskEngine-JNI").c_str(),
                            "%s: %d", OBF("RegisterNatives failed").c_str(), result);
    }
    env->DeleteLocalRef(clazz);
    return result == JNI_OK;
}
