#include "custom_jni_register.h"

bool custom_register_natives(JNIEnv *env, const char *class_name,
                             const JNINativeMethod *methods, int numMethods) {
    jclass clazz = env->FindClass(class_name);
    if (clazz == nullptr) {
        return false;
    }
    jint result = env->RegisterNatives(clazz, methods, numMethods);
    env->DeleteLocalRef(clazz);
    return result == JNI_OK;
}
