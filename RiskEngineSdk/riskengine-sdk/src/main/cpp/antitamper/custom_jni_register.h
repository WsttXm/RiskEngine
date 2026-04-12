#ifndef RISKENGINE_CUSTOM_JNI_REGISTER_H
#define RISKENGINE_CUSTOM_JNI_REGISTER_H

#include <jni.h>

bool custom_register_natives(JNIEnv *env, const char *class_name,
                             const JNINativeMethod *methods, int numMethods);

#endif
