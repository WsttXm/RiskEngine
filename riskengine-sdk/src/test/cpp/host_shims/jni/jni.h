#ifndef RISKENGINE_HOST_SHIM_JNI_H
#define RISKENGINE_HOST_SHIM_JNI_H

#include <cstdint>

struct JNIEnv;
typedef void *jobject;
typedef void *jclass;
typedef void *jstring;
typedef int32_t jint;
typedef int64_t jlong;
typedef uint8_t jboolean;

struct JNINativeInterface {
    void *reserved0;
    void *reserved1;
    void *reserved2;
    void *reserved3;
    jint (*GetVersion)(JNIEnv *);
    void *DefineClass;
    jclass (*FindClass)(JNIEnv *, const char *);
};

struct JNIEnv {
    const JNINativeInterface *functions;
};

struct JNINativeMethod {
    const char *name;
    const char *signature;
    void *fnPtr;
};

#endif  // RISKENGINE_HOST_SHIM_JNI_H
