#include "drm_collector.h"
#include <jni.h>
#include <string>
#include <android/log.h>

#define LOG_TAG "RiskEngine:DRM"

// DRM ID is collected via Java MediaDrm API called through JNI
// This is because MediaDrm requires Java-level API access
std::string get_drm_id(JNIEnv *env) {
    // Get UUID for Widevine
    jclass uuidClass = env->FindClass("java/util/UUID");
    if (!uuidClass) return "";

    jmethodID uuidCtor = env->GetMethodID(uuidClass, "<init>", "(JJ)V");
    // Widevine UUID: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
    jobject uuid = env->NewObject(uuidClass, uuidCtor,
                                  (jlong) 0xedef8ba979d64aceLL,
                                  (jlong) 0xa3c827dcd51d21edLL);

    jclass mediaDrmClass = env->FindClass("android/media/MediaDrm");
    if (!mediaDrmClass) return "";

    jmethodID ctor = env->GetMethodID(mediaDrmClass, "<init>", "(Ljava/util/UUID;)V");
    jobject mediaDrm = env->NewObject(mediaDrmClass, ctor, uuid);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return "";
    }

    jmethodID getPropertyByteArray = env->GetMethodID(mediaDrmClass,
                                                       "getPropertyByteArray", "(Ljava/lang/String;)[B");
    jstring propName = env->NewStringUTF("deviceUniqueId");
    jbyteArray idArray = (jbyteArray) env->CallObjectMethod(mediaDrm, getPropertyByteArray, propName);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        // Close MediaDrm
        jmethodID closeMethod = env->GetMethodID(mediaDrmClass, "close", "()V");
        env->CallVoidMethod(mediaDrm, closeMethod);
        return "";
    }

    std::string result;
    if (idArray) {
        jsize len = env->GetArrayLength(idArray);
        jbyte *bytes = env->GetByteArrayElements(idArray, nullptr);
        char hex[3];
        for (int i = 0; i < len; i++) {
            sprintf(hex, "%02x", (unsigned char) bytes[i]);
            result += hex;
        }
        env->ReleaseByteArrayElements(idArray, bytes, 0);
    }

    // Close MediaDrm
    jmethodID closeMethod = env->GetMethodID(mediaDrmClass, "close", "()V");
    env->CallVoidMethod(mediaDrm, closeMethod);

    return result;
}
