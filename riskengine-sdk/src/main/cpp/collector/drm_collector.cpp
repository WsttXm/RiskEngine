#include "drm_collector.h"
#include <jni.h>
#include <string>
#include <vector>

namespace {

void clear_pending_exception(JNIEnv *env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

}  // namespace

// DRM ID is collected via Java MediaDrm API called through JNI
// This is because MediaDrm requires Java-level API access
std::string get_drm_id(JNIEnv *env) {
    if (env == nullptr) return "";

    jclass uuidClass = nullptr;
    jobject uuid = nullptr;
    jclass mediaDrmClass = nullptr;
    jobject mediaDrm = nullptr;
    jstring propName = nullptr;
    jbyteArray idArray = nullptr;

    auto cleanup = [&]() {
        clear_pending_exception(env);
        if (mediaDrm != nullptr && mediaDrmClass != nullptr) {
            jmethodID closeMethod = env->GetMethodID(mediaDrmClass, "close", "()V");
            if (closeMethod != nullptr && !env->ExceptionCheck()) {
                env->CallVoidMethod(mediaDrm, closeMethod);
            }
            clear_pending_exception(env);
        }
        if (idArray != nullptr) env->DeleteLocalRef(idArray);
        if (propName != nullptr) env->DeleteLocalRef(propName);
        if (mediaDrm != nullptr) env->DeleteLocalRef(mediaDrm);
        if (mediaDrmClass != nullptr) env->DeleteLocalRef(mediaDrmClass);
        if (uuid != nullptr) env->DeleteLocalRef(uuid);
        if (uuidClass != nullptr) env->DeleteLocalRef(uuidClass);
    };

    uuidClass = env->FindClass("java/util/UUID");
    if (uuidClass == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }

    jmethodID uuidCtor = env->GetMethodID(uuidClass, "<init>", "(JJ)V");
    if (uuidCtor == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }
    // Widevine UUID: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
    uuid = env->NewObject(uuidClass, uuidCtor,
                          static_cast<jlong>(0xedef8ba979d64aceLL),
                          static_cast<jlong>(0xa3c827dcd51d21edLL));
    if (uuid == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }

    mediaDrmClass = env->FindClass("android/media/MediaDrm");
    if (mediaDrmClass == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }

    jmethodID ctor = env->GetMethodID(mediaDrmClass, "<init>", "(Ljava/util/UUID;)V");
    if (ctor == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }
    mediaDrm = env->NewObject(mediaDrmClass, ctor, uuid);
    if (mediaDrm == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }

    jmethodID getPropertyByteArray = env->GetMethodID(mediaDrmClass,
                                                       "getPropertyByteArray", "(Ljava/lang/String;)[B");
    if (getPropertyByteArray == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }
    propName = env->NewStringUTF("deviceUniqueId");
    if (propName == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }
    idArray = static_cast<jbyteArray>(
            env->CallObjectMethod(mediaDrm, getPropertyByteArray, propName));
    if (idArray == nullptr || env->ExceptionCheck()) {
        cleanup();
        return "";
    }

    jsize len = env->GetArrayLength(idArray);
    if (env->ExceptionCheck() || len <= 0 || len > 4096) {
        cleanup();
        return "";
    }
    std::vector<jbyte> bytes(static_cast<size_t>(len));
    env->GetByteArrayRegion(idArray, 0, len, bytes.data());
    if (env->ExceptionCheck()) {
        cleanup();
        return "";
    }

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(static_cast<size_t>(len) * 2);
    for (jbyte item : bytes) {
        auto value = static_cast<unsigned char>(item);
        result.push_back(hex[(value >> 4) & 0x0f]);
        result.push_back(hex[value & 0x0f]);
    }

    cleanup();
    return result;
}
