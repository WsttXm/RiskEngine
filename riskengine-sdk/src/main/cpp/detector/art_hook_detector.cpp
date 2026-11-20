#include "art_hook_detector.h"

#include "../util/maps_parser.h"
#include "../util/obf_str.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void add_token(std::vector<std::string> &tokens, const std::string &token) {
    if (!token.empty()
        && std::find(tokens.begin(), tokens.end(), token) == tokens.end()) {
        tokens.push_back(token);
    }
}

std::string join_tokens(const std::vector<std::string> &tokens) {
    std::string joined;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i) joined += ",";
        joined += tokens[i];
    }
    return joined;
}

void clear_exception(JNIEnv *env) {
    if (env != nullptr && env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool method_is_native(JNIEnv *env, const std::string &class_name,
                      const std::string &method_name, const std::string &signature,
                      bool is_static, bool &found) {
    found = false;
    jclass target = env->FindClass(class_name.c_str());
    if (target == nullptr) {
        clear_exception(env);
        return false;
    }
    jmethodID method = is_static
            ? env->GetStaticMethodID(target, method_name.c_str(), signature.c_str())
            : env->GetMethodID(target, method_name.c_str(), signature.c_str());
    if (method == nullptr) {
        clear_exception(env);
        env->DeleteLocalRef(target);
        return false;
    }
    jobject reflected = env->ToReflectedMethod(target, method, is_static);
    if (reflected == nullptr) {
        clear_exception(env);
        env->DeleteLocalRef(target);
        return false;
    }

    jint modifiers = 0;
    jclass method_class = env->FindClass(OBF("java/lang/reflect/Method").c_str());
    if (method_class != nullptr) {
        jmethodID get_modifiers =
                env->GetMethodID(method_class, OBF("getModifiers").c_str(), OBF("()I").c_str());
        if (get_modifiers != nullptr) {
            modifiers = env->CallIntMethod(reflected, get_modifiers);
            if (env->ExceptionCheck()) {
                clear_exception(env);
            } else {
                found = true;
            }
        } else {
            clear_exception(env);
        }
        env->DeleteLocalRef(method_class);
    } else {
        clear_exception(env);
    }

    env->DeleteLocalRef(reflected);
    env->DeleteLocalRef(target);

    constexpr jint kAccNative = 0x0100;
    return (modifiers & kAccNative) != 0;
}

void inspect_class_loader_chain(JNIEnv *env, std::vector<std::string> &tokens) {
    jclass anchor = env->FindClass(OBF(
            "com/wsttxm/riskenginesdk/collector/native_layer/NativeCollectorBridge").c_str());
    if (anchor == nullptr) {
        clear_exception(env);
        return;
    }
    jclass class_class = env->FindClass(OBF("java/lang/Class").c_str());
    jclass loader_class = env->FindClass(OBF("java/lang/ClassLoader").c_str());
    jclass object_class = env->FindClass(OBF("java/lang/Object").c_str());
    if (class_class == nullptr || loader_class == nullptr || object_class == nullptr) {
        clear_exception(env);
        if (object_class != nullptr) env->DeleteLocalRef(object_class);
        if (loader_class != nullptr) env->DeleteLocalRef(loader_class);
        if (class_class != nullptr) env->DeleteLocalRef(class_class);
        env->DeleteLocalRef(anchor);
        return;
    }

    jmethodID get_loader = env->GetMethodID(class_class,
            OBF("getClassLoader").c_str(), OBF("()Ljava/lang/ClassLoader;").c_str());
    jmethodID get_parent = env->GetMethodID(loader_class,
            OBF("getParent").c_str(), OBF("()Ljava/lang/ClassLoader;").c_str());
    jmethodID get_class = env->GetMethodID(object_class,
            OBF("getClass").c_str(), OBF("()Ljava/lang/Class;").c_str());
    jmethodID get_name = env->GetMethodID(class_class,
            OBF("getName").c_str(), OBF("()Ljava/lang/String;").c_str());

    std::vector<std::string> chain;
    if (get_loader != nullptr && get_parent != nullptr
        && get_class != nullptr && get_name != nullptr) {
        jobject loader = env->CallObjectMethod(anchor, get_loader);
        clear_exception(env);
        int depth = 0;
        while (loader != nullptr && depth < 12) {
            jobject loader_type = env->CallObjectMethod(loader, get_class);
            if (loader_type == nullptr || env->ExceptionCheck()) {
                clear_exception(env);
                env->DeleteLocalRef(loader);
                break;
            }
            auto name = static_cast<jstring>(env->CallObjectMethod(loader_type, get_name));
            if (name != nullptr && !env->ExceptionCheck()) {
                const char *chars = env->GetStringUTFChars(name, nullptr);
                if (chars != nullptr) {
                    chain.push_back(to_lower(std::string(chars)));
                    env->ReleaseStringUTFChars(name, chars);
                }
            }
            clear_exception(env);
            if (name != nullptr) env->DeleteLocalRef(name);
            env->DeleteLocalRef(loader_type);

            jobject parent = env->CallObjectMethod(loader, get_parent);
            clear_exception(env);
            env->DeleteLocalRef(loader);
            loader = parent;
            ++depth;
        }
        if (loader != nullptr) env->DeleteLocalRef(loader);
    } else {
        clear_exception(env);
    }

    env->DeleteLocalRef(object_class);
    env->DeleteLocalRef(loader_class);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(anchor);

    if (chain.empty()) return;
    add_token(tokens, OBF("loader_depth:") + std::to_string(chain.size()));
    if (chain.size() > 3) {
        add_token(tokens, OBF("loader_chain_deep:") + std::to_string(chain.size()));
    }
    for (const auto &entry : chain) {
        if (entry.find(OBF("pathclassloader")) != std::string::npos
            || entry.find(OBF("bootclassloader")) != std::string::npos
            || entry.find(OBF("dexclassloader")) != std::string::npos
            || entry.find(OBF("inmemorydexclassloader")) != std::string::npos
            || entry.find(OBF("delegatelastclassloader")) != std::string::npos) {
            continue;
        }
        add_token(tokens, OBF("loader_unexpected:") + entry);
    }
}

void inspect_reflection_slots(JNIEnv *env, const std::vector<MapEntry> &maps,
                              std::vector<std::string> &tokens) {
    uintptr_t art_start = 0, art_end = 0;
    const std::string libart = OBF("libart.so");
    for (const auto &entry : maps) {
        if (!is_rx(entry)) continue;
        if (entry.path.find(libart) == std::string::npos) continue;
        if (art_start == 0 || entry.start < art_start) art_start = entry.start;
        if (entry.end > art_end) art_end = entry.end;
    }
    if (art_start == 0) return;

    struct Slot {
        std::string name;
        const void *pointer;
    };
    const Slot slots[] = {
            {OBF("GetMethodID"), reinterpret_cast<const void *>(env->functions->GetMethodID)},
            {OBF("GetStaticMethodID"), reinterpret_cast<const void *>(env->functions->GetStaticMethodID)},
            {OBF("ToReflectedMethod"), reinterpret_cast<const void *>(env->functions->ToReflectedMethod)},
            {OBF("CallIntMethod"), reinterpret_cast<const void *>(env->functions->CallIntMethod)},
            {OBF("RegisterNatives"), reinterpret_cast<const void *>(env->functions->RegisterNatives)},
            {OBF("GetStringUTFChars"), reinterpret_cast<const void *>(env->functions->GetStringUTFChars)},
    };
    for (const auto &slot : slots) {
        auto addr = reinterpret_cast<uintptr_t>(slot.pointer);
        if (addr != 0 && (addr < art_start || addr >= art_end)) {
            add_token(tokens, OBF("jni_slot_hook:") + slot.name);
        }
    }
}

}  // namespace

std::string native_get_art_hook_evidence(JNIEnv *env, const std::vector<MapEntry> &maps) {
    std::vector<std::string> tokens;
    if (env == nullptr) return join_tokens(tokens);

    inspect_reflection_slots(env, maps, tokens);
    inspect_class_loader_chain(env, tokens);

    // Non-native methods that must never flip to ACC_NATIVE at runtime.
    // Includes both platform APIs and public/kept SDK entry points.
    struct Probe {
        std::string cls;
        std::string method;
        std::string signature;
        bool is_static;
    };
    const std::string bridge_cls =
            OBF("com/wsttxm/riskenginesdk/collector/native_layer/NativeCollectorBridge");
    const std::string engine_cls = OBF("com/wsttxm/riskenginesdk/RiskEngine");
    const Probe probes[] = {
            {OBF("java/lang/Runtime"), OBF("exec"),
             OBF("(Ljava/lang/String;)Ljava/lang/Process;"), false},
            {OBF("java/io/File"), OBF("exists"), OBF("()Z"), false},
            {bridge_cls, OBF("isNativeAvailable"), OBF("()Z"), true},
            {engine_cls, OBF("collectSync"),
             OBF("()Lcom/wsttxm/riskenginesdk/model/RiskReport;"), true},
    };
    for (const auto &probe : probes) {
        bool found = false;
        if (method_is_native(env, probe.cls, probe.method, probe.signature,
                             probe.is_static, found) && found) {
            add_token(tokens, OBF("art_native_flag:") + probe.method);
        }
    }

    // Native bridge methods that must remain ACC_NATIVE at runtime.
    // Java-layer hooks (e.g. Frida Java.use().implementation) that replace a
    // native method with a managed proxy clear ACC_NATIVE on the ArtMethod.
    const Probe native_probes[] = {
            {bridge_cls, OBF("nativeGetHookEvidenceRaw"), OBF("()Ljava/lang/String;"), true},
            {bridge_cls, OBF("nativeGetRootEvidenceRaw"), OBF("()Ljava/lang/String;"), true},
            {bridge_cls, OBF("nativeGetTracerPidRaw"), OBF("()I"), true},
            {bridge_cls, OBF("nativeCheckEmulatorFilesRaw"), OBF("()Ljava/lang/String;"), true},
    };
    for (const auto &probe : native_probes) {
        bool found = false;
        bool is_native = method_is_native(env, probe.cls, probe.method, probe.signature,
                                          probe.is_static, found);
        if (found && !is_native) {
            add_token(tokens, OBF("art_native_cleared:") + probe.method);
        }
    }

    return join_tokens(tokens);
}

std::string native_get_art_hook_evidence(JNIEnv *env) {
    auto maps = read_self_maps();
    return native_get_art_hook_evidence(env, maps);
}
