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

/**
 * Reads a method's Java modifiers via public reflection.
 *
 * Deliberately not by reading ArtMethod struct offsets: those shift between
 * Android releases and a stale offset reads unrelated memory. Modifiers are
 * stable API and still expose the flag flip, because a method not declared
 * native cannot legitimately become native at runtime.
 */
bool method_is_native(JNIEnv *env, const char *class_name,
                      const char *method_name, const char *signature,
                      bool is_static, bool &found) {
    found = false;
    jclass target = env->FindClass(class_name);
    if (target == nullptr) {
        clear_exception(env);
        return false;
    }
    jmethodID method = is_static
            ? env->GetStaticMethodID(target, method_name, signature)
            : env->GetMethodID(target, method_name, signature);
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
                env->GetMethodID(method_class, OBF("getModifiers").c_str(), "()I");
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

/**
 * Walks the ClassLoader parent chain of this library's own bridge class.
 *
 * A stock app chain is short and well known. Xposed-family frameworks insert a
 * loader so their module dex resolves, and cloning containers insert their own.
 * Both appear as extra links or an unexpected implementation class.
 */
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
            || entry.find(OBF("delegatelastclassloader")) != std::string::npos) {
            continue;
        }
        add_token(tokens, OBF("loader_unexpected:") + entry);
    }
}

/**
 * Confirms the JNIEnv slots this module itself relies on still point into
 * libart. If they are redirected, the reflection results above cannot be
 * trusted, and that fact belongs in the report rather than being assumed away.
 */
void inspect_reflection_slots(JNIEnv *env, std::vector<std::string> &tokens) {
    auto maps = read_self_maps();
    uintptr_t art_start = 0, art_end = 0;
    for (const auto &entry : maps) {
        if (!is_rx(entry)) continue;
        if (entry.path.find(OBF("libart.so")) == std::string::npos) continue;
        if (art_start == 0 || entry.start < art_start) art_start = entry.start;
        if (entry.end > art_end) art_end = entry.end;
    }
    if (art_start == 0) return;

    struct Slot {
        const char *name;
        const void *pointer;
    };
    const Slot slots[] = {
            {"GetMethodID", reinterpret_cast<const void *>(env->functions->GetMethodID)},
            {"GetStaticMethodID", reinterpret_cast<const void *>(env->functions->GetStaticMethodID)},
            {"ToReflectedMethod", reinterpret_cast<const void *>(env->functions->ToReflectedMethod)},
            {"CallIntMethod", reinterpret_cast<const void *>(env->functions->CallIntMethod)},
            {"RegisterNatives", reinterpret_cast<const void *>(env->functions->RegisterNatives)},
            {"GetStringUTFChars", reinterpret_cast<const void *>(env->functions->GetStringUTFChars)},
    };
    for (const auto &slot : slots) {
        auto addr = reinterpret_cast<uintptr_t>(slot.pointer);
        if (addr != 0 && (addr < art_start || addr >= art_end)) {
            add_token(tokens, OBF("jni_slot_hook:") + slot.name);
        }
    }
}

}  // namespace

std::string native_get_art_hook_evidence(JNIEnv *env) {
    std::vector<std::string> tokens;
    if (env == nullptr) return join_tokens(tokens);

    inspect_reflection_slots(env, tokens);
    inspect_class_loader_chain(env, tokens);

    // Methods that must not be native on a clean device. Checked by mechanism,
    // so a renamed framework is still caught.
    struct Probe {
        const char *cls;
        const char *method;
        const char *signature;
        bool is_static;
    };
    const Probe probes[] = {
            {"java/lang/reflect/Method", "invoke",
             "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false},
            {"java/lang/Runtime", "exec",
             "(Ljava/lang/String;)Ljava/lang/Process;", false},
            {"java/io/File", "exists", "()Z", false},
            {"com/wsttxm/riskenginesdk/collector/native_layer/NativeCollectorBridge",
             "isNativeAvailable", "()Z", true},
    };
    for (const auto &probe : probes) {
        bool found = false;
        if (method_is_native(env, probe.cls, probe.method, probe.signature,
                             probe.is_static, found) && found) {
            add_token(tokens, OBF("art_native_flag:") + probe.method);
        }
    }

    return join_tokens(tokens);
}
