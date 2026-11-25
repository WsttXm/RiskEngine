#include "periodic_monitor.h"

#include "native_debug_detector.h"
#include "native_hook_detector.h"
#include "native_integrity.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <string>
#include <vector>

namespace {

constexpr int64_t kForegroundResumeRecheckMs = 10'000;
constexpr unsigned kInitialMinSeconds = 2;
constexpr unsigned kInitialJitterMod = 3;      // 2..4s initial pass
constexpr unsigned kForegroundMinSeconds = 20;
constexpr unsigned kForegroundJitterMod = 7;   // 20..26s foreground jitter
constexpr unsigned kBackgroundBackoffSeconds = 120;

std::atomic<bool> g_running{false};
std::atomic<uintptr_t> g_monitor_generation{0};
std::atomic<int> g_passes{0};

pthread_t g_thread{};
bool g_thread_started = false;
std::mutex g_lifecycle_mutex;

std::mutex g_sleep_mutex;
std::condition_variable g_sleep_condition;
bool g_background = false;
bool g_immediate_recheck = false;
uint64_t g_state_version = 0;
int64_t g_last_pass_mono_ms = 0;

std::mutex g_findings_mutex;
std::vector<std::string> g_findings;

// Cached in JNI_OnLoad before monitor start; cleared in JNI_OnUnload after pthread_join.
JavaVM *g_vm = nullptr;
jclass g_dispatcher_class = nullptr;
jmethodID g_dispatcher_method = nullptr;

int64_t now_mono_ms() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

bool is_active_generation(uintptr_t my_gen) {
    return g_running.load(std::memory_order_acquire)
            && g_monitor_generation.load(std::memory_order_acquire) == my_gen;
}

unsigned random_jitter(unsigned mod) {
    if (mod <= 1) return 0;
    unsigned jitter = 0;
    const auto urandom = OBF("/dev/urandom");
    int fd = static_cast<int>(my_openat(AT_FDCWD, urandom.c_str(),
                                        O_RDONLY | O_CLOEXEC, 0));
    if (fd >= 0) {
        unsigned char byte = 0;
        if (my_read(fd, &byte, 1) == 1) {
            jitter = static_cast<unsigned>(byte) % mod;
        }
        my_close(fd);
    }
    return jitter;
}

bool latch_token(uintptr_t my_gen,
                 const std::string &token,
                 std::vector<std::string> &newly_latched) {
    if (token.empty() || !is_active_generation(my_gen)) return false;
    bool inserted = false;
    {
        std::lock_guard<std::mutex> lock(g_findings_mutex);
        if (!is_active_generation(my_gen)) return false;
        if (std::find(g_findings.begin(), g_findings.end(), token) == g_findings.end()) {
            g_findings.push_back(token);
            inserted = true;
        }
    }
    if (inserted) {
        newly_latched.push_back(token);
    }
    return inserted;
}

void scan_proc_self_fd(uintptr_t my_gen, std::vector<std::string> &newly_latched) {
    const auto fd_dir = OBF("/proc/self/fd");
    RawDirResult entries = raw_list_dir(fd_dir.c_str());
    if (!entries.ok()) return;

    const auto fd_prefix = OBF("/proc/self/fd/");
    const auto kw_linjector = OBF("linjector");
    const auto kw_frida = OBF("frida");
    const auto kw_gum = OBF("gum-js-loop");
    const auto tok_frida_fd = OBF("late_frida_fd");

    for (const auto &name : entries.names) {
        if (!is_active_generation(my_gen)) return;
        if (name.empty()) continue;
        bool numeric = true;
        for (char c : name) {
            if (c < '0' || c > '9') {
                numeric = false;
                break;
            }
        }
        if (!numeric) continue;

        std::string fd_path = std::string(fd_prefix.c_str()) + name;
        char target[512] = {};
        long len = my_readlinkat(AT_FDCWD, fd_path.c_str(), target, sizeof(target) - 1);
        if (len <= 0) continue;
        target[len] = '\0';

        std::string lower(target, static_cast<size_t>(len));
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower.find(kw_linjector.c_str()) != std::string::npos
                || lower.find(kw_frida.c_str()) != std::string::npos
                || lower.find(kw_gum.c_str()) != std::string::npos) {
            latch_token(my_gen, tok_frida_fd.c_str(), newly_latched);
            return;
        }
    }
}

void push_findings_to_java(uintptr_t my_gen, const std::vector<std::string> &tokens) {
    if (tokens.empty() || !is_active_generation(my_gen)) return;
    JavaVM *vm = g_vm;
    jclass cls = g_dispatcher_class;
    jmethodID method = g_dispatcher_method;
    if (vm == nullptr || cls == nullptr || method == nullptr) {
        return;
    }

    JNIEnv *env = nullptr;
    bool attached = false;
    jint env_status = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (env_status == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || env == nullptr) {
            return;
        }
        attached = true;
    } else if (env_status != JNI_OK || env == nullptr) {
        return;
    }

    const auto src_detail = OBF("periodic_monitor");
    for (const auto &token : tokens) {
        if (!is_active_generation(my_gen)) break;
        jstring j_token = env->NewStringUTF(token.c_str());
        if (j_token == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            continue;
        }
        jstring j_detail = env->NewStringUTF(src_detail.c_str());
        if (j_detail == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(j_token);
            continue;
        }

        // Upcall executes with zero native mutexes held; never invokes FindClass.
        env->CallStaticVoidMethod(cls, method, j_token, j_detail);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(j_detail);
        env->DeleteLocalRef(j_token);
    }

    if (attached) {
        vm->DetachCurrentThread();
    }
}

bool wait_next_interval(bool initial_pass, uintptr_t my_gen) {
    std::unique_lock<std::mutex> lock(g_sleep_mutex);
    while (true) {
        if (!is_active_generation(my_gen)) {
            return false;
        }
        if (g_immediate_recheck) {
            g_immediate_recheck = false;
            return true;
        }

        unsigned wait_seconds;
        if (g_background) {
            wait_seconds = kBackgroundBackoffSeconds;
        } else if (initial_pass) {
            wait_seconds = kInitialMinSeconds + random_jitter(kInitialJitterMod);
        } else {
            wait_seconds = kForegroundMinSeconds + random_jitter(kForegroundJitterMod);
        }

        const uint64_t observed_version = g_state_version;
        const bool woke_for_signal = g_sleep_condition.wait_for(
                lock,
                std::chrono::seconds(wait_seconds),
                [my_gen, observed_version] {
                    return !is_active_generation(my_gen)
                            || g_immediate_recheck
                            || g_state_version != observed_version;
                });

        if (!is_active_generation(my_gen)) {
            return false;
        }
        if (g_immediate_recheck) {
            g_immediate_recheck = false;
            return true;
        }
        if (!woke_for_signal) {
            // Normal timer expiration.
            return true;
        }
        // State version changed (e.g. foreground <-> background): recalculate wait interval.
    }
}

void run_pass(uintptr_t my_gen) {
    if (!is_active_generation(my_gen)) return;

    std::vector<std::string> newly_latched;

    // 1. Share one /proc/self/maps read across maps, memfd, and .text checks.
    auto maps = read_self_maps();
    if (!is_active_generation(my_gen)) return;

    // 2. Dual-path & per-thread TracerPid check.
    if (get_tracer_pid() > 0) {
        latch_token(my_gen, OBF("late_tracer_attached").c_str(), newly_latched);
    }
    if (!is_active_generation(my_gen)) return;

    // 3. W+X segments and late-loaded Frida/LSPosed libraries.
    const MapEntry *self_code = find_map_containing(
            maps, reinterpret_cast<uintptr_t>(&run_pass));
    const auto self_so = OBF("libriskengine.so");
    const auto art_so = OBF("libart.so");
    const auto kw_frida = OBF("frida");
    const auto kw_gadget = OBF("libgadget");
    const auto kw_lsposed = OBF("lsposed");
    const auto kw_lspd = OBF("lspd");
    const auto tok_wx_self = OBF("late_wx_self");
    const auto tok_wx_art = OBF("late_wx_art");
    const auto tok_mod_frida = OBF("late_module:frida");
    const auto tok_mod_lsposed = OBF("late_module:lsposed");

    for (const auto &entry : maps) {
        if (entry.perms.size() >= 3 && entry.perms[1] == 'w' && entry.perms[2] == 'x') {
            if (self_code != nullptr && entry.start == self_code->start) {
                latch_token(my_gen, tok_wx_self.c_str(), newly_latched);
            } else {
                std::string lower_path = entry.path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (lower_path.find(self_so.c_str()) != std::string::npos) {
                    latch_token(my_gen, tok_wx_self.c_str(), newly_latched);
                } else if (lower_path.find(art_so.c_str()) != std::string::npos) {
                    latch_token(my_gen, tok_wx_art.c_str(), newly_latched);
                }
            }
        }

        std::string lower_raw = entry.raw;
        std::transform(lower_raw.begin(), lower_raw.end(), lower_raw.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower_raw.find(kw_frida.c_str()) != std::string::npos
            || lower_raw.find(kw_gadget.c_str()) != std::string::npos) {
            latch_token(my_gen, tok_mod_frida.c_str(), newly_latched);
        }
        if (lower_raw.find(kw_lsposed.c_str()) != std::string::npos
            || lower_raw.find(kw_lspd.c_str()) != std::string::npos) {
            latch_token(my_gen, tok_mod_lsposed.c_str(), newly_latched);
        }
    }
    if (!is_active_generation(my_gen)) return;

    // 4. memfd private ELF injection.
    if (!native_scan_memfd_private_elfs(maps).empty()) {
        latch_token(my_gen, OBF("late_memfd_elf").c_str(), newly_latched);
    }
    if (!is_active_generation(my_gen)) return;

    // 5. /proc/self/fd scan for late Frida/linjector file descriptors.
    scan_proc_self_fd(my_gen, newly_latched);
    if (!is_active_generation(my_gen)) return;

    // 6. COW-safe windowed .text & recorded prologue self-integrity recheck.
    const auto integrity_findings = native_collect_integrity_findings(nullptr, maps);
    if (!integrity_findings.empty()) {
        const auto code_text = OBF("text_mismatch");
        const auto code_jni = OBF("jni_self_hook");
        const auto code_fn = OBF("fn_prologue_hook");
        const auto tok_late_text = OBF("late_text_mismatch");
        for (const auto &finding : integrity_findings) {
            if (finding.code == code_text.c_str()) {
                latch_token(my_gen, tok_late_text.c_str(), newly_latched);
            } else if (finding.code == code_jni.c_str() || finding.code == code_fn.c_str()) {
                latch_token(my_gen, finding.token, newly_latched);
            }
        }
    }

    if (is_active_generation(my_gen)) {
        g_passes.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(g_sleep_mutex);
            g_last_pass_mono_ms = now_mono_ms();
        }
        // Push newly discovered threats to Java with zero mutexes held.
        push_findings_to_java(my_gen, newly_latched);
    }
}

void *monitor_main(void *arg) {
    const uintptr_t my_gen = reinterpret_cast<uintptr_t>(arg);
    bool initial_pass = true;
    while (is_active_generation(my_gen)) {
        if (!wait_next_interval(initial_pass, my_gen)) break;
        initial_pass = false;
        run_pass(my_gen);
    }
    return nullptr;
}

}  // namespace

void native_monitor_init_dispatcher(JNIEnv *env, JavaVM *vm) {
    std::lock_guard<std::mutex> lifecycle_lock(g_lifecycle_mutex);
    g_vm = vm;
    if (env == nullptr) return;

    if (g_dispatcher_class != nullptr) {
        env->DeleteGlobalRef(g_dispatcher_class);
        g_dispatcher_class = nullptr;
        g_dispatcher_method = nullptr;
    }

    const auto cls_name = OBF(
            "com/wsttxm/riskenginesdk/collector/native_layer/NativeMonitorDispatcher");
    jclass local_cls = env->FindClass(cls_name.c_str());
    if (local_cls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return;
    }

    const auto method_name = OBF("onNativeThreatDetected");
    const auto method_sig = OBF("(Ljava/lang/String;Ljava/lang/String;)V");
    jmethodID mid = env->GetStaticMethodID(local_cls, method_name.c_str(), method_sig.c_str());
    if (mid == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(local_cls);
        return;
    }

    jclass global_cls = static_cast<jclass>(env->NewGlobalRef(local_cls));
    env->DeleteLocalRef(local_cls);
    if (global_cls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return;
    }

    g_dispatcher_class = global_cls;
    g_dispatcher_method = mid;
}

void native_monitor_cleanup_dispatcher(JNIEnv *env) {
    std::lock_guard<std::mutex> lifecycle_lock(g_lifecycle_mutex);
    if (env != nullptr && g_dispatcher_class != nullptr) {
        env->DeleteGlobalRef(g_dispatcher_class);
    }
    g_dispatcher_class = nullptr;
    g_dispatcher_method = nullptr;
    g_vm = nullptr;
}

void native_monitor_start(JavaVM *vm) {
    std::lock_guard<std::mutex> lifecycle_lock(g_lifecycle_mutex);
    if (vm != nullptr && g_vm == nullptr) {
        g_vm = vm;
    }
    if (g_running.load(std::memory_order_acquire) && g_thread_started) {
        return;
    }
    uintptr_t next_gen = g_monitor_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (next_gen == 0) {
        next_gen = g_monitor_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    }
    {
        std::lock_guard<std::mutex> findings_lock(g_findings_mutex);
        g_findings.clear();
        g_passes.store(0, std::memory_order_relaxed);
    }
    {
        std::lock_guard<std::mutex> sleep_lock(g_sleep_mutex);
        g_immediate_recheck = false;
        g_last_pass_mono_ms = 0;
        g_state_version++;
    }
    g_running.store(true, std::memory_order_release);
    if (pthread_create(&g_thread, nullptr, monitor_main,
                       reinterpret_cast<void *>(next_gen)) != 0) {
        g_running.store(false, std::memory_order_release);
        return;
    }
    g_thread_started = true;
}

void native_monitor_stop() {
    pthread_t thread_to_join{};
    bool should_join = false;
    {
        std::lock_guard<std::mutex> lifecycle_lock(g_lifecycle_mutex);
        g_monitor_generation.fetch_add(1, std::memory_order_acq_rel);
        g_running.store(false, std::memory_order_release);
        if (g_thread_started) {
            thread_to_join = g_thread;
            g_thread_started = false;
            should_join = true;
        }
    }
    {
        // Synchronize with wait_next_interval's predicate check to prevent lost wakeups.
        std::lock_guard<std::mutex> sleep_lock(g_sleep_mutex);
        g_immediate_recheck = false;
        g_state_version++;
    }
    g_sleep_condition.notify_all();
    // Join outside g_lifecycle_mutex so a slow monitor pass cannot stall
    // concurrent lifecycle operations or reinitialization (D05 deadlock freedom).
    if (should_join) {
        pthread_join(thread_to_join, nullptr);
    }
}

void native_monitor_set_background(bool is_background) {
    bool should_notify = false;
    {
        std::lock_guard<std::mutex> sleep_lock(g_sleep_mutex);
        const bool was_background = g_background;
        g_background = is_background;
        if (was_background && !is_background) {
            const int64_t elapsed = now_mono_ms() - g_last_pass_mono_ms;
            if (g_last_pass_mono_ms > 0 && elapsed > kForegroundResumeRecheckMs) {
                g_immediate_recheck = true;
            }
        }
        if (was_background != is_background || g_immediate_recheck) {
            g_state_version++;
            should_notify = true;
        }
    }
    if (should_notify) {
        g_sleep_condition.notify_all();
    }
}

std::string native_monitor_findings() {
    std::lock_guard<std::mutex> lock(g_findings_mutex);
    std::string joined = std::string(OBF("passes:").c_str()) + std::to_string(
            g_passes.load(std::memory_order_relaxed));
    for (const auto &token : g_findings) {
        joined += ",";
        joined += token;
    }
    return joined;
}
