#include "periodic_monitor.h"

#include "native_integrity.h"
#include "native_debug_detector.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <string>
#include <time.h>
#include <vector>

namespace {

std::atomic<bool> g_running{false};
std::atomic<int> g_passes{0};
pthread_t g_thread;
bool g_thread_started = false;
std::mutex g_lifecycle_mutex;
std::mutex g_sleep_mutex;
std::condition_variable g_sleep_condition;
std::mutex g_findings_mutex;
std::vector<std::string> g_findings;
JavaVM *g_vm = nullptr;

bool has_csv_token(const std::string &value, const std::string &wanted) {
    size_t start = 0;
    while (start <= value.size()) {
        size_t comma = value.find(',', start);
        if (comma == std::string::npos) comma = value.size();
        if (value.compare(start, comma - start, wanted) == 0) return true;
        if (comma == value.size()) break;
        start = comma + 1;
    }
    return false;
}

void latch(const std::string &token) {
    if (token.empty()) return;
    std::lock_guard<std::mutex> lock(g_findings_mutex);
    if (std::find(g_findings.begin(), g_findings.end(), token) == g_findings.end()) {
        g_findings.push_back(token);
    }
}

/** Waits with jitter, but wakes immediately when shutdown is requested. */
bool jittered_wait(unsigned base_seconds) {
    unsigned jitter = 0;
    int fd = static_cast<int>(my_openat(AT_FDCWD, OBF("/dev/urandom").c_str(),
                                        O_RDONLY | O_CLOEXEC, 0));
    if (fd >= 0) {
        unsigned char byte = 0;
        if (my_read(fd, &byte, 1) == 1) {
            jitter = byte % 7;
        }
        my_close(fd);
    }
    std::unique_lock<std::mutex> lock(g_sleep_mutex);
    g_sleep_condition.wait_for(
            lock,
            std::chrono::seconds(base_seconds + jitter),
            [] { return !g_running.load(std::memory_order_acquire); });
    return g_running.load(std::memory_order_acquire);
}

/**
 * One pass of the cheap checks.
 *
 * Each of these detects a change to running code or an attached tracer, which
 * is precisely the class of attack that arrives after the initial snapshot.
 */
void run_pass() {
    // Text-segment divergence: catches a hook written into our own code after
    // the first collection completed.
    const std::string self = native_get_so_integrity_evidence();
    // Availability tokens such as text_mismatch:apk_embedded are coverage
    // failures, not proof that executable bytes changed.
    if (has_csv_token(self, OBF("text_mismatch"))) {
        latch(OBF("late_text_mismatch"));
    }

    // A tracer that attached after startup.
    if (get_tracer_pid() > 0) {
        latch(OBF("late_tracer_attached"));
    }

    // A writable+executable mapping of our own code, or of libart/libc, that
    // was not present at load time.
    for (const auto &entry : read_self_maps()) {
        if (entry.perms.size() < 3) continue;
        if (entry.perms[1] != 'w' || entry.perms[2] != 'x') continue;
        std::string lower = entry.path;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (lower.find(OBF("libriskengine.so")) != std::string::npos) {
            latch(OBF("late_wx_self"));
        } else if (lower.find(OBF("libart.so")) != std::string::npos) {
            latch(OBF("late_wx_art"));
        }
    }

    // A framework module mapped in after startup.
    for (const auto &entry : read_self_maps()) {
        std::string lower = entry.raw;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (lower.find(OBF("frida")) != std::string::npos
            || lower.find(OBF("libgadget")) != std::string::npos) {
            latch(OBF("late_module:frida"));
            break;
        }
        if (lower.find(OBF("lsposed")) != std::string::npos
            || lower.find(OBF("lspd")) != std::string::npos) {
            latch(OBF("late_module:lsposed"));
            break;
        }
    }

    g_passes.fetch_add(1, std::memory_order_relaxed);
}

void *monitor_main(void *) {
    // First pass is delayed: at startup the values are the same ones the
    // initial collection already reported, so an immediate pass adds nothing.
    while (g_running.load(std::memory_order_acquire)) {
        if (!jittered_wait(20)) break;
        run_pass();
    }
    return nullptr;
}

}  // namespace

void native_monitor_start(JavaVM *vm) {
    std::lock_guard<std::mutex> lifecycle_lock(g_lifecycle_mutex);
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) {
        return;  // Already running.
    }
    {
        std::lock_guard<std::mutex> findings_lock(g_findings_mutex);
        g_findings.clear();
        g_passes.store(0, std::memory_order_relaxed);
    }
    g_vm = vm;
    if (pthread_create(&g_thread, nullptr, monitor_main, nullptr) != 0) {
        g_running.store(false, std::memory_order_release);
        return;
    }
    g_thread_started = true;
}

void native_monitor_stop() {
    std::lock_guard<std::mutex> lifecycle_lock(g_lifecycle_mutex);
    g_running.store(false, std::memory_order_release);
    g_sleep_condition.notify_all();
    if (g_thread_started) {
        pthread_join(g_thread, nullptr);
        g_thread_started = false;
    }
}

std::string native_monitor_findings() {
    std::lock_guard<std::mutex> lock(g_findings_mutex);
    std::string joined = OBF("passes:") + std::to_string(
            g_passes.load(std::memory_order_relaxed));
    for (const auto &token : g_findings) {
        joined += ",";
        joined += token;
    }
    return joined;
}
