#include "periodic_monitor.h"

#include "native_integrity.h"
#include "native_debug_detector.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <atomic>
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
std::mutex g_findings_mutex;
std::vector<std::string> g_findings;
JavaVM *g_vm = nullptr;

void latch(const std::string &token) {
    if (token.empty()) return;
    std::lock_guard<std::mutex> lock(g_findings_mutex);
    if (std::find(g_findings.begin(), g_findings.end(), token) == g_findings.end()) {
        g_findings.push_back(token);
    }
}

/** Sleeps with jitter so the cadence is not a stable timing signal. */
void jittered_sleep(unsigned base_seconds) {
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
    struct timespec ts = {};
    ts.tv_sec = static_cast<time_t>(base_seconds + jitter);
    ts.tv_nsec = 0;
    nanosleep(&ts, nullptr);
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
    if (self.find(OBF("text_mismatch")) != std::string::npos) {
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
        jittered_sleep(20);
        if (!g_running.load(std::memory_order_acquire)) break;
        run_pass();
    }
    return nullptr;
}

}  // namespace

void native_monitor_start(JavaVM *vm) {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) {
        return;  // Already running.
    }
    g_vm = vm;
    if (pthread_create(&g_thread, nullptr, monitor_main, nullptr) != 0) {
        g_running.store(false, std::memory_order_release);
        return;
    }
    pthread_detach(g_thread);
}

void native_monitor_stop() {
    g_running.store(false, std::memory_order_release);
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
