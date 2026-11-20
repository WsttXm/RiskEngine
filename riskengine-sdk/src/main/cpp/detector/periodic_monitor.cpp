#include "periodic_monitor.h"

#include "native_hook_detector.h"
#include "native_integrity.h"
#include "native_debug_detector.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <dlfcn.h>
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

void run_pass() {
    if (!g_running.load(std::memory_order_acquire)) return;

    // Share one /proc/self/maps read across all checks in this pass.
    auto maps = read_self_maps();
    if (!g_running.load(std::memory_order_acquire)) return;

    const std::string self = native_get_so_integrity_evidence(maps);
    if (has_csv_token(self, OBF("text_mismatch"))
        || has_csv_token(self, OBF("text_mismatch:anonymous_map"))) {
        latch(OBF("late_text_mismatch"));
    }

    if (!g_running.load(std::memory_order_acquire)) return;
    if (get_tracer_pid() > 0) {
        latch(OBF("late_tracer_attached"));
    }

    if (!g_running.load(std::memory_order_acquire)) return;

    const MapEntry *self_code = find_map_containing(
            maps, reinterpret_cast<uintptr_t>(&run_pass));
    for (const auto &entry : maps) {
        if (entry.perms.size() >= 3 && entry.perms[1] == 'w' && entry.perms[2] == 'x') {
            if (self_code != nullptr && entry.start == self_code->start) {
                latch(OBF("late_wx_self"));
            } else {
                std::string lower_path = entry.path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(),
                               [](unsigned char c) { return static_cast<char>(::tolower(c)); });
                if (lower_path.find(OBF("libriskengine.so")) != std::string::npos) {
                    latch(OBF("late_wx_self"));
                } else if (lower_path.find(OBF("libart.so")) != std::string::npos) {
                    latch(OBF("late_wx_art"));
                }
            }
        }

        std::string lower_raw = entry.raw;
        std::transform(lower_raw.begin(), lower_raw.end(), lower_raw.begin(),
                       [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (lower_raw.find(OBF("frida")) != std::string::npos
            || lower_raw.find(OBF("libgadget")) != std::string::npos) {
            latch(OBF("late_module:frida"));
        }
        if (lower_raw.find(OBF("lsposed")) != std::string::npos
            || lower_raw.find(OBF("lspd")) != std::string::npos) {
            latch(OBF("late_module:lsposed"));
        }
    }

    if (!native_scan_memfd_private_elfs(maps).empty()) {
        latch(OBF("late_memfd_elf"));
    }

    g_passes.fetch_add(1, std::memory_order_relaxed);
}

void *monitor_main(void *) {
    while (g_running.load(std::memory_order_acquire)) {
        if (!jittered_wait(20)) break;
        run_pass();
    }
    return nullptr;
}

}  // namespace

void native_monitor_start(JavaVM *) {
    std::lock_guard<std::mutex> lifecycle_lock(g_lifecycle_mutex);
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) {
        return;
    }
    {
        std::lock_guard<std::mutex> findings_lock(g_findings_mutex);
        g_findings.clear();
        g_passes.store(0, std::memory_order_relaxed);
    }
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
