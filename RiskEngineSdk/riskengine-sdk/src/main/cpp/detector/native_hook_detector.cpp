#include "native_hook_detector.h"
#include "../util/syscall_wrapper.h"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    std::string perms;
    std::string path;
    std::string raw;
};

struct ExecPointerCandidate {
    size_t offset = 0;
    uintptr_t address = 0;
    MapEntry region;
};

volatile sig_atomic_t g_sigtrap_seen = 0;

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool contains_any(const std::string &haystack, const std::vector<std::string> &needles) {
    for (const auto &needle : needles) {
        if (haystack.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void add_evidence(std::vector<std::string> &evidence, const std::string &value) {
    if (!value.empty()) {
        evidence.push_back(value);
    }
}

std::vector<MapEntry> read_maps() {
    std::vector<MapEntry> entries;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        MapEntry entry;
        entry.raw = line;

        std::istringstream iss(line);
        std::string range;
        std::string offset;
        std::string dev;
        std::string inode;
        if (!(iss >> range >> entry.perms >> offset >> dev >> inode)) {
            continue;
        }

        auto dash = range.find('-');
        if (dash == std::string::npos) {
            continue;
        }

        entry.start = static_cast<uintptr_t>(std::strtoull(range.substr(0, dash).c_str(), nullptr, 16));
        entry.end = static_cast<uintptr_t>(std::strtoull(range.substr(dash + 1).c_str(), nullptr, 16));

        std::string path;
        std::getline(iss, path);
        if (!path.empty() && path[0] == ' ') {
            path.erase(0, 1);
        }
        entry.path = path;
        entries.push_back(entry);
    }
    return entries;
}

bool is_arm64_ldr_literal(uint32_t instruction) {
    return (instruction & 0x3B000000u) == 0x18000000u;
}

bool is_arm64_br(uint32_t instruction) {
    return (instruction & 0xFFFFFC1Fu) == 0xD61F0000u;
}

size_t scan_trampoline_hits(const MapEntry &entry) {
#if defined(__aarch64__)
    if (entry.end <= entry.start || entry.perms.size() < 3 || entry.perms[0] != 'r' || entry.perms[2] != 'x') {
        return 0;
    }

    size_t length = static_cast<size_t>(std::min<uintptr_t>(entry.end - entry.start, 4096));
    if (length < sizeof(uint32_t) * 2) {
        return 0;
    }

    auto *cursor = reinterpret_cast<const uint32_t *>(entry.start);
    size_t count = length / sizeof(uint32_t);
    size_t hits = 0;
    for (size_t i = 0; i + 1 < count; ++i) {
        if (is_arm64_ldr_literal(cursor[i]) && is_arm64_br(cursor[i + 1])) {
            ++hits;
        }
    }
    return hits;
#else
    (void) entry;
    return 0;
#endif
}

bool is_suspicious_executable_region(const MapEntry &entry) {
    if (entry.end <= entry.start || entry.perms.size() < 3) {
        return false;
    }
    if (entry.perms[0] != 'r' || entry.perms[2] != 'x') {
        return false;
    }

    std::string lower = to_lower(entry.raw);
    if (contains_any(lower, {
            "dalvik-jit", "jit-cache", "zygote", "scudo", "linker_alloc",
            "memfd:jit", "vdex", "boot-framework", "[vectors]"
    })) {
        return false;
    }

    return entry.path.empty();
}

bool is_executable_region(const MapEntry &entry) {
    return entry.end > entry.start
           && entry.perms.size() >= 3
           && entry.perms[2] == 'x';
}

bool is_readable_region(const MapEntry &entry) {
    return entry.end > entry.start
           && !entry.perms.empty()
           && entry.perms[0] == 'r';
}

std::string summarize_region(const MapEntry &entry) {
    return entry.path.empty() ? "anonymous" : entry.path;
}

bool is_allowed_method_region(const MapEntry &entry) {
    std::string lower = to_lower(entry.raw);
    if (contains_any(lower, {
            "libart", "libartbase", "boot.oat", "/apex/", "/system/",
            "/system_ext/", "/product/", ".oat", ".odex", "memfd:jit",
            "jit-cache", "dalvik-jit", "/data/app/", ".apk"
    })) {
        return true;
    }
    return false;
}

bool is_suspicious_method_region(const MapEntry &entry) {
    std::string lower = to_lower(entry.raw);
    if (contains_any(lower, {"frida", "gadget", "xposed", "substrate"})) {
        return true;
    }
    return is_suspicious_executable_region(entry);
}

const MapEntry *find_region(const std::vector<MapEntry> &regions, uintptr_t address) {
    for (const auto &region : regions) {
        if (address >= region.start && address < region.end) {
            return &region;
        }
    }
    return nullptr;
}

void sigtrap_handler(int, siginfo_t *, void *) {
    g_sigtrap_seen = 1;
}

bool run_sigtrap_probe() {
    struct sigaction action{};
    struct sigaction old_action{};
    action.sa_sigaction = sigtrap_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGTRAP, &action, &old_action) != 0) {
        return true;
    }

    g_sigtrap_seen = 0;
    pid_t pid = getpid();
    pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
    syscall(__NR_tgkill, pid, tid, SIGTRAP);
    sigaction(SIGTRAP, &old_action, nullptr);
    return g_sigtrap_seen == 1;
}

void collect_hook_evidence(std::vector<std::string> &evidence) {
    auto maps = read_maps();
    for (const auto &entry : maps) {
        std::string lower = to_lower(entry.raw);
        if (contains_any(lower, {"frida", "libfrida", "gadget", "xposed", "substrate"})) {
            if (lower.find("frida") != std::string::npos || lower.find("libfrida") != std::string::npos) {
                add_evidence(evidence, "maps:frida");
            }
            if (lower.find("gadget") != std::string::npos) {
                add_evidence(evidence, "maps:gadget");
            }
            if (lower.find("xposed") != std::string::npos) {
                add_evidence(evidence, "maps:xposed");
            }
            if (lower.find("substrate") != std::string::npos) {
                add_evidence(evidence, "maps:substrate");
            }
        }

        if (is_suspicious_executable_region(entry)) {
            add_evidence(evidence, "anon_exec:" + entry.perms);
            size_t trampoline_hits = scan_trampoline_hits(entry);
            if (trampoline_hits > 0) {
                add_evidence(evidence, "trampoline:" + std::to_string(trampoline_hits));
            }
        }
    }

    DIR *task_dir = opendir("/proc/self/task");
    if (task_dir) {
        struct dirent *entry;
        char task_path[128];
        char comm_buf[64];
        while ((entry = readdir(task_dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            std::snprintf(task_path, sizeof(task_path), "/proc/self/task/%s/comm", entry->d_name);
            if (read_file_content(task_path, comm_buf, sizeof(comm_buf)) > 0) {
                std::string comm = to_lower(comm_buf);
                if (comm.find("gum-js-loop") != std::string::npos ||
                    comm.find("gmain") != std::string::npos ||
                    comm.find("frida") != std::string::npos) {
                    add_evidence(evidence, "thread:" + comm);
                }
            }
        }
        closedir(task_dir);
    }

    if (!run_sigtrap_probe()) {
        add_evidence(evidence, "sigtrap:handler_missed");
    }
}

}  // namespace

bool native_check_hooks() {
    std::vector<std::string> evidence;
    collect_hook_evidence(evidence);
    return !evidence.empty();
}

std::string native_get_hook_evidence() {
    std::vector<std::string> evidence;
    collect_hook_evidence(evidence);

    std::string joined;
    for (size_t i = 0; i < evidence.size(); ++i) {
        if (i > 0) {
            joined += ",";
        }
        joined += evidence[i];
    }
    return joined;
}

std::string native_inspect_method_entry_point(void *method_id) {
    if (method_id == nullptr) {
        return "unavailable:null_method_id";
    }

    auto regions = read_maps();
    uintptr_t art_method = reinterpret_cast<uintptr_t>(method_id);
    const MapEntry *art_method_region = find_region(regions, art_method);
    if (art_method_region == nullptr || !is_readable_region(*art_method_region)) {
        return "unavailable:opaque_art_method";
    }

    std::vector<ExecPointerCandidate> candidates;

    constexpr size_t kProbeBytes = 64;
    constexpr size_t kWordSize = sizeof(uintptr_t);
    size_t readable_bytes = static_cast<size_t>(art_method_region->end - art_method);
    size_t probe_bytes = std::min(kProbeBytes, readable_bytes);
    for (size_t offset = 0; offset + kWordSize <= probe_bytes; offset += kWordSize) {
        auto *slot = reinterpret_cast<const uintptr_t *>(art_method + offset);
        uintptr_t candidate_address = *slot;
        if (candidate_address < 4096) {
            continue;
        }
        const MapEntry *region = find_region(regions, candidate_address);
        if (region == nullptr || !is_executable_region(*region)) {
            continue;
        }

        bool duplicate = false;
        for (const auto &existing : candidates) {
            if (existing.address == candidate_address) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            candidates.push_back(ExecPointerCandidate{offset, candidate_address, *region});
        }
    }

    if (candidates.empty()) {
        return "unavailable:no_exec_pointer";
    }

    auto chosen = std::max_element(candidates.begin(), candidates.end(),
                                   [](const ExecPointerCandidate &lhs, const ExecPointerCandidate &rhs) {
                                       return lhs.offset < rhs.offset;
                                   });

    std::ostringstream summary;
    summary << summarize_region(chosen->region) << "@0x" << std::hex << chosen->address
            << std::dec << "#offset=" << chosen->offset;

    if (is_suspicious_method_region(chosen->region) || !is_allowed_method_region(chosen->region)) {
        return "suspicious:" + summary.str();
    }
    return "ok:" + summary.str();
}
