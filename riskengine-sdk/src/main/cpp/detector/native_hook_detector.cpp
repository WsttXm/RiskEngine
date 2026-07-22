#include "native_hook_detector.h"
#include "../util/syscall_wrapper.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
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
    if (!value.empty()
        && std::find(evidence.begin(), evidence.end(), value) == evidence.end()) {
        evidence.push_back(value);
    }
}

std::vector<MapEntry> read_maps() {
    std::vector<MapEntry> entries;
    constexpr size_t kMaxMapsBytes = 2 * 1024 * 1024;
    long fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        return entries;
    }
    std::string maps_content;
    maps_content.reserve(64 * 1024);
    char buffer[8192];
    while (maps_content.size() < kMaxMapsBytes) {
        size_t remaining = kMaxMapsBytes - maps_content.size();
        long count = my_read(static_cast<int>(fd), buffer,
                             std::min(sizeof(buffer), remaining));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        maps_content.append(buffer, static_cast<size_t>(count));
    }
    my_close(static_cast<int>(fd));

    std::istringstream maps(maps_content);
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

void collect_hook_evidence(std::vector<std::string> &evidence) {
    auto maps = read_maps();
    for (const auto &entry : maps) {
        std::string lower = to_lower(entry.raw);
        if (contains_any(lower, {"frida", "libfrida", "frida-gadget", "libgadget.so",
                                 "xposed", "substrate"})) {
            if (lower.find("frida") != std::string::npos || lower.find("libfrida") != std::string::npos) {
                add_evidence(evidence, "maps:frida");
            }
            if (lower.find("frida-gadget") != std::string::npos
                || lower.find("libgadget.so") != std::string::npos) {
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
                if (comm.find("gum-js-loop") != std::string::npos) {
                    add_evidence(evidence, "thread:gum-js-loop");
                } else if (comm.find("frida") != std::string::npos) {
                    add_evidence(evidence, "thread:frida");
                } else if (comm.find("gmain") != std::string::npos) {
                    add_evidence(evidence, "thread:gmain");
                }
            }
        }
        closedir(task_dir);
    }

}

}  // namespace

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
