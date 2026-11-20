#include "native_hook_detector.h"
#include "art_hook_detector.h"
#include "native_integrity.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cctype>
#include <dlfcn.h>
#include <fcntl.h>
#include <map>
#include <string>
#include <vector>

namespace {

void add_evidence(std::vector<std::string> &evidence, const std::string &value) {
    if (!value.empty()
        && std::find(evidence.begin(), evidence.end(), value) == evidence.end()) {
        evidence.push_back(value);
    }
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool contains_any(const std::string &haystack, const std::vector<std::string> &needles) {
    for (const auto &needle : needles) {
        if (haystack.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool is_suspicious_executable_region(const MapEntry &entry) {
    if (entry.end <= entry.start || entry.perms.size() < 3) return false;
    if (entry.perms[0] != 'r' || entry.perms[2] != 'x') return false;
    std::string lower = to_lower(entry.raw);
    if (contains_any(lower, {
            OBF("dalvik-jit"), OBF("jit-cache"), OBF("zygote"), OBF("scudo"),
            OBF("linker_alloc"), OBF("memfd:jit"), OBF("vdex"),
            OBF("boot-framework"), OBF("[vectors]")
    })) {
        return false;
    }
    return entry.path.empty();
}

void scan_unix_sockets(std::vector<std::string> &evidence) {
    std::string content = read_file_string(OBF("/proc/net/unix").c_str(), 512 * 1024);
    if (content.empty()) return;
    std::string lower = to_lower(content);
    if (lower.find(OBF("re.frida")) != std::string::npos
        || lower.find(OBF("frida:")) != std::string::npos
        || lower.find(OBF("frida-zymbiote")) != std::string::npos
        || lower.find(OBF("linjector")) != std::string::npos) {
        add_evidence(evidence, OBF("unix_socket:frida"));
    }
    if (lower.find(OBF("gum-js")) != std::string::npos) {
        add_evidence(evidence, OBF("unix_socket:gum"));
    }
}

std::string sanitize_memfd_label(const std::string &path) {
    const std::string prefix = OBF("/memfd:");
    std::string label = path.rfind(prefix, 0) == 0 ? path.substr(prefix.size()) : path;
    const std::string deleted_suffix = OBF(" (deleted)");
    auto del_pos = label.find(deleted_suffix);
    if (del_pos != std::string::npos) {
        label.erase(del_pos);
    }
    std::string clean;
    clean.reserve(std::min<size_t>(label.size(), 32));
    for (char c : label) {
        if (clean.size() >= 32) break;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            clean.push_back(c);
        }
    }
    return clean.empty() ? OBF("unknown") : clean;
}

bool read_elf_magic_safe(int mem_fd, uintptr_t addr) {
    if (mem_fd < 0 || addr == 0) return false;
    unsigned char magic[4] = {0};
    long n = my_pread64(mem_fd, magic, sizeof(magic), static_cast<uint64_t>(addr));
    return n == 4 && magic[0] == 0x7f && magic[1] == 'E'
           && magic[2] == 'L' && magic[3] == 'F';
}

void scan_self_wx_segments(const std::vector<MapEntry> &maps,
                           std::vector<std::string> &evidence) {
    Dl_info self_info {};
    uintptr_t self_base = 0;
    if (dladdr(reinterpret_cast<const void *>(&scan_self_wx_segments), &self_info) != 0
        && self_info.dli_fbase != nullptr) {
        self_base = reinterpret_cast<uintptr_t>(self_info.dli_fbase);
    }
    const MapEntry *self_code = find_map_containing(
            maps, reinterpret_cast<uintptr_t>(&scan_self_wx_segments));

    for (const auto &entry : maps) {
        if (entry.perms.size() < 3) continue;
        const bool writable = entry.perms[1] == 'w';
        const bool executable = entry.perms[2] == 'x';
        if (!writable || !executable) continue;

        if ((self_code != nullptr && entry.start == self_code->start)
            || (self_base != 0 && self_base >= entry.start && self_base < entry.end)) {
            add_evidence(evidence, OBF("wx_segment:self"));
            continue;
        }
        std::string lower = to_lower(entry.path);
        if (lower.find(OBF("libriskengine.so")) != std::string::npos) {
            add_evidence(evidence, OBF("wx_segment:self"));
        } else if (lower.find(OBF("libart.so")) != std::string::npos
                   || lower.find(OBF("libc.so")) != std::string::npos) {
            add_evidence(evidence, OBF("wx_segment:") + lower);
        }
    }
}

void append_csv_tokens(const std::string &csv, std::vector<std::string> &evidence) {
    if (csv.empty()) return;
    size_t start = 0;
    while (start <= csv.size()) {
        size_t comma = csv.find(',', start);
        if (comma == std::string::npos) comma = csv.size();
        add_evidence(evidence, csv.substr(start, comma - start));
        if (comma == csv.size()) break;
        start = comma + 1;
    }
}

std::string sanitize_maps_path(const std::string &path) {
    if (path.empty()) return "";
    std::string out = path;
    for (char &c : out) {
        if (c == ',') c = '_';
    }
    return out;
}

void collect_hook_evidence(JNIEnv *env, const std::vector<MapEntry> &maps,
                           std::vector<std::string> &evidence) {
    bool has_frida_family = false;
    for (const auto &entry : maps) {
        std::string lower = to_lower(entry.raw);
        std::string clean_path = sanitize_maps_path(entry.path);
        if (contains_any(lower, {OBF("frida"), OBF("libfrida"), OBF("frida-gadget"),
                                 OBF("libgadget.so")})) {
            has_frida_family = true;
            if (lower.find(OBF("frida")) != std::string::npos
                || lower.find(OBF("libfrida")) != std::string::npos) {
                add_evidence(evidence, clean_path.empty()
                        ? OBF("maps:frida") : OBF("maps:frida:") + clean_path);
            }
            if (lower.find(OBF("frida-gadget")) != std::string::npos
                || lower.find(OBF("libgadget.so")) != std::string::npos) {
                add_evidence(evidence, clean_path.empty()
                        ? OBF("maps:gadget") : OBF("maps:gadget:") + clean_path);
            }
        }
        if (lower.find(OBF("xposed")) != std::string::npos) {
            add_evidence(evidence, clean_path.empty()
                    ? OBF("maps:xposed") : OBF("maps:xposed:") + clean_path);
        }
        if (lower.find(OBF("lsposed")) != std::string::npos
            || lower.find(OBF("liblsposed")) != std::string::npos
            || lower.find(OBF("lspd")) != std::string::npos) {
            add_evidence(evidence, clean_path.empty()
                    ? OBF("maps:lsposed") : OBF("maps:lsposed:") + clean_path);
        }
        if (lower.find(OBF("substrate")) != std::string::npos) {
            add_evidence(evidence, clean_path.empty()
                    ? OBF("maps:substrate") : OBF("maps:substrate:") + clean_path);
        }
        if (is_suspicious_executable_region(entry)) {
            add_evidence(evidence, OBF("anon_exec:") + entry.perms);
        }
    }

    bool saw_gmain = false;
    RawDirResult tasks = raw_list_dir(OBF("/proc/self/task").c_str());
    if (tasks.ok()) {
        const std::string task_prefix = OBF("/proc/self/task/");
        const std::string comm_suffix = OBF("/comm");
        for (const auto &tid : tasks.names) {
            std::string comm_path = task_prefix + tid + comm_suffix;
            char comm_buf[64] = {0};
            if (read_file_content(comm_path.c_str(), comm_buf, sizeof(comm_buf)) <= 0) {
                continue;
            }
            std::string comm = to_lower(comm_buf);
            if (comm.find(OBF("gum-js-loop")) != std::string::npos) {
                has_frida_family = true;
                add_evidence(evidence, OBF("thread:gum-js-loop"));
            } else if (comm.find(OBF("frida")) != std::string::npos) {
                has_frida_family = true;
                add_evidence(evidence, OBF("thread:frida"));
            } else if (comm.find(OBF("gmain")) != std::string::npos) {
                saw_gmain = true;
            }
        }
    }
    if (saw_gmain && has_frida_family) {
        add_evidence(evidence, OBF("thread:gmain"));
    }

    scan_unix_sockets(evidence);
    scan_self_wx_segments(maps, evidence);
    for (const auto &token : native_scan_memfd_private_elfs(maps)) {
        add_evidence(evidence, token);
    }

    append_csv_tokens(native_get_art_hook_evidence(env, maps), evidence);
    append_csv_tokens(native_get_integrity_evidence(env, maps), evidence);
}

}  // namespace

std::vector<std::string> native_scan_memfd_private_elfs(const std::vector<MapEntry> &maps) {
    struct MemfdGroup {
        std::string label;
        bool has_priv_exec = false;
        bool has_priv_data = false;
        uintptr_t base_addr = 0;
    };

    const std::string memfd_prefix = OBF("/memfd:");
    std::map<uint64_t, MemfdGroup> groups;
    uint64_t synthetic_key = 1ull << 63;

    for (const auto &entry : maps) {
        if (entry.path.rfind(memfd_prefix, 0) != 0) continue;
        if (entry.perms.size() < 4) continue;
        // Legitimate ART /memfd:jit-cache and /memfd:jit-zygote-cache mappings are
        // always shared (perms[3] == 's'). Injected agents loaded via memfd_create
        // are mapped private (perms[3] == 'p') with ELF PT_LOAD segments (r-xp + r--p/rw-p).
        if (entry.perms[3] != 'p') continue;

        uint64_t key = entry.inode != 0 ? entry.inode : (++synthetic_key);
        auto &group = groups[key];
        if (group.label.empty()) {
            group.label = sanitize_memfd_label(entry.path);
        }
        if (entry.perms[2] == 'x') {
            group.has_priv_exec = true;
        } else if (entry.perms[0] == 'r') {
            group.has_priv_data = true;
        }
        if (entry.offset == 0 && entry.perms[0] == 'r' && group.base_addr == 0) {
            group.base_addr = entry.start;
        }
    }

    std::vector<std::string> results;
    int mem_fd = -1;
    bool mem_open_attempted = false;

    for (const auto &kv : groups) {
        const auto &group = kv.second;
        if (!group.has_priv_exec) continue;

        bool is_elf = false;
        if (group.base_addr != 0) {
            if (!mem_open_attempted) {
                mem_open_attempted = true;
                mem_fd = static_cast<int>(my_openat(
                        AT_FDCWD, OBF("/proc/self/mem").c_str(), O_RDONLY | O_CLOEXEC, 0));
            }
            is_elf = read_elf_magic_safe(mem_fd, group.base_addr);
        }

        if (is_elf || group.has_priv_data) {
            add_evidence(results, OBF("memfd_private_elf:") + group.label);
        }
    }

    if (mem_fd >= 0) {
        my_close(mem_fd);
    }
    return results;
}

std::string native_get_hook_evidence(JNIEnv *env, const std::vector<MapEntry> &maps) {
    std::vector<std::string> evidence;
    collect_hook_evidence(env, maps, evidence);
    std::string joined;
    for (size_t i = 0; i < evidence.size(); ++i) {
        if (i) joined += ",";
        joined += evidence[i];
    }
    return joined;
}

std::string native_get_hook_evidence(JNIEnv *env) {
    auto maps = read_self_maps();
    return native_get_hook_evidence(env, maps);
}
