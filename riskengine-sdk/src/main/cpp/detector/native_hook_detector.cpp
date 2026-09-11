#include "native_hook_detector.h"
#include "art_hook_detector.h"
#include "native_integrity.h"
#include "../util/maps_parser.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cctype>
#include <fcntl.h>
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

/**
 * Frida's agent binds abstract AF_UNIX sockets whose names contain a known
 * prefix. Reading /proc/net/unix observes them passively; unlike a port
 * connect it never touches the agent, so it cannot be detected or refused.
 */
void scan_unix_sockets(std::vector<std::string> &evidence) {
    std::string content = read_file_string(OBF("/proc/net/unix").c_str(), 512 * 1024);
    if (content.empty()) return;
    std::string lower = to_lower(content);
    if (lower.find(OBF("re.frida")) != std::string::npos
        || lower.find(OBF("frida:")) != std::string::npos
        || lower.find(OBF("linjector")) != std::string::npos) {
        add_evidence(evidence, OBF("unix_socket:frida"));
    }
    if (lower.find(OBF("gum-js")) != std::string::npos) {
        add_evidence(evidence, OBF("unix_socket:gum"));
    }
}

/**
 * A writable+executable mapping belonging to this library indicates a patched
 * text segment. Stock loaders never leave our own code W+X.
 */
void scan_self_wx_segments(std::vector<std::string> &evidence) {
    for (const auto &entry : read_self_maps()) {
        if (entry.perms.size() < 3) continue;
        const bool writable = entry.perms[1] == 'w';
        const bool executable = entry.perms[2] == 'x';
        if (!writable || !executable) continue;
        std::string lower = to_lower(entry.path);
        if (lower.find(OBF("libriskengine.so")) != std::string::npos) {
            add_evidence(evidence, OBF("wx_segment:self"));
        } else if (lower.find(OBF("libart.so")) != std::string::npos
                   || lower.find(OBF("libc.so")) != std::string::npos) {
            add_evidence(evidence, OBF("wx_segment:") + lower);
        }
    }
}

void collect_hook_evidence(JNIEnv *env, std::vector<std::string> &evidence) {
    bool has_frida_family = false;
    auto maps = read_self_maps();
    for (const auto &entry : maps) {
        std::string lower = to_lower(entry.raw);
        if (contains_any(lower, {OBF("frida"), OBF("libfrida"), OBF("frida-gadget"),
                                 OBF("libgadget.so")})) {
            has_frida_family = true;
            if (lower.find(OBF("frida")) != std::string::npos
                || lower.find(OBF("libfrida")) != std::string::npos) {
                add_evidence(evidence, OBF("maps:frida"));
            }
            if (lower.find(OBF("frida-gadget")) != std::string::npos
                || lower.find(OBF("libgadget.so")) != std::string::npos) {
                add_evidence(evidence, OBF("maps:gadget"));
            }
        }
        if (lower.find(OBF("xposed")) != std::string::npos) {
            add_evidence(evidence, OBF("maps:xposed"));
        }
        if (lower.find(OBF("lsposed")) != std::string::npos
            || lower.find(OBF("liblsposed")) != std::string::npos
            || lower.find(OBF("lspd")) != std::string::npos) {
            add_evidence(evidence, OBF("maps:lsposed"));
        }
        if (lower.find(OBF("substrate")) != std::string::npos) {
            add_evidence(evidence, OBF("maps:substrate"));
        }
        if (is_suspicious_executable_region(entry)) {
            add_evidence(evidence, OBF("anon_exec:") + entry.perms);
        }
    }

    bool saw_gmain = false;
    RawDirResult tasks = raw_list_dir(OBF("/proc/self/task").c_str());
    if (tasks.ok()) {
        for (const auto &tid : tasks.names) {
            std::string comm_path = OBF("/proc/self/task/") + tid + OBF("/comm");
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
    scan_self_wx_segments(evidence);

    // ART-level checks catch renamed Xposed-family frameworks by mechanism
    // rather than by any matchable name.
    std::string art = native_get_art_hook_evidence(env);
    if (!art.empty()) {
        size_t start = 0;
        while (start <= art.size()) {
            size_t comma = art.find(',', start);
            if (comma == std::string::npos) comma = art.size();
            add_evidence(evidence, art.substr(start, comma - start));
            if (comma == art.size()) break;
            start = comma + 1;
        }
    }

    std::string integrity = native_get_integrity_evidence(env);
    if (!integrity.empty()) {
        size_t start = 0;
        while (start <= integrity.size()) {
            size_t comma = integrity.find(',', start);
            if (comma == std::string::npos) comma = integrity.size();
            add_evidence(evidence, integrity.substr(start, comma - start));
            if (comma == integrity.size()) break;
            start = comma + 1;
        }
    }
}

}  // namespace

std::string native_get_hook_evidence(JNIEnv *env) {
    std::vector<std::string> evidence;
    collect_hook_evidence(env, evidence);
    std::string joined;
    for (size_t i = 0; i < evidence.size(); ++i) {
        if (i) joined += ",";
        joined += evidence[i];
    }
    return joined;
}
