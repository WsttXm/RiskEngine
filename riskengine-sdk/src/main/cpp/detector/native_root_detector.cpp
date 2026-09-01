#include "native_root_detector.h"
#include "../generated/detection_lists.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

void add_token(std::vector<std::string> &tokens, const std::string &token) {
    if (!token.empty()
        && std::find(tokens.begin(), tokens.end(), token) == tokens.end()) {
        tokens.push_back(token);
    }
}

struct PathProbe {
    bool access_ok = false;
    bool stat_ok = false;
    bool open_ok = false;
    bool any() const { return access_ok || stat_ok || open_ok; }
    bool mismatch() const {
        int n = static_cast<int>(access_ok) + static_cast<int>(stat_ok)
                + static_cast<int>(open_ok);
        return n == 1 || n == 2;
    }
};

PathProbe probe_path(const std::string &path) {
    PathProbe probe;
    probe.access_ok = my_faccessat(AT_FDCWD, path.c_str(), F_OK, 0) == 0;
    struct stat st {};
    probe.stat_ok = my_fstatat(AT_FDCWD, path.c_str(), &st, 0) == 0;
    int fd = static_cast<int>(my_openat(AT_FDCWD, path.c_str(),
                                        O_RDONLY | O_CLOEXEC, 0));
    if (fd >= 0) {
        probe.open_ok = true;
        my_close(fd);
    }
    return probe;
}

void probe_group(const std::vector<std::string> &paths, const std::string &prefix,
                 std::vector<std::string> &tokens) {
    for (const auto &path : paths) {
        PathProbe probe = probe_path(path);
        if (probe.any()) {
            add_token(tokens, prefix + path);
        }
        if (probe.mismatch()) {
            add_token(tokens, OBF("syscall_mismatch:") + path);
        }
    }
}

void scan_path_env(std::vector<std::string> &tokens) {
    char buf[8192];
    int n = read_file_content(OBF("/proc/self/environ").c_str(), buf, sizeof(buf));
    if (n <= 0) return;
    std::string path_value;
    size_t i = 0;
    while (i < static_cast<size_t>(n)) {
        const char *entry = buf + i;
        size_t len = 0;
        while (i + len < static_cast<size_t>(n) && buf[i + len] != '\0') len++;
        if (len > 5 && std::strncmp(entry, "PATH=", 5) == 0) {
            path_value.assign(entry + 5, len - 5);
            break;
        }
        i += len + 1;
    }
    if (path_value.empty()) return;

    const std::vector<std::string> bins = {
            OBF("su"), OBF("ksud"), OBF("apd"), OBF("magisk")
    };
    size_t start = 0;
    while (start < path_value.size()) {
        size_t sep = path_value.find(':', start);
        if (sep == std::string::npos) sep = path_value.size();
        std::string dir = path_value.substr(start, sep - start);
        start = sep + 1;
        if (dir.empty()) continue;
        for (const auto &bin : bins) {
            std::string candidate = dir + "/" + bin;
            if (my_faccessat(AT_FDCWD, candidate.c_str(), F_OK, 0) == 0) {
                add_token(tokens, OBF("path_su:") + candidate);
            }
        }
    }
}

void scan_mountinfo(std::vector<std::string> &tokens) {
    char buf[65536];
    int n = read_file_content(OBF("/proc/self/mountinfo").c_str(), buf, sizeof(buf));
    if (n <= 0) return;
    std::string content(buf, static_cast<size_t>(n));
    std::string lower = content;
    for (char &c : lower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    if (lower.find(OBF("magisk")) != std::string::npos
        || lower.find(OBF("core/mirror")) != std::string::npos
        || lower.find(OBF("debug_ramdisk")) != std::string::npos) {
        add_token(tokens, OBF("mount:magisk"));
    }
    if (lower.find(OBF("/data/adb/modules")) != std::string::npos) {
        add_token(tokens, OBF("mount:module"));
    }
}

int read_selinux_enforce() {
    char buf[8] = {0};
    int n = read_file_content(OBF("/sys/fs/selinux/enforce").c_str(), buf, sizeof(buf));
    if (n <= 0) return -1;
    if (buf[0] == '0') return 0;
    if (buf[0] == '1') return 1;
    return -1;
}

}  // namespace

int native_get_selinux_enforce() {
    return read_selinux_enforce();
}

std::string native_get_build_prop_fingerprint() {
    char buf[8192];
    int n = read_file_content(OBF("/system/build.prop").c_str(), buf, sizeof(buf));
    if (n <= 0) return "";
    std::string content(buf, static_cast<size_t>(n));
    const std::string key = OBF("ro.build.fingerprint=");
    auto pos = content.find(key);
    if (pos == std::string::npos) return "";
    auto end = content.find('\n', pos);
    std::string value = content.substr(pos + key.size(),
                                       end == std::string::npos ? std::string::npos
                                                                : end - pos - key.size());
    while (!value.empty() && (value.back() == '\r' || value.back() == ' ')) {
        value.pop_back();
    }
    return value;
}

bool native_check_root() {
    return !native_get_root_evidence().empty();
}

std::string native_get_root_evidence() {
    std::vector<std::string> tokens;
    probe_group(list_su_paths(), OBF("su:"), tokens);
    probe_group(list_magisk_paths(), OBF("magisk:"), tokens);
    probe_group(list_kernelsu_paths(), OBF("ksu:"), tokens);
    probe_group(list_apatch_paths(), OBF("apatch:"), tokens);
    probe_group(list_module_paths(), OBF("modules:"), tokens);
    scan_path_env(tokens);
    scan_mountinfo(tokens);
    if (read_selinux_enforce() == 0) {
        add_token(tokens, OBF("selinux_permissive"));
    }

    std::string joined;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i) joined += ",";
        joined += tokens[i];
    }
    return joined;
}
