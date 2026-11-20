#include "native_root_detector.h"
#include "kernel_su_probe.h"
#include "../generated/detection_lists.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <map>
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
    std::string env_content = read_file_string(OBF("/proc/self/environ").c_str(), 32 * 1024);
    if (env_content.empty()) return;
    std::string path_value;
    const std::string path_prefix = OBF("PATH=");
    size_t i = 0;
    while (i < env_content.size()) {
        size_t nul = env_content.find('\0', i);
        if (nul == std::string::npos) nul = env_content.size();
        if (nul - i > path_prefix.size()
                && env_content.compare(i, path_prefix.size(), path_prefix) == 0) {
            path_value = env_content.substr(i + path_prefix.size(), nul - i - path_prefix.size());
            break;
        }
        i = nul + 1;
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
    std::string content = read_file_string(OBF("/proc/self/mountinfo").c_str(), 512 * 1024);
    if (content.empty()) return;
    std::string lower = content;
    for (char &c : lower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    const bool has_ksu = lower.find(OBF("kernelsu")) != std::string::npos
                         || lower.find(OBF("/data/adb/ksu")) != std::string::npos
                         || lower.find(OBF(" ksu ")) != std::string::npos;
    const bool has_magisk = lower.find(OBF("magisk")) != std::string::npos
                            || lower.find(OBF("core/mirror")) != std::string::npos;
    if (has_ksu) {
        add_token(tokens, OBF("mount:ksu"));
    }
    if (has_magisk) {
        add_token(tokens, OBF("mount:magisk"));
    }
    // debug_ramdisk is shared by several root implementations. Do not label it
    // Magisk unless the mount table also contains a Magisk-specific marker.
    if (!has_ksu && !has_magisk
        && lower.find(OBF("debug_ramdisk")) != std::string::npos) {
        add_token(tokens, OBF("mount:debug_ramdisk"));
    }
    if (lower.find(OBF("/data/adb/modules")) != std::string::npos) {
        add_token(tokens, OBF("mount:module"));
    }

    // Detect tmpfs mounted directly onto read-only system partition subpaths
    // (e.g. MoveCertificate / Magisk / KernelSU module mounting tmpfs on
    // /system/etc/security/cacerts, which survives KernelSU umount + Shamiko).
    const std::string sep_marker = OBF(" - ");
    const std::string tmpfs_tok = OBF("tmpfs");
    const std::vector<std::string> ro_prefixes = {
            OBF("/system/"), OBF("/vendor/"), OBF("/product/"),
            OBF("/system_ext/"), OBF("/odm/")
    };
    size_t pos = 0;
    while (pos < content.size()) {
        size_t nl = content.find('\n', pos);
        if (nl == std::string::npos) nl = content.size();
        if (nl > pos) {
            std::string line = content.substr(pos, nl - pos);
            // mountinfo field 5 (0-based index 4) is the mount point
            size_t field = 0;
            size_t p = 0;
            while (field < 4 && p != std::string::npos) {
                p = line.find(' ', p);
                if (p != std::string::npos) {
                    ++p;
                    ++field;
                }
            }
            if (field == 4 && p < line.size()) {
                size_t mp_end = line.find(' ', p);
                if (mp_end != std::string::npos && mp_end > p) {
                    std::string mount_point = line.substr(p, mp_end - p);
                    bool under_ro = false;
                    for (const auto &prefix : ro_prefixes) {
                        if (mount_point.rfind(prefix, 0) == 0) {
                            under_ro = true;
                            break;
                        }
                    }
                    if (under_ro) {
                        size_t sep = line.find(sep_marker, mp_end);
                        if (sep != std::string::npos) {
                            size_t fs_start = sep + sep_marker.size();
                            size_t fs_end = line.find(' ', fs_start);
                            std::string fs_type = fs_end == std::string::npos
                                    ? line.substr(fs_start)
                                    : line.substr(fs_start, fs_end - fs_start);
                            if (fs_type == tmpfs_tok) {
                                add_token(tokens, OBF("mount:system_tmpfs:") + mount_point);
                            }
                        }
                    }
                }
            }
        }
        pos = nl + 1;
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

std::string parent_dir_of(const std::string &path) {
    auto pos = path.rfind('/');
    if (pos == std::string::npos || pos == 0) return std::string("/");
    return path.substr(0, pos);
}

std::string base_name_of(const std::string &path) {
    auto pos = path.rfind('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

/**
 * Cross-checks direct stat against a getdents64 listing of the parent.
 * Caches parent directory listings within a single scan to avoid repeated
 * getdents64 passes over /system/bin and /data/adb.
 */
void cross_check_listing(const std::vector<std::string> &paths,
                         std::map<std::string, RawDirResult> &dir_cache,
                         std::vector<std::string> &tokens) {
    for (const auto &path : paths) {
        bool stat_visible = my_faccessat(AT_FDCWD, path.c_str(), F_OK, 0) == 0;
        const std::string parent = parent_dir_of(path);
        auto it = dir_cache.find(parent);
        if (it == dir_cache.end()) {
            it = dir_cache.emplace(parent, raw_list_dir(parent.c_str())).first;
        }
        const RawDirResult &dir = it->second;
        if (!dir.ok()) continue;
        const std::string name = base_name_of(path);
        bool listed = std::find(dir.names.begin(), dir.names.end(), name)
                      != dir.names.end();
        if (stat_visible != listed) {
            add_token(tokens, OBF("listing_mismatch:") + path);
        }
    }
}

}  // namespace

int native_get_selinux_enforce() {
    return read_selinux_enforce();
}

std::string native_get_build_prop_fingerprint() {
    std::string content = read_file_string(OBF("/system/build.prop").c_str(), 128 * 1024);
    if (content.empty()) return "";
    const std::string key = OBF("ro.build.fingerprint=");
    size_t pos = 0;
    while (pos < content.size()) {
        size_t end = content.find('\n', pos);
        if (end == std::string::npos) end = content.size();
        if (end - pos > key.size() && content.compare(pos, key.size(), key) == 0) {
            std::string value = content.substr(pos + key.size(), end - pos - key.size());
            while (!value.empty() && (value.back() == '\r' || value.back() == ' ')) {
                value.pop_back();
            }
            return value;
        }
        pos = end + 1;
    }
    return "";
}

std::string native_get_proc_cmdline_boot_props() {
    std::string cmdline = read_file_string(OBF("/proc/cmdline").c_str(), 16 * 1024);
    if (cmdline.empty()) return "";

    const std::vector<std::string> wanted_keys = {
            OBF("androidboot.verifiedbootstate"),
            OBF("androidboot.flash.locked"),
            OBF("androidboot.vbmeta.digest"),
            OBF("androidboot.qemu")
    };

    std::vector<std::string> pairs;
    size_t pos = 0;
    while (pos < cmdline.size()) {
        while (pos < cmdline.size()
                && (cmdline[pos] == ' ' || cmdline[pos] == '\t'
                    || cmdline[pos] == '\n' || cmdline[pos] == '\r')) {
            ++pos;
        }
        if (pos >= cmdline.size()) break;
        size_t end = pos;
        while (end < cmdline.size()
                && cmdline[end] != ' ' && cmdline[end] != '\t'
                && cmdline[end] != '\n' && cmdline[end] != '\r') {
            ++end;
        }
        std::string item = cmdline.substr(pos, end - pos);
        pos = end;
        auto eq = item.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 >= item.size()) continue;
        std::string key = item.substr(0, eq);
        std::string val = item.substr(eq + 1);
        for (const auto &wanted : wanted_keys) {
            if (key == wanted) {
                add_token(pairs, key + "=" + val);
                break;
            }
        }
    }

    std::string joined;
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i) joined += ";";
        joined += pairs[i];
    }
    return joined;
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
    probe_group(list_tamper_tool_paths(), OBF("tamper_tool:"), tokens);
    scan_path_env(tokens);
    scan_mountinfo(tokens);

    // Hidden-root detection that path probes cannot reach.
    std::map<std::string, RawDirResult> dir_cache;
    cross_check_listing(list_su_paths(), dir_cache, tokens);
    cross_check_listing(list_magisk_paths(), dir_cache, tokens);

    const std::string kernel_evidence = native_get_kernel_root_evidence();
    if (!kernel_evidence.empty()) {
        size_t start = 0;
        while (start <= kernel_evidence.size()) {
            size_t comma = kernel_evidence.find(',', start);
            if (comma == std::string::npos) comma = kernel_evidence.size();
            add_token(tokens, kernel_evidence.substr(start, comma - start));
            if (comma == kernel_evidence.size()) break;
            start = comma + 1;
        }
    }

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
