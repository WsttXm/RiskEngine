#include "mount_namespace_diff.h"

#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <fcntl.h>
#include <string>
#include <vector>

namespace {

void add_token(std::vector<std::string> &tokens, const std::string &token) {
    if (!token.empty()
        && std::find(tokens.begin(), tokens.end(), token) == tokens.end()) {
        tokens.push_back(token);
    }
}

std::string join_tokens(const std::vector<std::string> &tokens) {
    std::string joined;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i) joined += ",";
        joined += tokens[i];
    }
    return joined;
}

std::vector<std::string> split_lines(const std::string &content) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < content.size()) {
        size_t nl = content.find('\n', start);
        if (nl == std::string::npos) nl = content.size();
        if (nl > start) lines.emplace_back(content, start, nl - start);
        start = nl + 1;
    }
    return lines;
}

/** mountinfo field 5 is the mount point. Returns empty when malformed. */
std::string mount_point_of(const std::string &line) {
    size_t field = 0;
    size_t pos = 0;
    while (field < 4) {
        pos = line.find(' ', pos);
        if (pos == std::string::npos) return std::string();
        ++pos;
        ++field;
    }
    size_t end = line.find(' ', pos);
    if (end == std::string::npos) return std::string();
    return line.substr(pos, end - pos);
}

std::string read_ns_link(const char *path) {
    char buf[128] = {0};
    long n = my_readlinkat(AT_FDCWD, path, buf, sizeof(buf) - 1);
    if (n <= 0) return std::string();
    return std::string(buf, static_cast<size_t>(n));
}

bool is_interesting_mount(const std::string &point) {
    // Mount points that root frameworks bind over and then hide per-process.
    static const char *const kPrefixes[] = {
            "/system", "/vendor", "/product", "/system_ext", "/odm",
            "/data/adb", "/sbin", "/debug_ramdisk", "/apex"
    };
    for (const char *prefix : kPrefixes) {
        if (point.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

}  // namespace

std::string native_get_mount_namespace_evidence() {
    std::vector<std::string> tokens;

    const std::string self_ns = read_ns_link(OBF("/proc/self/ns/mnt").c_str());
    const std::string init_ns = read_ns_link(OBF("/proc/1/ns/mnt").c_str());

    std::string self_info = read_file_string(OBF("/proc/self/mountinfo").c_str());
    std::string init_info = read_file_string(OBF("/proc/1/mountinfo").c_str());

    if (self_info.empty()) {
        add_token(tokens, OBF("ns_unreadable:self"));
        return join_tokens(tokens);
    }
    if (init_info.empty()) {
        // Expected on most stock devices for a non-privileged app. Report as a
        // coverage token so the Java layer can mark PARTIAL instead of SAFE.
        add_token(tokens, OBF("ns_unreadable:init"));
    }

    if (!self_ns.empty() && !init_ns.empty() && self_ns != init_ns) {
        add_token(tokens, OBF("ns_differs"));
    }

    if (!init_info.empty()) {
        std::vector<std::string> self_points;
        for (const auto &line : split_lines(self_info)) {
            std::string point = mount_point_of(line);
            if (!point.empty()) self_points.push_back(point);
        }
        std::sort(self_points.begin(), self_points.end());

        size_t missing = 0;
        for (const auto &line : split_lines(init_info)) {
            std::string point = mount_point_of(line);
            if (point.empty() || !is_interesting_mount(point)) continue;
            if (!std::binary_search(self_points.begin(), self_points.end(), point)) {
                ++missing;
                if (missing <= 4) {
                    add_token(tokens, OBF("mount_hidden:") + point);
                }
            }
        }
        if (missing > 0) {
            add_token(tokens, OBF("mount_hidden_count:") + std::to_string(missing));
        }
    }

    return join_tokens(tokens);
}
