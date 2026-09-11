#include "kernel_su_probe.h"

#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cerrno>
#include <string>
#include <vector>

namespace {

// KernelSU's private prctl option and the reply it writes.
constexpr int kKsuOption = 0xDEADBEEF;
constexpr unsigned long kKsuCmdGetVersion = 2;
constexpr int kKsuMagicReply = 0x5A5A5A5A;

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

/**
 * Sends one KSU-style prctl and reports whether the kernel answered.
 * A stock kernel returns -EINVAL and leaves both out-params alone.
 */
bool probe_ksu_version(int &version_out) {
    volatile int version = 0;
    volatile int reply = 0;
    version_out = 0;

    long ret = my_prctl(kKsuOption, kKsuCmdGetVersion,
                        reinterpret_cast<unsigned long>(&version),
                        0,
                        reinterpret_cast<unsigned long>(&reply));

    // Any of: success return, a written version, or the magic reply.
    if (version != 0) {
        version_out = version;
        return true;
    }
    if (reply == kKsuMagicReply) {
        return true;
    }
    if (ret == 0) {
        return true;
    }
    return false;
}

}  // namespace

std::string native_get_kernel_root_evidence() {
    std::vector<std::string> tokens;

    int version = 0;
    if (probe_ksu_version(version)) {
        if (version > 0) {
            add_token(tokens, OBF("ksu_prctl:v") + std::to_string(version));
        } else {
            add_token(tokens, OBF("ksu_prctl:present"));
        }
    }

    // APatch reuses the KernelSU prctl surface, so a positive probe above
    // covers it. The su-context check below is a second, independent read:
    // on a stock device this process's SELinux context is an app domain.
    std::string context = read_file_string(OBF("/proc/self/attr/current").c_str(), 256);
    while (!context.empty()
           && (context.back() == '\0' || context.back() == '\n')) {
        context.pop_back();
    }
    if (!context.empty()) {
        std::string lower = context;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (lower.find(OBF("magisk")) != std::string::npos
            || lower.find(OBF("su:")) != std::string::npos
            || lower.find(OBF(":su")) != std::string::npos) {
            add_token(tokens, OBF("selinux_context:") + context);
        }
    }

    return join_tokens(tokens);
}
