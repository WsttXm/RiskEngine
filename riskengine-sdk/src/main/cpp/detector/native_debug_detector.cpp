#include "native_debug_detector.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <cstdlib>
#include <cstring>
#include <string>

namespace {

int parse_tracer_pid_from_status(const std::string &status) {
    const std::string key = OBF("TracerPid:");
    auto pos = status.find(key);
    if (pos == std::string::npos) return -1;
    const char *p = status.c_str() + pos + key.size();
    while (*p == ' ' || *p == '\t') ++p;
    if (*p < '0' || *p > '9') return -1;
    return std::atoi(p);
}

}  // namespace

int get_tracer_pid() {
    std::string self_status = read_file_string(OBF("/proc/self/status").c_str(), 8192);
    int main_tracer = self_status.empty() ? -1 : parse_tracer_pid_from_status(self_status);
    if (main_tracer > 0) {
        return main_tracer;
    }

    // Also inspect per-thread status in case a debugger attaches to a worker thread.
    RawDirResult tasks = raw_list_dir(OBF("/proc/self/task").c_str());
    if (tasks.ok()) {
        const std::string prefix = OBF("/proc/self/task/");
        const std::string suffix = OBF("/status");
        for (const auto &tid : tasks.names) {
            std::string status = read_file_string((prefix + tid + suffix).c_str(), 4096);
            if (status.empty()) continue;
            int tracer = parse_tracer_pid_from_status(status);
            if (tracer > 0) {
                return tracer;
            }
        }
    }
    return main_tracer;
}
