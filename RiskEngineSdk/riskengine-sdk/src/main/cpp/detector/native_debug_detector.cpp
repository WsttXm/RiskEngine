#include "native_debug_detector.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>
#include <cstdlib>
#include <sys/ptrace.h>
#include <fcntl.h>

int get_tracer_pid() {
    char buf[1024] = {0};
    int n = read_file_content("/proc/self/status", buf, sizeof(buf));
    if (n <= 0) return 0;

    char *line = strstr(buf, "TracerPid:");
    if (line) {
        return atoi(line + 10);
    }
    return 0;
}

bool check_ptrace() {
    // Try to ptrace ourselves; if already being traced, this will fail
    long ret = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    if (ret < 0) {
        return true; // Already being traced
    }
    // Detach
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    return false;
}
