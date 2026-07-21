#include "native_debug_detector.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>

int get_tracer_pid() {
    char buf[1024] = {0};
    int n = read_file_content("/proc/self/status", buf, sizeof(buf));
    if (n <= 0) return -1;

    char *line = strstr(buf, "TracerPid:");
    if (line) {
        return atoi(line + 10);
    }
    return -1;
}
