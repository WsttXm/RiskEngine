#include "cpu_info_collector.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>

std::string get_cpu_info() {
    char buf[4096] = {0};
    int n = read_file_content("/proc/cpuinfo", buf, sizeof(buf));
    if (n <= 0) return "";

    // Extract non-unique CPU implementation and hardware information.
    std::string result;
    char *saveptr = nullptr;
    char *line = strtok_r(buf, "\n", &saveptr);
    while (line) {
        if (strstr(line, "Hardware") || strstr(line, "Processor") ||
            strstr(line, "CPU implementer") ||
            strstr(line, "CPU part")) {
            if (!result.empty()) result += "|";
            result += line;
        }
        line = strtok_r(nullptr, "\n", &saveptr);
    }
    return result;
}
