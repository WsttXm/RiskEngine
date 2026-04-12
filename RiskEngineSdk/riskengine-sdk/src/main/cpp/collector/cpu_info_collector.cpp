#include "cpu_info_collector.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>

std::string get_cpu_info() {
    char buf[4096] = {0};
    int n = read_file_content("/proc/cpuinfo", buf, sizeof(buf));
    if (n <= 0) return "";

    // Extract serial and hardware info
    std::string result;
    char *line = strtok(buf, "\n");
    while (line) {
        if (strstr(line, "Serial") || strstr(line, "Hardware") ||
            strstr(line, "Processor") || strstr(line, "CPU implementer") ||
            strstr(line, "CPU part")) {
            if (!result.empty()) result += "|";
            result += line;
        }
        line = strtok(nullptr, "\n");
    }
    return result;
}
