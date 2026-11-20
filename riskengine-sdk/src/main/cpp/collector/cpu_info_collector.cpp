#include "cpu_info_collector.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>

std::string get_cpu_info() {
    std::string content = read_file_string(OBF("/proc/cpuinfo").c_str(), 64 * 1024);
    if (content.empty()) return "";

    const std::string kHardware = OBF("Hardware");
    const std::string kProcessor = OBF("Processor");
    const std::string kImpl = OBF("CPU implementer");
    const std::string kPart = OBF("CPU part");

    std::string result;
    size_t start = 0;
    while (start < content.size()) {
        size_t nl = content.find('\n', start);
        if (nl == std::string::npos) nl = content.size();
        std::string line = content.substr(start, nl - start);
        start = nl + 1;
        if (line.find(kHardware) != std::string::npos
                || line.find(kProcessor) != std::string::npos
                || line.find(kImpl) != std::string::npos
                || line.find(kPart) != std::string::npos) {
            if (!result.empty()) result += "|";
            result += line;
        }
    }
    return result;
}
