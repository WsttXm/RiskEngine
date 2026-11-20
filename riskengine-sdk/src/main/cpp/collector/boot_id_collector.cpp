#include "boot_id_collector.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"
#include <string>

std::string get_boot_id() {
    char buf[128] = {0};
    int n = read_file_content(OBF("/proc/sys/kernel/random/boot_id").c_str(), buf, sizeof(buf));
    if (n > 0) {
        return std::string(buf, static_cast<size_t>(n));
    }
    return "";
}
