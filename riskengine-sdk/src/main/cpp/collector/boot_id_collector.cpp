#include "boot_id_collector.h"
#include "../util/syscall_wrapper.h"
#include <string>

std::string get_boot_id() {
    char buf[128] = {0};
    int n = read_file_content("/proc/sys/kernel/random/boot_id", buf, sizeof(buf));
    if (n > 0) {
        return std::string(buf);
    }
    return "";
}
