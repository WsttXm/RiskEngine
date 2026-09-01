#include "kernel_info_collector.h"
#include "../util/syscall_wrapper.h"

#include <cstring>
#include <string>

std::string get_kernel_info() {
    struct utsname buf;
    memset(&buf, 0, sizeof(buf));
    if (my_uname(&buf) == 0) {
        return std::string(buf.sysname) + " " + buf.release + " " + buf.machine;
    }
    return "";
}
