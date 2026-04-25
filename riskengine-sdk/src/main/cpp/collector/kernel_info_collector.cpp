#include "kernel_info_collector.h"
#include <sys/utsname.h>
#include <string>

std::string get_kernel_info() {
    struct utsname buf;
    if (uname(&buf) == 0) {
        return std::string(buf.sysname) + " " + buf.release + " " +
               buf.version + " " + buf.machine;
    }
    return "";
}
