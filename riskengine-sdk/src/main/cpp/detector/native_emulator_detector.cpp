#include "native_emulator_detector.h"
#include "../generated/detection_lists.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <fcntl.h>
#include <unistd.h>

std::string check_emulator_files() {
    std::string found;
    for (const auto &path : list_emulator_files()) {
        if (my_faccessat(AT_FDCWD, path.c_str(), F_OK, 0) == 0) {
            if (!found.empty()) found += ",";
            found += path;
        }
    }
    return found;
}

int get_thermal_zone_count() {
    RawDirResult dir = raw_list_dir(OBF("/sys/class/thermal").c_str());
    if (!dir.ok()) return -1;
    int count = 0;
    const std::string prefix = OBF("thermal_zone");
    for (const auto &name : dir.names) {
        if (name.find(prefix) != std::string::npos) {
            count++;
        }
    }
    return count;
}
