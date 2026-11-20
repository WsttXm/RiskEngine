#include "native_emulator_detector.h"
#include "../generated/detection_lists.h"
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"

#include <algorithm>
#include <cctype>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>

namespace {

std::string read_sys_prop_lower(const std::string &name) {
    char buf[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(name.c_str(), buf);
    if (len <= 0) return "";
    std::string out(buf, static_cast<size_t>(len));
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

}  // namespace

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

bool native_has_emulator_props() {
    if (read_sys_prop_lower(OBF("ro.kernel.qemu")) == OBF("1")
        || read_sys_prop_lower(OBF("ro.boot.qemu")) == OBF("1")) {
        return true;
    }
    const std::string hardware = read_sys_prop_lower(OBF("ro.hardware"));
    if (hardware.find(OBF("ranchu")) != std::string::npos
        || hardware.find(OBF("goldfish")) != std::string::npos
        || hardware.find(OBF("vbox")) != std::string::npos) {
        return true;
    }
    const std::string model = read_sys_prop_lower(OBF("ro.product.model"));
    if (model.find(OBF("sdk_gphone")) != std::string::npos
        || model.find(OBF("emulator")) != std::string::npos
        || model.find(OBF("android sdk built for")) != std::string::npos) {
        return true;
    }
    return false;
}
