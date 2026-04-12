#include "native_emulator_detector.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>
#include <dirent.h>
#include <unistd.h>

static const char *emulator_files[] = {
        "/system/bin/androVM-prop",
        "/system/bin/microvirt-prop",
        "/system/lib/libdroid4x.so",
        "/system/bin/windroyed",
        "/system/bin/nox-prop",
        "/system/lib/libnoxspeedup.so",
        "/system/bin/ttVM-prop",
        "/data/.bluestacks.prop",
        "/system/bin/duosconfig",
        "/system/etc/xxzs_prop.sh",
        "/system/etc/mumu-configs/device-prop-configs/mumu.config",
        "/system/priv-app/ldAppStore",
        "/system/lib/libc_malloc_debug_qemu.so",
        nullptr
};

std::string check_emulator_files() {
    for (int i = 0; emulator_files[i]; i++) {
        if (my_access(emulator_files[i], F_OK) == 0) {
            return std::string(emulator_files[i]);
        }
    }
    return "";
}

int get_thermal_zone_count() {
    DIR *dir = opendir("/sys/class/thermal/");
    if (!dir) return -1;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        if (strstr(entry->d_name, "thermal_zone") != nullptr) {
            count++;
        }
    }
    closedir(dir);
    return count;
}
