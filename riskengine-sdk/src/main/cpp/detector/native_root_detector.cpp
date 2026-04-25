#include "native_root_detector.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <vector>
#include <unistd.h>

static const char *su_paths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/su", "/su/bin/su",
        "/apex/com.android.runtime/bin/su",
        nullptr
};

static const char *magisk_paths[] = {
        "/sbin/.magisk", "/data/adb/magisk",
        "/data/adb/magisk.db", "/data/adb/modules",
        "/cache/.disable_magisk",
        nullptr
};

bool native_check_root() {
    for (int i = 0; su_paths[i]; i++) {
        if (my_access(su_paths[i], F_OK) == 0) return true;
    }
    for (int i = 0; magisk_paths[i]; i++) {
        if (my_access(magisk_paths[i], F_OK) == 0) return true;
    }
    return false;
}

std::string native_get_root_evidence() {
    std::string evidence;
    for (int i = 0; su_paths[i]; i++) {
        if (my_access(su_paths[i], F_OK) == 0) {
            if (!evidence.empty()) evidence += ",";
            evidence += su_paths[i];
        }
    }
    for (int i = 0; magisk_paths[i]; i++) {
        if (my_access(magisk_paths[i], F_OK) == 0) {
            if (!evidence.empty()) evidence += ",";
            evidence += magisk_paths[i];
        }
    }
    return evidence;
}
