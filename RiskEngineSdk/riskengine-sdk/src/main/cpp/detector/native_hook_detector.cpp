#include "native_hook_detector.h"
#include "../util/syscall_wrapper.h"
#include "../util/elf_parser.h"
#include <string>
#include <cstring>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>

bool native_check_hooks() {
    // Check /proc/self/maps for known hook libraries
    char buf[16384] = {0};
    int fd = (int) my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return false;

    ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
    my_close(fd);

    if (n > 0) {
        buf[n] = '\0';
        if (strstr(buf, "frida") || strstr(buf, "LIBFRIDA") ||
            strstr(buf, "gadget") || strstr(buf, "xposed") ||
            strstr(buf, "substrate")) {
            return true;
        }
    }

    // Check thread names for Frida
    char task_path[128];
    char comm_buf[64];
    DIR *task_dir = opendir("/proc/self/task");
    if (task_dir) {
        struct dirent *entry;
        while ((entry = readdir(task_dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            snprintf(task_path, sizeof(task_path), "/proc/self/task/%s/comm", entry->d_name);
            if (read_file_content(task_path, comm_buf, sizeof(comm_buf)) > 0) {
                if (strstr(comm_buf, "gum-js-loop") ||
                    strstr(comm_buf, "gmain") ||
                    strstr(comm_buf, "frida")) {
                    closedir(task_dir);
                    return true;
                }
            }
        }
        closedir(task_dir);
    }

    return false;
}

std::string native_get_hook_evidence() {
    std::string evidence;

    // Scan maps
    char buf[16384] = {0};
    int fd = (int) my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd >= 0) {
        ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
        my_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            const char *keywords[] = {"frida", "LIBFRIDA", "gadget", "xposed", "substrate", nullptr};
            for (int i = 0; keywords[i]; i++) {
                if (strstr(buf, keywords[i])) {
                    if (!evidence.empty()) evidence += ",";
                    evidence += "maps:" + std::string(keywords[i]);
                }
            }
        }
    }

    // Check thread names
    DIR *task_dir = opendir("/proc/self/task");
    if (task_dir) {
        struct dirent *entry;
        char task_path[128], comm_buf[64];
        while ((entry = readdir(task_dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            snprintf(task_path, sizeof(task_path), "/proc/self/task/%s/comm", entry->d_name);
            if (read_file_content(task_path, comm_buf, sizeof(comm_buf)) > 0) {
                if (strstr(comm_buf, "gum-js-loop") || strstr(comm_buf, "frida")) {
                    if (!evidence.empty()) evidence += ",";
                    evidence += "thread:" + std::string(comm_buf);
                }
            }
        }
        closedir(task_dir);
    }

    return evidence;
}
