#include "native_signature_checker.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>

// Verify APK by reading it directly via raw syscalls
// This bypasses any IO redirect hooks
std::string verify_apk_signature(const char *apk_path) {
    // Open APK via raw syscall
    int fd = (int) my_openat(AT_FDCWD, apk_path, O_RDONLY, 0);
    if (fd < 0) return "";

    // Verify fd path matches expected path (detect IO redirect)
    char fd_link[256] = {0};
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t link_len = my_readlinkat(AT_FDCWD, proc_path, fd_link, sizeof(fd_link) - 1);
    if (link_len > 0) {
        fd_link[link_len] = '\0';
        if (strcmp(fd_link, apk_path) != 0) {
            my_close(fd);
            return "io_redirect:" + std::string(fd_link);
        }
    }

    // Verify fstat - APK should be owned by system (uid 1000)
    struct stat st;
    if (my_fstat(fd, &st) == 0) {
        // Read APK signature block (simplified - just compute hash of first 4K)
        // Full implementation would parse ZIP end-of-central-directory
        unsigned char buf[4096];
        ssize_t n = my_read(fd, buf, sizeof(buf));
        my_close(fd);

        if (n > 0) {
            // Simple hash for now
            unsigned int hash = 0;
            for (int i = 0; i < n; i++) {
                hash = hash * 31 + buf[i];
            }
            char hex[32];
            snprintf(hex, sizeof(hex), "%08x", hash);
            return std::string(hex);
        }
    }

    my_close(fd);
    return "";
}
