#include "maps_monitor.h"
#include "../util/syscall_wrapper.h"
#include <string>
#include <cstdio>
#include <cstring>
#include <fcntl.h>

bool check_maps_redirect() {
    // Method: Open /proc/self/maps via raw syscall, then verify the fd
    // actually points to /proc/self/maps (not redirected)
    int fd = (int) my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return false;

    // Read fd link via raw syscall
    char link_buf[256] = {0};
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t link_len = my_readlinkat(AT_FDCWD, fd_path, link_buf, sizeof(link_buf) - 1);

    my_close(fd);

    if (link_len > 0) {
        link_buf[link_len] = '\0';
        // Verify it actually points to /proc/self/maps or /proc/<pid>/maps
        if (strstr(link_buf, "/proc/") && strstr(link_buf, "/maps")) {
            return false; // No redirect detected
        }
        return true; // Redirected to somewhere else
    }

    return false;
}
