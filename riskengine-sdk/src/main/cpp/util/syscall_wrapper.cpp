#include "syscall_wrapper.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

// Use raw syscall to avoid libc hooks
long my_openat(int dirfd, const char *path, int flags, mode_t mode) {
    return syscall(__NR_openat, dirfd, path, flags, mode);
}

long my_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

long my_close(int fd) {
    return syscall(__NR_close, fd);
}

long my_access(const char *path, int mode) {
    return syscall(__NR_faccessat, AT_FDCWD, path, mode, 0);
}

int read_file_content(const char *path, char *buf, size_t bufsize) {
    if (path == nullptr || buf == nullptr || bufsize == 0) return -1;
    int fd = (int) my_openat(AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return -1;

    memset(buf, 0, bufsize);
    ssize_t total = 0;
    ssize_t n;
    while (total < (ssize_t)(bufsize - 1)) {
        n = my_read(fd, buf + total, bufsize - 1 - total);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        total += n;
    }
    my_close(fd);

    // Trim trailing newline
    if (total > 0 && buf[total - 1] == '\n') {
        buf[total - 1] = '\0';
    }
    return (int) total;
}
