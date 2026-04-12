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

long my_write(int fd, const void *buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

long my_close(int fd) {
    return syscall(__NR_close, fd);
}

long my_lseek(int fd, off_t offset, int whence) {
    return syscall(__NR_lseek, fd, offset, whence);
}

long my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsize) {
    return syscall(__NR_readlinkat, dirfd, path, buf, bufsize);
}

long my_fstat(int fd, struct stat *statbuf) {
    return syscall(__NR_fstat, fd, statbuf);
}

long my_access(const char *path, int mode) {
    return syscall(__NR_faccessat, AT_FDCWD, path, mode, 0);
}

long my_getdents64(int fd, void *dirp, size_t count) {
    return syscall(__NR_getdents64, fd, dirp, count);
}

int read_file_content(const char *path, char *buf, size_t bufsize) {
    int fd = (int) my_openat(AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return -1;

    memset(buf, 0, bufsize);
    ssize_t total = 0;
    ssize_t n;
    while (total < (ssize_t)(bufsize - 1)) {
        n = my_read(fd, buf + total, bufsize - 1 - total);
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
