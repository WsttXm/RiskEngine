#include "syscall_wrapper.h"
#include "raw_syscall.h"

#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {
thread_local int g_raw_errno = 0;

bool is_error(long ret) {
    return ret < 0 && ret > -4096;
}

long normalize(long ret) {
    if (is_error(ret)) {
        g_raw_errno = static_cast<int>(-ret);
        return -1;
    }
    g_raw_errno = 0;
    return ret;
}

#if defined(__NR_newfstatat)
constexpr long kFstatatNr = __NR_newfstatat;
#elif defined(__NR_fstatat64)
constexpr long kFstatatNr = __NR_fstatat64;
#else
constexpr long kFstatatNr = __NR_fstatat;
#endif

// armeabi routes through __NR_statfs64 below and never reads this constant.
#if defined(__NR_statfs)
[[maybe_unused]] constexpr long kStatfsNr = __NR_statfs;
#elif defined(__NR_statfs64)
[[maybe_unused]] constexpr long kStatfsNr = __NR_statfs64;
#else
#error "statfs syscall number missing"
#endif
}  // namespace

int raw_last_error() {
    return g_raw_errno;
}

long my_openat(int dirfd, const char *path, int flags, mode_t mode) {
    if (path == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
    return normalize(raw_syscall4(__NR_openat, dirfd, reinterpret_cast<long>(path),
                                  flags, static_cast<long>(mode)));
}

long my_read(int fd, void *buf, size_t count) {
    if (buf == nullptr && count > 0) {
        g_raw_errno = EFAULT;
        return -1;
    }
    long ret;
    do {
        ret = raw_syscall3(__NR_read, fd, reinterpret_cast<long>(buf),
                           static_cast<long>(count));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
}

long my_close(int fd) {
    return normalize(raw_syscall1(__NR_close, fd));
}

long my_lseek(int fd, long offset, int whence) {
#if defined(__NR_lseek)
    return normalize(raw_syscall3(__NR_lseek, fd, offset, whence));
#elif defined(__NR__llseek)
    unsigned long result[2] = {0, 0};
    long ret = raw_syscall5(__NR__llseek, fd, offset >> 32, offset & 0xffffffffL,
                            reinterpret_cast<long>(result), whence);
    if (normalize(ret) < 0) {
        return -1;
    }
    return static_cast<long>(result[0]);
#else
#error "lseek syscall number missing"
#endif
}

long my_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (path == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
    return normalize(raw_syscall4(__NR_faccessat, dirfd, reinterpret_cast<long>(path),
                                  mode, flags));
}

long my_access(const char *path, int mode) {
    return my_faccessat(AT_FDCWD, path, mode, 0);
}

long my_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    if (path == nullptr || st == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
    return normalize(raw_syscall4(kFstatatNr, dirfd, reinterpret_cast<long>(path),
                                  reinterpret_cast<long>(st), flags));
}

long my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    if (path == nullptr || buf == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
    return normalize(raw_syscall4(__NR_readlinkat, dirfd, reinterpret_cast<long>(path),
                                  reinterpret_cast<long>(buf), static_cast<long>(bufsiz)));
}

long my_getdents64(int fd, void *buf, size_t count) {
    if (buf == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
    long ret;
    do {
        ret = raw_syscall3(__NR_getdents64, fd, reinterpret_cast<long>(buf),
                           static_cast<long>(count));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
}

long my_statfs(const char *path, struct statfs *buf) {
    if (path == nullptr || buf == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_statfs64) && defined(__arm__)
    return normalize(raw_syscall3(__NR_statfs64, reinterpret_cast<long>(path),
                                  sizeof(*buf), reinterpret_cast<long>(buf)));
#else
    return normalize(raw_syscall2(kStatfsNr, reinterpret_cast<long>(path),
                                  reinterpret_cast<long>(buf)));
#endif
}

long my_uname(struct utsname *buf) {
    if (buf == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
    return normalize(raw_syscall1(__NR_uname, reinterpret_cast<long>(buf)));
}

long my_mmap(void *addr, size_t length, int prot, int flags, int fd, long offset) {
#if defined(__i386__)
    (void) addr; (void) length; (void) prot; (void) flags; (void) fd; (void) offset;
    g_raw_errno = ENOSYS;
    return -1;
#elif defined(__NR_mmap)
    return normalize(raw_syscall6(__NR_mmap, reinterpret_cast<long>(addr),
                                  static_cast<long>(length), prot, flags, fd, offset));
#elif defined(__NR_mmap2)
    return normalize(raw_syscall6(__NR_mmap2, reinterpret_cast<long>(addr),
                                  static_cast<long>(length), prot, flags, fd,
                                  offset / 4096));
#else
#error "mmap syscall number missing"
#endif
}

long my_munmap(void *addr, size_t length) {
    return normalize(raw_syscall2(__NR_munmap, reinterpret_cast<long>(addr),
                                  static_cast<long>(length)));
}

long my_prctl(int option, unsigned long a2, unsigned long a3,
              unsigned long a4, unsigned long a5) {
    return normalize(raw_syscall5(__NR_prctl, option, static_cast<long>(a2),
                                  static_cast<long>(a3), static_cast<long>(a4),
                                  static_cast<long>(a5)));
}

long my_getppid(void) {
    return normalize(raw_syscall0(__NR_getppid));
}

long my_gettid(void) {
    return normalize(raw_syscall0(__NR_gettid));
}

std::string read_file_string(const char *path, size_t max_bytes) {
    if (path == nullptr || max_bytes == 0) return std::string();
    int fd = static_cast<int>(my_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) return std::string();
    std::string out;
    char buffer[8192];
    while (out.size() < max_bytes) {
        size_t want = std::min(sizeof(buffer), max_bytes - out.size());
        long n = my_read(fd, buffer, want);
        if (n < 0) {
            if (raw_last_error() == EINTR) continue;
            break;
        }
        if (n == 0) break;
        out.append(buffer, static_cast<size_t>(n));
    }
    my_close(fd);
    return out;
}

int read_file_content(const char *path, char *buf, size_t bufsize) {
    if (path == nullptr || buf == nullptr || bufsize == 0) return -1;
    int fd = (int) my_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;

    memset(buf, 0, bufsize);
    ssize_t total = 0;
    while (total < (ssize_t) (bufsize - 1)) {
        long n = my_read(fd, buf + total, bufsize - 1 - total);
        if (n < 0 && raw_last_error() == EINTR) continue;
        if (n <= 0) break;
        total += n;
    }
    my_close(fd);
    if (total > 0 && buf[total - 1] == '\n') {
        buf[total - 1] = '\0';
        total--;
    }
    return (int) total;
}
