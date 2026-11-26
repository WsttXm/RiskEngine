#include "syscall_wrapper.h"
#include "mylibc.h"
#include "raw_syscall.h"

#include <algorithm>
#include <errno.h>
#include <fcntl.h>
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
#elif defined(__NR_fstatat)
constexpr long kFstatatNr = __NR_fstatat;
#else
#error "fstatat syscall number missing"
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
    long ret;
    do {
        ret = raw_syscall4(__NR_openat, dirfd, reinterpret_cast<long>(path),
                           flags, static_cast<long>(mode));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
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

long my_pread64(int fd, void *buf, size_t count, uint64_t offset) {
    if (buf == nullptr && count > 0) {
        g_raw_errno = EFAULT;
        return -1;
    }
    long ret;
    do {
#if defined(__LP64__)
        ret = raw_syscall4(__NR_pread64, fd, reinterpret_cast<long>(buf),
                           static_cast<long>(count), static_cast<long>(offset));
#else
#error "RiskEngine requires a 64-bit ABI (arm64-v8a or x86_64)"
#endif
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
}

long my_close(int fd) {
    return normalize(raw_syscall1(__NR_close, fd));
}

long my_lseek(int fd, long offset, int whence) {
#if defined(__NR_lseek)
    return normalize(raw_syscall3(__NR_lseek, fd, offset, whence));
#else
#error "lseek syscall number missing"
#endif
}

long my_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (path == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
    if (flags == 0) {
        return normalize(raw_syscall3(__NR_faccessat, dirfd,
                                      reinterpret_cast<long>(path), mode));
    }
#if defined(__NR_faccessat2)
    return normalize(raw_syscall4(__NR_faccessat2, dirfd,
                                  reinterpret_cast<long>(path), mode, flags));
#else
    g_raw_errno = ENOSYS;
    return -1;
#endif
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
#if defined(__NR_statfs)
    return normalize(raw_syscall2(__NR_statfs, reinterpret_cast<long>(path),
                                  reinterpret_cast<long>(buf)));
#else
#error "statfs syscall number missing"
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
#if defined(__NR_mmap)
    return normalize(raw_syscall6(__NR_mmap, reinterpret_cast<long>(addr),
                                  static_cast<long>(length), prot, flags, fd, offset));
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

long my_getcpu(unsigned *cpu, unsigned *node) {
#if defined(__NR_getcpu)
    return normalize(raw_syscall3(__NR_getcpu,
                                  reinterpret_cast<long>(cpu),
                                  reinterpret_cast<long>(node), 0));
#else
    (void) cpu;
    (void) node;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_statx(int dirfd, const char *path, int flags, unsigned int mask, void *stx_buf) {
    if (path == nullptr || stx_buf == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_statx)
    long ret;
    do {
        ret = raw_syscall5(__NR_statx, dirfd, reinterpret_cast<long>(path),
                           flags, static_cast<long>(mask),
                           reinterpret_cast<long>(stx_buf));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) dirfd;
    (void) flags;
    (void) mask;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_getxattr(const char *path, const char *name, void *value, size_t size) {
    if (path == nullptr || name == nullptr || (value == nullptr && size > 0)) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_getxattr)
    long ret;
    do {
        ret = raw_syscall4(__NR_getxattr, reinterpret_cast<long>(path),
                           reinterpret_cast<long>(name),
                           reinterpret_cast<long>(value),
                           static_cast<long>(size));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_lgetxattr(const char *path, const char *name, void *value, size_t size) {
    if (path == nullptr || name == nullptr || (value == nullptr && size > 0)) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_lgetxattr)
    long ret;
    do {
        ret = raw_syscall4(__NR_lgetxattr, reinterpret_cast<long>(path),
                           reinterpret_cast<long>(name),
                           reinterpret_cast<long>(value),
                           static_cast<long>(size));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_truncate(const char *path, off_t length) {
    if (path == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_truncate)
    long ret;
    do {
        ret = raw_syscall2(__NR_truncate, reinterpret_cast<long>(path),
                           static_cast<long>(length));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) length;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_mincore(void *addr, size_t length, unsigned char *vec) {
    if (vec == nullptr && length > 0) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_mincore)
    long ret;
    do {
        ret = raw_syscall3(__NR_mincore, reinterpret_cast<long>(addr),
                           static_cast<long>(length),
                           reinterpret_cast<long>(vec));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) addr;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
#if defined(__NR_setresuid)
    return normalize(raw_syscall3(__NR_setresuid,
                                  static_cast<long>(ruid),
                                  static_cast<long>(euid),
                                  static_cast<long>(suid)));
#else
    (void) ruid;
    (void) euid;
    (void) suid;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_reboot(unsigned int magic1, unsigned int magic2, unsigned int cmd, void *arg) {
#if defined(__NR_reboot)
    return normalize(raw_syscall4(__NR_reboot,
                                  static_cast<long>(magic1),
                                  static_cast<long>(magic2),
                                  static_cast<long>(cmd),
                                  reinterpret_cast<long>(arg)));
#else
    (void) magic1;
    (void) magic2;
    (void) cmd;
    (void) arg;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_ioctl(int fd, unsigned long request, unsigned long arg) {
#if defined(__NR_ioctl)
    long ret;
    do {
        ret = raw_syscall3(__NR_ioctl, fd,
                           static_cast<long>(request),
                           static_cast<long>(arg));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) fd;
    (void) request;
    (void) arg;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_socket(int domain, int type, int protocol) {
#if defined(__NR_socket)
    return normalize(raw_syscall3(__NR_socket, domain, type, protocol));
#else
    (void) domain;
    (void) type;
    (void) protocol;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr == nullptr && addrlen > 0) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_bind)
    long ret;
    do {
        ret = raw_syscall3(__NR_bind, sockfd,
                           reinterpret_cast<long>(addr),
                           static_cast<long>(addrlen));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) sockfd;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    if ((buf == nullptr && len > 0) || (dest_addr == nullptr && addrlen > 0)) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_sendto)
    long ret;
    do {
        ret = raw_syscall6(__NR_sendto, sockfd,
                           reinterpret_cast<long>(buf),
                           static_cast<long>(len),
                           flags,
                           reinterpret_cast<long>(dest_addr),
                           static_cast<long>(addrlen));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) sockfd;
    (void) flags;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    if (buf == nullptr && len > 0) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_recvfrom)
    long ret;
    do {
        ret = raw_syscall6(__NR_recvfrom, sockfd,
                           reinterpret_cast<long>(buf),
                           static_cast<long>(len),
                           flags,
                           reinterpret_cast<long>(src_addr),
                           reinterpret_cast<long>(addrlen));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) sockfd;
    (void) flags;
    (void) src_addr;
    (void) addrlen;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_openat2(int dirfd, const char *path, const void *how, size_t size) {
    if (path == nullptr || how == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_openat2)
    long ret;
    do {
        ret = raw_syscall4(__NR_openat2, dirfd,
                           reinterpret_cast<long>(path),
                           reinterpret_cast<long>(how),
                           static_cast<long>(size));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) dirfd;
    (void) size;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_memfd_create(const char *name, unsigned int flags) {
    if (name == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_memfd_create)
    return normalize(raw_syscall2(__NR_memfd_create,
                                  reinterpret_cast<long>(name),
                                  static_cast<long>(flags)));
#else
    (void) flags;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_pidfd_open(pid_t pid, unsigned int flags) {
#if defined(__NR_pidfd_open)
    return normalize(raw_syscall2(__NR_pidfd_open,
                                  static_cast<long>(pid),
                                  static_cast<long>(flags)));
#else
    (void) pid;
    (void) flags;
    g_raw_errno = ENOSYS;
    return -1;
#endif
}

long my_renameat2(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, unsigned int flags) {
    if (oldpath == nullptr || newpath == nullptr) {
        g_raw_errno = EFAULT;
        return -1;
    }
#if defined(__NR_renameat2)
    long ret;
    do {
        ret = raw_syscall5(__NR_renameat2, olddirfd,
                           reinterpret_cast<long>(oldpath),
                           newdirfd,
                           reinterpret_cast<long>(newpath),
                           static_cast<long>(flags));
    } while (is_error(ret) && (-ret) == EINTR);
    return normalize(ret);
#else
    (void) olddirfd;
    (void) newdirfd;
    (void) flags;
    g_raw_errno = ENOSYS;
    return -1;
#endif
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

    my_memset(buf, 0, bufsize);
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
