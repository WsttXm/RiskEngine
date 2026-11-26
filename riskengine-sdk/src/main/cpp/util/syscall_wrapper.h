#ifndef RISKENGINE_SYSCALL_WRAPPER_H
#define RISKENGINE_SYSCALL_WRAPPER_H

#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#ifdef __cplusplus
extern "C" {
#endif

int raw_last_error(void);

long my_openat(int dirfd, const char *path, int flags, mode_t mode);
long my_read(int fd, void *buf, size_t count);
long my_pread64(int fd, void *buf, size_t count, uint64_t offset);
long my_close(int fd);
long my_lseek(int fd, long offset, int whence);
/* Uses 3-arg __NR_faccessat when flags == 0, or 4-arg __NR_faccessat2 when flags != 0. */
long my_faccessat(int dirfd, const char *path, int mode, int flags);
long my_access(const char *path, int mode);
long my_fstatat(int dirfd, const char *path, struct stat *st, int flags);
long my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz);
long my_getdents64(int fd, void *buf, size_t count);
/* Uses __NR_statfs64 on 32-bit ARM/i386 ABIs and __NR_statfs on 64-bit ABIs. */
long my_statfs(const char *path, struct statfs *buf);
long my_uname(struct utsname *buf);
long my_mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
long my_munmap(void *addr, size_t length);
long my_prctl(int option, unsigned long a2, unsigned long a3,
              unsigned long a4, unsigned long a5);
long my_getppid(void);
long my_gettid(void);

/* Phase 2 4-ABI raw syscall extensions */
long my_getcpu(unsigned *cpu, unsigned *node);
long my_statx(int dirfd, const char *path, int flags, unsigned int mask, void *stx_buf);
long my_getxattr(const char *path, const char *name, void *value, size_t size);
long my_lgetxattr(const char *path, const char *name, void *value, size_t size);
long my_truncate(const char *path, off_t length);
long my_mincore(void *addr, size_t length, unsigned char *vec);
long my_setresuid(uid_t ruid, uid_t euid, uid_t suid);
long my_reboot(unsigned int magic1, unsigned int magic2, unsigned int cmd, void *arg);
long my_ioctl(int fd, unsigned long request, unsigned long arg);
long my_socket(int domain, int type, int protocol);
long my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
long my_sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);
long my_recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);
long my_openat2(int dirfd, const char *path, const void *how, size_t size);
long my_memfd_create(const char *name, unsigned int flags);
long my_pidfd_open(pid_t pid, unsigned int flags);
long my_renameat2(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, unsigned int flags);

int read_file_content(const char *path, char *buf, size_t bufsize);

#ifdef __cplusplus
}  // extern "C"

#include <string>

/**
 * Reads a whole procfs/sysfs file that reports no size via stat, growing the
 * buffer as needed. Returns an empty string on failure. Capped by max_bytes.
 */
std::string read_file_string(const char *path, size_t max_bytes = 1024 * 1024);

#endif  // __cplusplus

#endif  // RISKENGINE_SYSCALL_WRAPPER_H
