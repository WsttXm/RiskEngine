#ifndef RISKENGINE_SYSCALL_WRAPPER_H
#define RISKENGINE_SYSCALL_WRAPPER_H

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
long my_close(int fd);
long my_lseek(int fd, long offset, int whence);
long my_faccessat(int dirfd, const char *path, int mode, int flags);
long my_access(const char *path, int mode);
long my_fstatat(int dirfd, const char *path, struct stat *st, int flags);
long my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz);
long my_getdents64(int fd, void *buf, size_t count);
long my_statfs(const char *path, struct statfs *buf);
long my_uname(struct utsname *buf);
long my_mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
long my_munmap(void *addr, size_t length);
long my_prctl(int option, unsigned long a2, unsigned long a3,
              unsigned long a4, unsigned long a5);
long my_getppid(void);
long my_gettid(void);

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
