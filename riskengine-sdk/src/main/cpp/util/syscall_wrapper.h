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

int read_file_content(const char *path, char *buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif
