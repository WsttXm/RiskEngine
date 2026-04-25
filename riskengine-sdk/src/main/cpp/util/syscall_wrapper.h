#ifndef RISKENGINE_SYSCALL_WRAPPER_H
#define RISKENGINE_SYSCALL_WRAPPER_H

#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

long my_openat(int dirfd, const char *path, int flags, mode_t mode);
long my_read(int fd, void *buf, size_t count);
long my_write(int fd, const void *buf, size_t count);
long my_close(int fd);
long my_lseek(int fd, off_t offset, int whence);
long my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsize);
long my_fstat(int fd, struct stat *statbuf);
long my_access(const char *path, int mode);
long my_getdents64(int fd, void *dirp, size_t count);

// Helper to read entire file content
int read_file_content(const char *path, char *buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif // RISKENGINE_SYSCALL_WRAPPER_H
