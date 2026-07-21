#ifndef RISKENGINE_SYSCALL_WRAPPER_H
#define RISKENGINE_SYSCALL_WRAPPER_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

long my_openat(int dirfd, const char *path, int flags, mode_t mode);
long my_read(int fd, void *buf, size_t count);
long my_close(int fd);
long my_access(const char *path, int mode);

// Helper to read entire file content
int read_file_content(const char *path, char *buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif  // RISKENGINE_SYSCALL_WRAPPER_H
