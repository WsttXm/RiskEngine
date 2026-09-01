#include "raw_dir.h"
#include "syscall_wrapper.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>

namespace {
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

bool is_dot(const char *name) {
    return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}
}  // namespace

RawDirResult raw_list_dir(const char *path) {
    RawDirResult result;
    if (path == nullptr) {
        result.error = EFAULT;
        return result;
    }
    int fd = static_cast<int>(my_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) {
        result.error = raw_last_error();
        if (result.error == 0) result.error = ENOENT;
        return result;
    }

    alignas(linux_dirent64) char buffer[4096];
    while (true) {
        long n = my_getdents64(fd, buffer, sizeof(buffer));
        if (n == 0) break;
        if (n < 0) {
            result.error = raw_last_error();
            if (result.error == 0) result.error = EIO;
            my_close(fd);
            return result;
        }
        long pos = 0;
        while (pos < n) {
            auto *entry = reinterpret_cast<linux_dirent64 *>(buffer + pos);
            if (entry->d_reclen == 0) break;
            if (!is_dot(entry->d_name)) {
                result.names.emplace_back(entry->d_name);
            }
            pos += entry->d_reclen;
        }
    }
    my_close(fd);
    return result;
}
