#include "raw_dir.h"
#include "syscall_wrapper.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <utility>
#include <unistd.h>

namespace {
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

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

    char buffer[4096];
    while (true) {
        long n = my_getdents64(fd, buffer, sizeof(buffer));
        if (n == 0) break;
        if (n < 0) {
            result.error = raw_last_error();
            if (result.error == 0) result.error = EIO;
            my_close(fd);
            return result;
        }
        if (static_cast<size_t>(n) > sizeof(buffer)) {
            result.error = EIO;
            my_close(fd);
            return result;
        }
        size_t pos = 0;
        const size_t bytes_read = static_cast<size_t>(n);
        constexpr size_t kNameOffset = offsetof(linux_dirent64, d_name);
        while (pos < bytes_read) {
            if (bytes_read - pos < kNameOffset + 1) {
                result.error = EIO;
                my_close(fd);
                return result;
            }
            uint16_t raw_record_length = 0;
            std::memcpy(&raw_record_length,
                        buffer + pos + offsetof(linux_dirent64, d_reclen),
                        sizeof(raw_record_length));
            const size_t record_length = raw_record_length;
            if (record_length < kNameOffset + 1 || record_length > bytes_read - pos) {
                result.error = EIO;
                my_close(fd);
                return result;
            }
            const size_t name_capacity = record_length - kNameOffset;
            const char *name_begin = buffer + pos + kNameOffset;
            const void *terminator = std::memchr(name_begin, '\0', name_capacity);
            if (terminator == nullptr) {
                result.error = EIO;
                my_close(fd);
                return result;
            }
            const size_t name_length = static_cast<const char *>(terminator) - name_begin;
            std::string name(name_begin, name_length);
            if (!name.empty() && name != "." && name != "..") {
                result.names.push_back(std::move(name));
            }
            pos += record_length;
        }
    }
    my_close(fd);
    return result;
}
