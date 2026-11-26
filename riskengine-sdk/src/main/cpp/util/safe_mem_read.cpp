#include "safe_mem_read.h"
#include "obf_str.h"
#include "raw_syscall.h"
#include "syscall_wrapper.h"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <sys/syscall.h>

namespace safe_mem {
namespace {

constexpr uint64_t kPagePresentMask = 1ULL << 63;
constexpr uint64_t kPageSwappedMask = 1ULL << 62;
constexpr uint64_t kPageFileOrSharedAnonMask = 1ULL << 61;

constexpr size_t kPagemapEntriesPerBatch = 512;  // 512 * 8 = 4 KiB stack buffer

inline bool is_syscall_error(long ret) noexcept {
    return ret < 0 && ret > -4096;
}

long raw_pipe2_cloexec_nonblock(int fds[2]) noexcept {
#if defined(__NR_pipe2)
    long ret;
    do {
        ret = raw_syscall2(__NR_pipe2, reinterpret_cast<long>(fds),
                           O_CLOEXEC | O_NONBLOCK);
    } while (is_syscall_error(ret) && (-ret) == EINTR);
    return ret;
#else
#error "__NR_pipe2 syscall number missing"
#endif
}

long raw_write_retry(int fd, const void *buf, size_t count) noexcept {
    long ret;
    do {
        ret = raw_syscall3(__NR_write, fd, reinterpret_cast<long>(buf),
                           static_cast<long>(count));
    } while (is_syscall_error(ret) && (-ret) == EINTR);
    return ret;
}

long raw_read_retry(int fd, void *buf, size_t count) noexcept {
    long ret;
    do {
        ret = raw_syscall3(__NR_read, fd, reinterpret_cast<long>(buf),
                           static_cast<long>(count));
    } while (is_syscall_error(ret) && (-ret) == EINTR);
    return ret;
}

PageResidency classify_pagemap_entry(uint64_t entry) noexcept {
    if ((entry & kPagePresentMask) != 0) {
        return (entry & kPageFileOrSharedAnonMask) != 0
                ? PageResidency::FILE_PAGE
                : PageResidency::ANONYMOUS_PAGE;
    }
    return (entry & kPageSwappedMask) != 0
            ? PageResidency::SWAPPED
            : PageResidency::NOT_PRESENT;
}

constexpr size_t kMinValidPageSize = 4096;
constexpr uint64_t kMaxPagemapPageIndex =
        static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) / sizeof(uint64_t);

bool is_valid_page_size(size_t value) noexcept {
    return value >= kMinValidPageSize && (value & (value - 1)) == 0;
}

}  // namespace

void ScopedFd::reset(int new_fd) noexcept {
    if (fd_ == new_fd) {
        return;
    }
    if (fd_ >= 0) {
        my_close(fd_);
    }
    fd_ = new_fd;
}

PagemapReader::PagemapReader() noexcept {
    long fd = my_openat(AT_FDCWD, OBF("/proc/self/pagemap").c_str(),
                        O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0) {
        fd_.reset(static_cast<int>(fd));
    }
}

bool PagemapReader::read_pages(uintptr_t start,
                               size_t page_count,
                               size_t page_size,
                               std::vector<PageResidency> &out) const {
    out.clear();
    if (!available() || !is_valid_page_size(page_size)) {
        return false;
    }
    if (page_count == 0) {
        return true;
    }

    // Prevent virtual address wraparound on [aligned_start, aligned_start + page_count * page_size).
    const uintptr_t aligned_start = start & ~(static_cast<uintptr_t>(page_size) - 1u);
    const size_t max_addr_pages =
            static_cast<size_t>((std::numeric_limits<uintptr_t>::max() - aligned_start)
                                / page_size) + 1u;
    if (page_count > max_addr_pages) {
        return false;
    }

    // Prevent unsigned underflow and loff_t (int64_t) offset overflow in pread64.
    const uint64_t first_page =
            static_cast<uint64_t>(aligned_start) / static_cast<uint64_t>(page_size);
    if (first_page > kMaxPagemapPageIndex
            || static_cast<uint64_t>(page_count) > kMaxPagemapPageIndex - first_page) {
        return false;
    }

    out.reserve(std::min(page_count, kPagemapEntriesPerBatch));
    uint64_t entries[kPagemapEntriesPerBatch] = {};
    size_t done = 0;

    while (done < page_count) {
        const size_t batch = std::min(kPagemapEntriesPerBatch, page_count - done);
        const size_t bytes = batch * sizeof(uint64_t);
        const uint64_t offset = (first_page + static_cast<uint64_t>(done)) * sizeof(uint64_t);

        const long got = my_pread64(fd_.get(), entries, bytes, offset);
        if (got != static_cast<long>(bytes)) {
            out.clear();
            return false;
        }
        for (size_t i = 0; i < batch; ++i) {
            out.push_back(classify_pagemap_entry(entries[i]));
        }
        done += batch;
    }
    return true;
}

bool PagemapReader::is_page_cow_anonymous(uintptr_t addr,
                                          size_t page_size,
                                          bool &is_cow_anonymous) const {
    is_cow_anonymous = false;
    if (!available() || !is_valid_page_size(page_size)) {
        return false;
    }
    const uint64_t page_idx = static_cast<uint64_t>(addr) / static_cast<uint64_t>(page_size);
    if (page_idx >= kMaxPagemapPageIndex) {
        return false;
    }
    uint64_t entry = 0;
    const long got = my_pread64(fd_.get(), &entry, sizeof(entry), page_idx * sizeof(uint64_t));
    if (got != static_cast<long>(sizeof(entry))) {
        return false;
    }
    const PageResidency residency = classify_pagemap_entry(entry);
    is_cow_anonymous = (residency == PageResidency::ANONYMOUS_PAGE
            || residency == PageResidency::SWAPPED);
    return true;
}

PipeMemoryReader::PipeMemoryReader() noexcept {
    int fds[2] = {-1, -1};
    if (raw_pipe2_cloexec_nonblock(fds) >= 0 && fds[0] >= 0 && fds[1] >= 0) {
        read_end_.reset(fds[0]);
        write_end_.reset(fds[1]);
    }
}

bool PipeMemoryReader::read(uintptr_t address, void *out, size_t size) noexcept {
    if (size == 0) {
        return out != nullptr && available();
    }
    if (!available() || out == nullptr || address == 0) {
        return false;
    }
    if (size > std::numeric_limits<uintptr_t>::max() - address) {
        return false;
    }

    auto *dst = static_cast<uint8_t *>(out);
    size_t done = 0;
    while (done < size) {
        const size_t chunk = std::min(kChunkBytes, size - done);
        const long written = raw_write_retry(
                write_end_.get(),
                reinterpret_cast<const void *>(address + done),
                chunk);
        if (written <= 0 || static_cast<size_t>(written) > chunk) {
            drain();
            return false;
        }

        const auto expected = static_cast<size_t>(written);
        size_t copied = 0;
        while (copied < expected) {
            const long got = raw_read_retry(
                    read_end_.get(), dst + done + copied, expected - copied);
            if (got <= 0 || static_cast<size_t>(got) > expected - copied) {
                drain();
                return false;
            }
            copied += static_cast<size_t>(got);
        }
        done += expected;
    }
    return true;
}

void PipeMemoryReader::drain() noexcept {
    if (!read_end_.valid()) {
        return;
    }
    uint8_t sink[kChunkBytes] = {};
    while (raw_read_retry(read_end_.get(), sink, sizeof(sink)) > 0) {
        // Discard any leftover bytes so subsequent reads start from an empty pipe.
    }
}

bool safe_mem_read(uintptr_t address, void *out, size_t size) noexcept {
    PipeMemoryReader reader;
    return reader.read(address, out, size);
}

}  // namespace safe_mem
