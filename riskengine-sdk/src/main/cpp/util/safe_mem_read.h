#ifndef RISKENGINE_SAFE_MEM_READ_H
#define RISKENGINE_SAFE_MEM_READ_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace safe_mem {

/**
 * RAII file descriptor closed via raw syscall (my_close).
 */
class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
    ~ScopedFd() noexcept { reset(); }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    ScopedFd(ScopedFd &&other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    ScopedFd &operator=(ScopedFd &&other) noexcept {
        if (this != &other) {
            reset(other.fd_);
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }
    void reset(int new_fd = -1) noexcept;

private:
    int fd_ = -1;
};

enum class PageResidency : uint8_t {
    NOT_PRESENT = 0,
    SWAPPED = 1,
    FILE_PAGE = 2,
    ANONYMOUS_PAGE = 3,
};

/**
 * Reads /proc/self/pagemap flag bits without pinning pages (avoids forced COW).
 * On Android without CAP_SYS_ADMIN the PFN is zeroed by the kernel, while
 * present (bit 63), swapped (bit 62), and file-or-shared-anon (bit 61) remain
 * readable for COW dirty-page classification.
 */
class PagemapReader {
public:
    PagemapReader() noexcept;

    bool available() const noexcept { return fd_.valid(); }

    /**
     * Classifies [start, start + page_count * page_size) into one PageResidency
     * entry per page. Returns false if pagemap is unavailable or any read fails.
     */
    bool read_pages(uintptr_t start,
                    size_t page_count,
                    size_t page_size,
                    std::vector<PageResidency> &out) const;

    /**
     * Classifies a single virtual address. Sets is_cow_anonymous to true when
     * the page is resident as a private anonymous page or swapped out (indicating
     * a COW break on a file-backed mapping). Returns false if pagemap cannot be
     * read (caller must treat unavailability as non-threatening).
     */
    bool is_page_cow_anonymous(uintptr_t addr,
                               size_t page_size,
                               bool &is_cow_anonymous) const;

private:
    ScopedFd fd_;
};

/**
 * COW-safe, crash-free memory reader backed by a non-blocking pipe2(O_CLOEXEC)
 * pair and fixed 4 KiB kernel copy_from_user chunks.
 *
 * Unlike direct pointer dereference (SIGSEGV on concurrent munmap or XOM) or
 * /proc/self/mem & process_vm_readv (EACCES when non-dumpable / get_user_pages
 * COW pinning), write(2) copies via copy_from_user and safely returns -EFAULT
 * on unmapped or unreadable pages.
 */
class PipeMemoryReader {
public:
    static constexpr size_t kChunkBytes = 4096;

    PipeMemoryReader() noexcept;

    bool available() const noexcept {
        return read_end_.valid() && write_end_.valid();
    }

    /**
     * Copies exactly size bytes from [address, address + size) into out.
     * Returns false if any byte cannot be read (e.g., EFAULT on unmapped/XOM).
     */
    bool read(uintptr_t address, void *out, size_t size) noexcept;

private:
    void drain() noexcept;

    ScopedFd read_end_;
    ScopedFd write_end_;
};

/**
 * One-shot convenience wrapper over PipeMemoryReader.
 * Prefer reusing a PipeMemoryReader instance across batch reads to avoid
 * repeated pipe2/close syscalls.
 */
bool safe_mem_read(uintptr_t address, void *out, size_t size) noexcept;

}  // namespace safe_mem

#endif  // RISKENGINE_SAFE_MEM_READ_H
