#include "maps_parser.h"
#include "obf_str.h"
#include "syscall_wrapper.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <unistd.h>

namespace {

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool parse_hex_u64(const char *begin, const char *end, uint64_t &out) {
    if (begin == nullptr || begin >= end) return false;
    uint64_t val = 0;
    for (const char *p = begin; p < end; ++p) {
        unsigned int digit;
        const char c = *p;
        if (c >= '0' && c <= '9') {
            digit = static_cast<unsigned int>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<unsigned int>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<unsigned int>(c - 'A' + 10);
        } else {
            return false;
        }
        if (val > (std::numeric_limits<uint64_t>::max() - digit) / 16ull) {
            return false;
        }
        val = (val << 4) | digit;
    }
    out = val;
    return true;
}

bool parse_dec_u64(const char *begin, const char *end, uint64_t &out) {
    if (begin == nullptr || begin >= end) return false;
    uint64_t val = 0;
    for (const char *p = begin; p < end; ++p) {
        const char c = *p;
        if (c < '0' || c > '9') return false;
        const unsigned int digit = static_cast<unsigned int>(c - '0');
        if (val > (std::numeric_limits<uint64_t>::max() - digit) / 10ull) {
            return false;
        }
        val = val * 10ull + digit;
    }
    out = val;
    return true;
}

inline const char *skip_spaces(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    return p;
}

inline const char *find_space(const char *p, const char *end) {
    while (p < end && *p != ' ' && *p != '\t') ++p;
    return p;
}

bool parse_map_line(const char *begin, const char *end, MapEntry &entry) {
    if (begin == nullptr || begin >= end) return false;

    const char *trimmed_end = end;
    if (trimmed_end > begin && trimmed_end[-1] == '\r') --trimmed_end;
    if (trimmed_end <= begin) return false;

    // 1. start-end
    const char *p = skip_spaces(begin, trimmed_end);
    const char *range_end = find_space(p, trimmed_end);
    const char *dash = static_cast<const char *>(
            std::memchr(p, '-', static_cast<size_t>(range_end - p)));
    if (dash == nullptr) return false;

    uint64_t start64 = 0;
    uint64_t end64 = 0;
    if (!parse_hex_u64(p, dash, start64)
            || !parse_hex_u64(dash + 1, range_end, end64)
            || start64 >= end64
            || end64 > std::numeric_limits<uintptr_t>::max()) {
        return false;
    }

    // 2. perms
    p = skip_spaces(range_end, trimmed_end);
    const char *perms_end = find_space(p, trimmed_end);
    if (perms_end <= p) return false;
    const char *perms_begin = p;

    // 3. offset
    p = skip_spaces(perms_end, trimmed_end);
    const char *off_end = find_space(p, trimmed_end);
    uint64_t offset64 = 0;
    if (!parse_hex_u64(p, off_end, offset64)) return false;

    // 4. dev
    p = skip_spaces(off_end, trimmed_end);
    const char *dev_end = find_space(p, trimmed_end);
    if (dev_end <= p) return false;

    // 5. inode
    p = skip_spaces(dev_end, trimmed_end);
    const char *inode_end = find_space(p, trimmed_end);
    uint64_t inode64 = 0;
    if (inode_end <= p || !parse_dec_u64(p, inode_end, inode64)) return false;

    // 6. optional path
    const char *path_begin = skip_spaces(inode_end, trimmed_end);

    entry.start = static_cast<uintptr_t>(start64);
    entry.end = static_cast<uintptr_t>(end64);
    entry.offset = offset64;
    entry.inode = inode64;
    entry.perms.assign(perms_begin, static_cast<size_t>(perms_end - perms_begin));
    if (path_begin < trimmed_end) {
        entry.path.assign(path_begin, static_cast<size_t>(trimmed_end - path_begin));
    } else {
        entry.path.clear();
    }
    entry.raw.assign(begin, static_cast<size_t>(trimmed_end - begin));
    return true;
}

}  // namespace

bool for_each_self_map(MapEntryVisitor visitor, void *ctx) {
    if (visitor == nullptr) return false;

    long fd = my_openat(AT_FDCWD, OBF("/proc/self/maps").c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }

    constexpr size_t kReadChunkBytes = 8192;
    constexpr size_t kMaxLineBytes = 4096;

    char chunk[kReadChunkBytes];
    std::string line_buf;
    line_buf.reserve(512);
    MapEntry reusable;
    bool discarding_overflow_line = false;
    bool stop = false;
    bool read_error = false;

    auto dispatch_line = [&](const char *begin, const char *end) {
        if (parse_map_line(begin, end, reusable)) {
            if (!visitor(reusable, ctx)) {
                stop = true;
            }
        }
    };

    while (!stop) {
        long count = my_read(static_cast<int>(fd), chunk, sizeof(chunk));
        if (count < 0) {
            if (raw_last_error() == EINTR) {
                continue;
            }
            read_error = true;
            break;
        }
        if (count == 0) {
            break;
        }

        const char *cur = chunk;
        const char *const end = chunk + static_cast<size_t>(count);

        while (cur < end && !stop) {
            const char *nl = static_cast<const char *>(
                    std::memchr(cur, '\n', static_cast<size_t>(end - cur)));
            const char *seg_end = nl != nullptr ? nl : end;
            const size_t seg_len = static_cast<size_t>(seg_end - cur);

            if (discarding_overflow_line) {
                if (nl != nullptr) {
                    discarding_overflow_line = false;
                    line_buf.clear();
                    cur = nl + 1;
                } else {
                    cur = end;
                }
                continue;
            }

            if (nl != nullptr && line_buf.empty()) {
                // Fast path: complete line sits inside chunk with zero copy into line_buf.
                if (seg_len <= kMaxLineBytes) {
                    dispatch_line(cur, seg_end);
                }
                cur = nl + 1;
                continue;
            }

            if (line_buf.size() + seg_len > kMaxLineBytes) {
                // Bound memory per malformed ultra-long line; skip until next '\n'.
                line_buf.clear();
                if (nl != nullptr) {
                    cur = nl + 1;
                } else {
                    discarding_overflow_line = true;
                    cur = end;
                }
                continue;
            }

            line_buf.append(cur, seg_len);
            if (nl != nullptr) {
                dispatch_line(line_buf.data(), line_buf.data() + line_buf.size());
                line_buf.clear();
                cur = nl + 1;
            } else {
                cur = end;
            }
        }
    }

    if (!stop && !read_error && !discarding_overflow_line && !line_buf.empty()) {
        dispatch_line(line_buf.data(), line_buf.data() + line_buf.size());
    }

    my_close(static_cast<int>(fd));
    return true;
}

bool find_self_map_containing(uintptr_t addr, MapEntry &out) {
    bool found = false;
    for_each_self_map([&](const MapEntry &entry) -> bool {
        if (addr >= entry.start && addr < entry.end) {
            out = entry;
            found = true;
            return false;
        }
        return true;
    });
    return found;
}

std::vector<MapEntry> read_self_maps() {
    std::vector<MapEntry> entries;
    entries.reserve(256);
    for_each_self_map([&](const MapEntry &entry) -> bool {
        entries.push_back(entry);
        return true;
    });
    return entries;
}

bool maps_path_contains(const MapEntry &entry, const std::string &needle) {
    return to_lower(entry.raw).find(to_lower(needle)) != std::string::npos;
}

bool is_rx(const MapEntry &entry) {
    return entry.perms.size() >= 3 && entry.perms[0] == 'r' && entry.perms[2] == 'x';
}

const MapEntry *find_map_containing(const std::vector<MapEntry> &maps, uintptr_t addr) {
    for (const auto &entry : maps) {
        if (addr >= entry.start && addr < entry.end) {
            return &entry;
        }
    }
    return nullptr;
}

const MapEntry *find_so_map(const std::vector<MapEntry> &maps, const std::string &so_name) {
    const MapEntry *best = nullptr;
    for (const auto &entry : maps) {
        if (!is_rx(entry)) continue;
        if (entry.path.find(so_name) != std::string::npos) {
            if (best == nullptr || entry.start < best->start) {
                best = &entry;
            }
        }
    }
    return best;
}
