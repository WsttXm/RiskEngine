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

}  // namespace

std::vector<MapEntry> read_self_maps() {
    std::vector<MapEntry> entries;
    constexpr size_t kMaxMapsBytes = 2 * 1024 * 1024;
    long fd = my_openat(AT_FDCWD, OBF("/proc/self/maps").c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return entries;
    }
    std::string maps_content;
    maps_content.reserve(64 * 1024);
    char buffer[8192];
    while (maps_content.size() < kMaxMapsBytes) {
        size_t remaining = kMaxMapsBytes - maps_content.size();
        long count = my_read(static_cast<int>(fd), buffer,
                             std::min(sizeof(buffer), remaining));
        if (count < 0 && raw_last_error() == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        maps_content.append(buffer, static_cast<size_t>(count));
    }
    my_close(static_cast<int>(fd));

    const char *cur = maps_content.data();
    const char *const end = cur + maps_content.size();
    entries.reserve(256);

    while (cur < end) {
        const char *nl = static_cast<const char *>(std::memchr(cur, '\n', static_cast<size_t>(end - cur)));
        const char *line_end = nl != nullptr ? nl : end;
        const char *next_line = nl != nullptr ? nl + 1 : end;

        // Strip optional trailing '\r'
        const char *trimmed_end = line_end;
        if (trimmed_end > cur && trimmed_end[-1] == '\r') --trimmed_end;

        // 1. start-end
        const char *p = skip_spaces(cur, trimmed_end);
        const char *range_end = find_space(p, trimmed_end);
        const char *dash = static_cast<const char *>(std::memchr(p, '-', static_cast<size_t>(range_end - p)));
        if (dash == nullptr) {
            cur = next_line;
            continue;
        }
        uint64_t start64 = 0, end64 = 0;
        if (!parse_hex_u64(p, dash, start64)
                || !parse_hex_u64(dash + 1, range_end, end64)
                || start64 >= end64
                || end64 > std::numeric_limits<uintptr_t>::max()) {
            cur = next_line;
            continue;
        }

        // 2. perms
        p = skip_spaces(range_end, trimmed_end);
        const char *perms_end = find_space(p, trimmed_end);
        if (perms_end <= p) {
            cur = next_line;
            continue;
        }
        const char *perms_begin = p;

        // 3. offset
        p = skip_spaces(perms_end, trimmed_end);
        const char *off_end = find_space(p, trimmed_end);
        uint64_t offset64 = 0;
        if (!parse_hex_u64(p, off_end, offset64)) {
            cur = next_line;
            continue;
        }

        // 4. dev
        p = skip_spaces(off_end, trimmed_end);
        const char *dev_end = find_space(p, trimmed_end);
        if (dev_end <= p) {
            cur = next_line;
            continue;
        }

        // 5. inode
        p = skip_spaces(dev_end, trimmed_end);
        const char *inode_end = find_space(p, trimmed_end);
        uint64_t inode64 = 0;
        if (inode_end <= p || !parse_dec_u64(p, inode_end, inode64)) {
            cur = next_line;
            continue;
        }

        // 6. optional path
        const char *path_begin = skip_spaces(inode_end, trimmed_end);

        MapEntry entry;
        entry.start = static_cast<uintptr_t>(start64);
        entry.end = static_cast<uintptr_t>(end64);
        entry.offset = offset64;
        entry.inode = inode64;
        entry.perms.assign(perms_begin, static_cast<size_t>(perms_end - perms_begin));
        if (path_begin < trimmed_end) {
            entry.path.assign(path_begin, static_cast<size_t>(trimmed_end - path_begin));
        }
        entry.raw.assign(cur, static_cast<size_t>(trimmed_end - cur));
        entries.push_back(std::move(entry));

        cur = next_line;
    }
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
