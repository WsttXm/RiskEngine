#include "maps_parser.h"
#include "syscall_wrapper.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <limits>
#include <sstream>
#include <unistd.h>

namespace {
std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool parse_address(const std::string &value, uintptr_t &out) {
    if (value.empty()) return false;
    errno = 0;
    char *end = nullptr;
    unsigned long long parsed = std::strtoull(value.c_str(), &end, 16);
    if (errno == ERANGE || end == value.c_str() || *end != '\0'
            || parsed > std::numeric_limits<uintptr_t>::max()) {
        return false;
    }
    out = static_cast<uintptr_t>(parsed);
    return true;
}
}  // namespace

std::vector<MapEntry> read_self_maps() {
    std::vector<MapEntry> entries;
    constexpr size_t kMaxMapsBytes = 2 * 1024 * 1024;
    long fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
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

    std::istringstream maps(maps_content);
    std::string line;
    while (std::getline(maps, line)) {
        MapEntry entry;
        entry.raw = line;
        std::istringstream iss(line);
        std::string range;
        std::string offset;
        std::string dev;
        std::string inode;
        if (!(iss >> range >> entry.perms >> offset >> dev >> inode)) {
            continue;
        }
        auto dash = range.find('-');
        if (dash == std::string::npos) {
            continue;
        }
        if (!parse_address(range.substr(0, dash), entry.start)
                || !parse_address(range.substr(dash + 1), entry.end)
                || entry.start >= entry.end) {
            continue;
        }
        std::string path;
        std::getline(iss, path);
        if (!path.empty() && path[0] == ' ') {
            path.erase(0, 1);
        }
        entry.path = path;
        entries.push_back(entry);
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
