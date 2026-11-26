#ifndef RISKENGINE_MAPS_PARSER_H
#define RISKENGINE_MAPS_PARSER_H

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uint64_t offset = 0;
    uint64_t inode = 0;
    std::string perms;
    std::string path;
    std::string raw;
};

using MapEntryVisitor = bool (*)(const MapEntry &entry, void *ctx);

/**
 * Streams /proc/self/maps line-by-line with a fixed read buffer and bounded
 * per-line buffer (no total-file truncation limit). Stops early when visitor
 * returns false. Returns true if /proc/self/maps was opened successfully.
 */
bool for_each_self_map(MapEntryVisitor visitor, void *ctx);

template<typename Fn>
inline bool for_each_self_map(Fn &&fn) {
    using DecayedFn = std::remove_reference_t<Fn>;
    return for_each_self_map(
            [](const MapEntry &entry, void *raw) -> bool {
                return (*static_cast<DecayedFn *>(raw))(entry);
            },
            const_cast<void *>(static_cast<const void *>(&fn)));
}

bool find_self_map_containing(uintptr_t addr, MapEntry &out);
std::vector<MapEntry> read_self_maps();
bool maps_path_contains(const MapEntry &entry, const std::string &needle);
bool is_rx(const MapEntry &entry);
const MapEntry *find_map_containing(const std::vector<MapEntry> &maps, uintptr_t addr);
const MapEntry *find_so_map(const std::vector<MapEntry> &maps, const std::string &so_name);

#endif
