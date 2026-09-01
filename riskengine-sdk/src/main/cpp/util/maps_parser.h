#ifndef RISKENGINE_MAPS_PARSER_H
#define RISKENGINE_MAPS_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    std::string perms;
    std::string path;
    std::string raw;
};

std::vector<MapEntry> read_self_maps();
bool maps_path_contains(const MapEntry &entry, const std::string &needle);
bool is_rx(const MapEntry &entry);
const MapEntry *find_map_containing(const std::vector<MapEntry> &maps, uintptr_t addr);
const MapEntry *find_so_map(const std::vector<MapEntry> &maps, const std::string &so_name);

#endif
