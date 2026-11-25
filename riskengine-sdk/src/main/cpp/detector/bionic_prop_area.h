#ifndef RISKENGINE_BIONIC_PROP_AREA_H
#define RISKENGINE_BIONIC_PROP_AREA_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace riskengine {
namespace prop_forensics {

constexpr uint32_t kPropAreaMagic = 0x504f5250U;
constexpr uint32_t kPropAreaVersion = 0xfc6ed0abU;
constexpr uint32_t kLongFlag = 1U << 16;
constexpr std::size_t kByteAlignment = 4;
constexpr std::size_t kPropValueMax = 92;
constexpr std::size_t kDirtyBackupAreaSize = kPropValueMax;
constexpr int kDirtyBackupMinSdk = 30;

struct DiskPropAreaHeader {
    uint32_t bytes_used;
    uint32_t serial;
    uint32_t magic;
    uint32_t version;
    uint32_t reserved[28];
};

struct DiskPropTrieNode {
    uint32_t namelen;
    uint32_t prop;
    uint32_t left;
    uint32_t right;
    uint32_t children;
};

struct DiskLongProperty {
    char error_message[56];
    uint32_t offset;
};

struct DiskPropInfo {
    uint32_t serial;
    union {
        char value[kPropValueMax];
        DiskLongProperty long_property;
    };
};

struct DiskPropertyInfoHeader {
    uint32_t current_version;
    uint32_t minimum_supported_version;
    uint32_t size;
    uint32_t contexts_offset;
    uint32_t types_offset;
    uint32_t root_offset;
};

static_assert(sizeof(DiskPropAreaHeader) == 128, "DiskPropAreaHeader layout mismatch");
static_assert(sizeof(DiskPropTrieNode) == 20, "DiskPropTrieNode layout mismatch");
static_assert(sizeof(DiskLongProperty) == 60, "DiskLongProperty layout mismatch");
static_assert(sizeof(DiskPropInfo) == 96, "DiskPropInfo layout mismatch");
static_assert(sizeof(DiskPropertyInfoHeader) == 24, "DiskPropertyInfoHeader layout mismatch");

struct HoleRun {
    uint32_t offset = 0;
    uint32_t length = 0;
};

struct RoSerialAnomaly {
    std::string prop_name;
    uint32_t serial = 0;
    uint32_t write_count = 0;
};

struct RoNulTailAnomaly {
    std::string prop_name;
    std::string clean_value;
    uint32_t nonzero_trailing_bytes = 0;
};

struct AreaAnalysisResult {
    bool parsed = false;
    uint32_t ro_checked = 0;
    std::vector<HoleRun> holes;
    std::vector<RoSerialAnomaly> serial_anomalies;
    std::vector<RoNulTailAnomaly> nul_tail_anomalies;
};

/**
 * Parses a read-only Bionic prop_area file image in memory (starting at DiskPropAreaHeader).
 *
 * Strictly gates the 92-byte dirty_backup_area reservation on sdk_level >= 30.
 * Never touches st_mtime. Performs full bounds and cycle validation on every offset.
 */
AreaAnalysisResult analyze_prop_area_image(const uint8_t *image,
                                           std::size_t image_size,
                                           int sdk_level);

/**
 * Parses an AOSP /dev/__properties__/property_info binary image and extracts the
 * deduplicated list of SELinux context file names (e.g. "u:object_r:default_prop:s0")
 * with strict bounds and path-safety validation.
 *
 * Used on Android 8+ where /dev/__properties__ has mode 0711 (drwx--x--x, no directory
 * listing) while property_info and individual context area files are 0444 readable.
 */
bool parse_property_info_contexts(const uint8_t *image,
                                  std::size_t image_size,
                                  std::vector<std::string> &contexts_out);

/**
 * Returns true if the property name belongs to the 18 security-critical read-only ro.* set.
 */
bool is_security_critical_ro_prop(const char *name, std::size_t len);

/**
 * Returns true if the prop_area context name is a high-priority target for resetprop --delete
 * (e.g. adbd_config_prop or shell_prop).
 */
bool is_high_priority_hole_context(const char *context, std::size_t len);

}  // namespace prop_forensics
}  // namespace riskengine

/**
 * Scans /dev/__properties__ strictly O_RDONLY and emits a NativePayloadCodec frame.
 */
std::string native_get_bionic_prop_forensics();

#endif  // RISKENGINE_BIONIC_PROP_AREA_H
