#include "bionic_prop_area.h"

#include "../util/mylibc.h"
#include "../util/payload_codec.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <unordered_set>
#include <vector>

#if defined(__ANDROID__)
#include "../util/obf_str.h"
#include "../util/raw_dir.h"
#include "../util/syscall_wrapper.h"
#include <android/api-level.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#endif

namespace riskengine {
namespace prop_forensics {

namespace {

constexpr std::size_t kMaxPropAreaFileSize = 8U * 1024U * 1024U;
constexpr std::size_t kMaxVisitedNodes = 65536U;

constexpr const char *kSecurityCriticalRoProps[18] = {
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.boot.vbmeta.digest",
        "ro.boot.veritymode",
        "ro.boot.warranty_bit",
        "ro.boot.qemu",
        "ro.debuggable",
        "ro.secure",
        "ro.build.tags",
        "ro.build.type",
        "ro.build.fingerprint",
        "ro.build.version.security_patch",
        "ro.adb.secure",
        "ro.oem_unlock_supported",
        "ro.crypto.state",
        "ro.product.model",
        "ro.vendor.boot.warranty_bit",
};

inline bool align_up_checked(std::size_t value, std::size_t *out) {
    if (value > (SIZE_MAX - (kByteAlignment - 1U))) {
        return false;
    }
    *out = (value + (kByteAlignment - 1U)) & ~(kByteAlignment - 1U);
    return true;
}

template <typename T>
bool read_struct_at(const uint8_t *data, std::size_t data_len, uint32_t offset, T *out) {
    if (offset > data_len || sizeof(T) > data_len - offset) {
        return false;
    }
    my_memcpy(out, data + offset, sizeof(T));
    return true;
}

bool bounded_c_string_length(const uint8_t *data,
                             std::size_t data_len,
                             uint32_t offset,
                             std::size_t *out_len) {
    if (offset >= data_len) {
        return false;
    }
    const std::size_t max_scan = data_len - offset;
    for (std::size_t i = 0; i < max_scan; ++i) {
        if (data[offset + i] == 0) {
            *out_len = i;
            return true;
        }
    }
    return false;
}

bool mark_range(uint8_t *occupied,
                std::size_t bytes_used,
                uint32_t offset,
                std::size_t size) {
    if (size == 0) {
        return true;
    }
    if ((offset % kByteAlignment) != 0 || (size % kByteAlignment) != 0) {
        return false;
    }
    if (offset > bytes_used || size > bytes_used - offset) {
        return false;
    }
    my_memset(occupied + offset, 1, size);
    return true;
}

void inspect_critical_ro_property(const DiskPropInfo &prop,
                                  const char *name,
                                  std::size_t name_len,
                                  AreaAnalysisResult &result) {
    if (!is_security_critical_ro_prop(name, name_len)) {
        return;
    }
    result.ro_checked++;

    const bool is_long = (prop.serial & kLongFlag) != 0;
    const uint32_t counter_bits = is_long
            ? ((prop.serial & ~kLongFlag) >> 1) & 0x7FFFFFU
            : (prop.serial >> 1) & 0x7FFFFFU;
    if (counter_bits != 0) {
        RoSerialAnomaly anomaly{};
        anomaly.prop_name.assign(name, name_len);
        anomaly.serial = prop.serial;
        anomaly.write_count = counter_bits;
        result.serial_anomalies.push_back(std::move(anomaly));
    }

    // Only inline short properties carry value[92]; long properties reuse value[92] for
    // DiskLongProperty (error_message[56] + offset).
    if (!is_long) {
        std::size_t nul_pos = kPropValueMax;
        for (std::size_t i = 0; i < kPropValueMax; ++i) {
            if (prop.value[i] == '\0') {
                nul_pos = i;
                break;
            }
        }
        if (nul_pos < kPropValueMax) {
            uint32_t trailing_nonzero = 0;
            for (std::size_t i = nul_pos + 1; i < kPropValueMax; ++i) {
                if (prop.value[i] != '\0') {
                    trailing_nonzero++;
                }
            }
            if (trailing_nonzero > 0) {
                RoNulTailAnomaly tail{};
                tail.prop_name.assign(name, name_len);
                tail.clean_value.assign(prop.value, nul_pos);
                tail.nonzero_trailing_bytes = trailing_nonzero;
                result.nul_tail_anomalies.push_back(std::move(tail));
            }
        }
    }
}

#if defined(__ANDROID__)

constexpr std::size_t kMaxHoleSamples = 4U;

int detect_android_sdk_level() {
    int level = android_get_device_api_level();
    if (level > 0) {
        return level;
    }
    char sdk_buf[PROP_VALUE_MAX]{};
    auto sdk_key = OBF("ro.build.version.sdk");
    int len = __system_property_get(sdk_key.c_str(), sdk_buf);
    if (len > 0) {
        return my_atoi(sdk_buf);
    }
    return 0;
}

std::string format_hex_u32(uint32_t val) {
    char buf[16]{};
    std::snprintf(buf, sizeof(buf), "0x%x", val);
    return std::string(buf);
}

std::string format_hole_ranges(const std::vector<HoleRun> &holes) {
    std::string out;
    const std::size_t count = std::min(holes.size(), kMaxHoleSamples);
    for (std::size_t i = 0; i < count; ++i) {
        if (i > 0) out.append(",");
        char seg[32]{};
        std::snprintf(seg, sizeof(seg), "@0x%x+%u", holes[i].offset, holes[i].length);
        out.append(seg);
    }
    if (holes.size() > count) {
        out.append(",...");
    }
    return out;
}

bool is_skipped_prop_dir_entry(const char *name) {
    if (!name || name[0] == '\0') return true;
    if (my_strcmp(name, ".") == 0 || my_strcmp(name, "..") == 0) return true;
    auto serial_name = OBF("properties_serial");
    auto info_name = OBF("property_info");
    if (my_strcmp(name, serial_name.c_str()) == 0) return true;
    if (my_strcmp(name, info_name.c_str()) == 0) return true;
    return false;
}

bool is_suspicious_selinux_xattr(const char *ctx) {
    if (!ctx || ctx[0] == '\0') {
        return false;
    }
    auto expected_prefix = OBF("u:object_r:");
    if (my_strncmp(ctx, expected_prefix.c_str(), expected_prefix.size()) != 0) {
        return true;
    }
    auto magisk_tok = OBF("magisk");
    auto ksu_tok = OBF("ksu_file");
    auto unlabeled_tok = OBF("unlabeled");
    if (my_strstr(ctx, magisk_tok.c_str()) != nullptr
            || my_strstr(ctx, ksu_tok.c_str()) != nullptr
            || my_strstr(ctx, unlabeled_tok.c_str()) != nullptr) {
        return true;
    }
    return false;
}

#endif  // defined(__ANDROID__)

bool is_safe_context_filename(const char *name, std::size_t len) noexcept {
    if (name == nullptr || len == 0 || len > 255U) {
        return false;
    }
    if ((len == 1 && name[0] == '.') || (len == 2 && name[0] == '.' && name[1] == '.')) {
        return false;
    }
    for (std::size_t i = 0; i < len; ++i) {
        const unsigned char c = static_cast<unsigned char>(name[i]);
        if (c == '/' || c == '\\' || c < 0x20U || c == 0x7FU) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool parse_property_info_contexts(const uint8_t *image,
                                  std::size_t image_size,
                                  std::vector<std::string> &contexts_out) {
    contexts_out.clear();
    if (image == nullptr
            || image_size < sizeof(DiskPropertyInfoHeader)
            || image_size > kMaxPropAreaFileSize) {
        return false;
    }

    DiskPropertyInfoHeader header{};
    my_memcpy(&header, image, sizeof(header));
    if (header.current_version < 1U || header.minimum_supported_version > 1U) {
        return false;
    }
    if (header.size < sizeof(DiskPropertyInfoHeader) || header.size > image_size) {
        return false;
    }

    const std::size_t effective_size = static_cast<std::size_t>(header.size);
    const std::size_t ctx_off = static_cast<std::size_t>(header.contexts_offset);
    if (ctx_off < sizeof(DiskPropertyInfoHeader)
            || (ctx_off % kByteAlignment) != 0
            || ctx_off > effective_size - sizeof(uint32_t)) {
        return false;
    }

    uint32_t count = 0;
    my_memcpy(&count, image + ctx_off, sizeof(count));
    constexpr uint32_t kMaxPropertyContexts = 4096U;
    if (count == 0U || count > kMaxPropertyContexts) {
        return false;
    }

    const std::size_t table_start = ctx_off + sizeof(uint32_t);
    const std::size_t max_entries = (effective_size - table_start) / sizeof(uint32_t);
    if (static_cast<std::size_t>(count) > max_entries) {
        return false;
    }

    std::unordered_set<std::string> seen;
    contexts_out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t str_off = 0;
        my_memcpy(&str_off, image + table_start + static_cast<std::size_t>(i) * sizeof(uint32_t),
                  sizeof(str_off));
        std::size_t str_len = 0;
        if (!bounded_c_string_length(image, effective_size, str_off, &str_len)) {
            continue;
        }
        const char *str_ptr = reinterpret_cast<const char *>(image + str_off);
        if (!is_safe_context_filename(str_ptr, str_len)) {
            continue;
        }
        std::string ctx(str_ptr, str_len);
        if (seen.insert(ctx).second) {
            contexts_out.push_back(std::move(ctx));
        }
    }
    return !contexts_out.empty();
}

bool is_security_critical_ro_prop(const char *name, std::size_t len) {
    if (name == nullptr || len == 0) {
        return false;
    }
    for (const char *candidate : kSecurityCriticalRoProps) {
        if (my_strlen(candidate) == len && my_memcmp(name, candidate, len) == 0) {
            return true;
        }
    }
    return false;
}

bool is_high_priority_hole_context(const char *context, std::size_t len) {
    if (context == nullptr || len == 0) {
        return false;
    }
    std::string ctx(context, len);
    return my_strstr(ctx.c_str(), "adbd_config_prop") != nullptr
            || my_strstr(ctx.c_str(), "shell_prop") != nullptr;
}

AreaAnalysisResult analyze_prop_area_image(const uint8_t *image,
                                           std::size_t image_size,
                                           int sdk_level) {
    AreaAnalysisResult result{};
    if (image == nullptr || image_size < sizeof(DiskPropAreaHeader)
            || image_size > kMaxPropAreaFileSize) {
        return result;
    }

    DiskPropAreaHeader header{};
    my_memcpy(&header, image, sizeof(header));
    if (header.magic != kPropAreaMagic || header.version != kPropAreaVersion) {
        return result;
    }

    const std::size_t data_capacity = image_size - sizeof(DiskPropAreaHeader);
    const std::size_t bytes_used = header.bytes_used;
    if (bytes_used < sizeof(DiskPropTrieNode)
            || bytes_used > data_capacity
            || (bytes_used % kByteAlignment) != 0) {
        return result;
    }

    const uint8_t *data = image + sizeof(DiskPropAreaHeader);
    const bool mark_dirty_backup = (sdk_level >= kDirtyBackupMinSdk);

    DiskPropTrieNode root{};
    if (!read_struct_at(data, bytes_used, 0, &root) || root.namelen != 0) {
        return result;
    }

    std::unique_ptr<uint8_t[]> occupied(new (std::nothrow) uint8_t[bytes_used]);
    if (!occupied) {
        return result;
    }
    my_memset(occupied.get(), 0, bytes_used);

    if (!mark_range(occupied.get(), bytes_used, 0, sizeof(DiskPropTrieNode))) {
        return result;
    }
    if (mark_dirty_backup) {
        if (!mark_range(occupied.get(), bytes_used,
                        static_cast<uint32_t>(sizeof(DiskPropTrieNode)),
                        kDirtyBackupAreaSize)) {
            return result;
        }
    }

    std::unordered_set<uint32_t> visited_nodes;
    std::unordered_set<uint32_t> visited_props;
    std::vector<uint32_t> node_stack;
    std::vector<uint32_t> prop_queue;

    auto push_node = [&](uint32_t off) {
        if (off != 0) {
            node_stack.push_back(off);
        }
    };
    auto push_prop = [&](uint32_t off) {
        if (off != 0) {
            prop_queue.push_back(off);
        }
    };

    push_node(root.left);
    push_node(root.right);
    push_node(root.children);
    push_prop(root.prop);

    while (!node_stack.empty()) {
        const uint32_t offset = node_stack.back();
        node_stack.pop_back();

        if (!visited_nodes.insert(offset).second) {
            continue;
        }
        if (visited_nodes.size() > kMaxVisitedNodes) {
            return result;
        }

        DiskPropTrieNode node{};
        if (!read_struct_at(data, bytes_used, offset, &node)) {
            return result;
        }
        if (offset > UINT32_MAX - static_cast<uint32_t>(sizeof(DiskPropTrieNode))) {
            return result;
        }
        const uint32_t name_offset = offset + static_cast<uint32_t>(sizeof(DiskPropTrieNode));
        std::size_t name_len = 0;
        if (!bounded_c_string_length(data, bytes_used, name_offset, &name_len)
                || name_len != node.namelen) {
            return result;
        }

        std::size_t alloc_size = 0;
        if (name_len > bytes_used
                || !align_up_checked(sizeof(DiskPropTrieNode) + name_len + 1U, &alloc_size)
                || !mark_range(occupied.get(), bytes_used, offset, alloc_size)) {
            return result;
        }

        push_node(node.left);
        push_node(node.right);
        push_node(node.children);
        push_prop(node.prop);
    }

    for (uint32_t prop_offset : prop_queue) {
        if (!visited_props.insert(prop_offset).second) {
            continue;
        }
        if (visited_props.size() > kMaxVisitedNodes) {
            return result;
        }

        DiskPropInfo prop{};
        if (!read_struct_at(data, bytes_used, prop_offset, &prop)) {
            return result;
        }
        if (prop_offset > UINT32_MAX - static_cast<uint32_t>(sizeof(DiskPropInfo))) {
            return result;
        }
        const uint32_t name_offset = prop_offset + static_cast<uint32_t>(sizeof(DiskPropInfo));
        std::size_t name_len = 0;
        if (!bounded_c_string_length(data, bytes_used, name_offset, &name_len)) {
            return result;
        }

        std::size_t alloc_size = 0;
        if (name_len > bytes_used
                || !align_up_checked(sizeof(DiskPropInfo) + name_len + 1U, &alloc_size)
                || !mark_range(occupied.get(), bytes_used, prop_offset, alloc_size)) {
            return result;
        }

        inspect_critical_ro_property(
                prop,
                reinterpret_cast<const char *>(data + name_offset),
                name_len,
                result);

        if ((prop.serial & kLongFlag) != 0) {
            const uint32_t rel_off = prop.long_property.offset;
            if (rel_off < sizeof(DiskPropInfo)
                    || prop_offset > UINT32_MAX - rel_off) {
                return result;
            }
            const uint32_t long_val_offset = prop_offset + rel_off;
            if (long_val_offset >= bytes_used) {
                return result;
            }
            std::size_t val_len = 0;
            if (!bounded_c_string_length(data, bytes_used, long_val_offset, &val_len)) {
                return result;
            }
            std::size_t long_alloc = 0;
            if (!align_up_checked(val_len + 1U, &long_alloc)
                    || !mark_range(occupied.get(), bytes_used, long_val_offset, long_alloc)) {
                return result;
            }
        }
    }

    std::size_t idx = 0;
    while (idx < bytes_used) {
        if (occupied[idx] != 0) {
            ++idx;
            continue;
        }
        const std::size_t start = idx;
        while (idx < bytes_used && occupied[idx] == 0) {
            ++idx;
        }
        const std::size_t length = idx - start;
        if ((start % kByteAlignment) != 0
                || length < kByteAlignment
                || (length % kByteAlignment) != 0) {
            return result;
        }
        HoleRun hole{};
        hole.offset = static_cast<uint32_t>(start);
        hole.length = static_cast<uint32_t>(length);
        result.holes.push_back(hole);
    }

    result.parsed = true;
    return result;
}

}  // namespace prop_forensics
}  // namespace riskengine

std::string native_get_bionic_prop_forensics() {
    using namespace payload_codec;
    using namespace riskengine::prop_forensics;

#if !defined(__ANDROID__)
    PayloadBuilder builder(Status::UNSUPPORTED, 0);
    return builder.build();
#else
    const int sdk_level = detect_android_sdk_level();
    auto prop_dir = OBF("/dev/__properties__");
    std::vector<std::string> area_names;
    int enum_err = 0;

    // 1. Try directory listing (succeeds on pre-Treble / permissive setups).
    RawDirResult dir = raw_list_dir(prop_dir.c_str());
    if (dir.ok() && !dir.names.empty()) {
        area_names = std::move(dir.names);
    } else {
        enum_err = dir.error;
        // 2. Android 8+ sets /dev/__properties__ to mode 0711 (drwx--x--x): no directory
        //    listing, but /dev/__properties__/property_info and individual context files
        //    are 0444 readable. Parse property_info's contexts table directly.
        const std::string info_path = std::string(prop_dir.c_str()) + "/" + OBF("property_info").str();
        const long info_fd_ret = my_openat(
                AT_FDCWD, info_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
        if (info_fd_ret >= 0) {
            const int info_fd = static_cast<int>(info_fd_ret);
            struct stat info_st{};
            if (my_fstatat(info_fd, "", &info_st, AT_EMPTY_PATH) == 0
                    && S_ISREG(info_st.st_mode)
                    && info_st.st_size >= static_cast<off_t>(sizeof(DiskPropertyInfoHeader))
                    && static_cast<uint64_t>(info_st.st_size) <= kMaxPropAreaFileSize) {
                const std::size_t info_size = static_cast<std::size_t>(info_st.st_size);
                const long mapped_info = my_mmap(
                        nullptr, info_size, PROT_READ, MAP_PRIVATE, info_fd, 0);
                if (mapped_info != -1) {
                    parse_property_info_contexts(
                            reinterpret_cast<const uint8_t *>(mapped_info),
                            info_size,
                            area_names);
                    my_munmap(reinterpret_cast<void *>(mapped_info), info_size);
                }
            }
            my_close(info_fd);
        }

        // 3. Final fallback: probe well-known security-critical context areas directly.
        if (area_names.empty()) {
            area_names.push_back(OBF("u:object_r:default_prop:s0").str());
            area_names.push_back(OBF("u:object_r:build_prop:s0").str());
            area_names.push_back(OBF("u:object_r:exported_default_prop:s0").str());
            area_names.push_back(OBF("u:object_r:adbd_config_prop:s0").str());
            area_names.push_back(OBF("u:object_r:shell_prop:s0").str());
            area_names.push_back(OBF("u:object_r:bootloader_prop:s0").str());
            area_names.push_back(OBF("u:object_r:system_prop:s0").str());
            area_names.push_back(OBF("u:object_r:debug_prop:s0").str());
        }
    }

    int areas_scanned = 0;
    int hole_areas = 0;
    int hole_total = 0;
    int ro_checked_total = 0;

    PayloadBuilder builder(Status::OK, 0);
    auto selinux_xattr_name = OBF("security.selinux");

    for (const std::string &name : area_names) {
        if (is_skipped_prop_dir_entry(name.c_str())) {
            continue;
        }
        std::string full_path = std::string(prop_dir.c_str()) + "/" + name;

        const long fd_ret = my_openat(
                AT_FDCWD, full_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
        if (fd_ret < 0) {
            continue;
        }
        const int fd = static_cast<int>(fd_ret);

        struct stat st{};
        if (my_fstatat(fd, "", &st, AT_EMPTY_PATH) != 0
                || !S_ISREG(st.st_mode)
                || st.st_size < static_cast<off_t>(sizeof(DiskPropAreaHeader))
                || static_cast<uint64_t>(st.st_size) > kMaxPropAreaFileSize) {
            my_close(fd);
            continue;
        }

        const std::size_t file_size = static_cast<std::size_t>(st.st_size);
        const long mapped_ret = my_mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
        my_close(fd);
        if (mapped_ret == -1) {
            continue;
        }
        auto *mapped = reinterpret_cast<const uint8_t *>(mapped_ret);
        AreaAnalysisResult analysis = analyze_prop_area_image(mapped, file_size, sdk_level);
        my_munmap(const_cast<uint8_t *>(mapped), file_size);

        if (!analysis.parsed) {
            continue;
        }

        areas_scanned++;
        ro_checked_total += static_cast<int>(analysis.ro_checked);

        // Check owner/mode metadata (NEVER st_mtime: tmpfs lacks page_mkwrite).
        if (st.st_uid != 0 || st.st_gid != 0 || (st.st_mode & 0022) != 0) {
            char meta_detail[96]{};
            std::snprintf(meta_detail, sizeof(meta_detail),
                          "uid=%u,gid=%u,mode=0%o",
                          static_cast<unsigned>(st.st_uid),
                          static_cast<unsigned>(st.st_gid),
                          static_cast<unsigned>(st.st_mode & 07777));
            RecordBuilder rec;
            rec.add("kind", "meta_anomaly")
               .add("context", name)
               .add("detail", meta_detail);
            builder.add_record(rec);
        }

        char xattr_buf[256]{};
        const long xattr_len = my_lgetxattr(
                full_path.c_str(), selinux_xattr_name.c_str(),
                xattr_buf, sizeof(xattr_buf) - 1);
        if (xattr_len > 0) {
            std::size_t clean_len = static_cast<std::size_t>(xattr_len);
            while (clean_len > 0 && xattr_buf[clean_len - 1] == '\0') {
                --clean_len;
            }
            xattr_buf[clean_len] = '\0';
            if (clean_len > 0 && is_suspicious_selinux_xattr(xattr_buf)) {
                RecordBuilder rec;
                rec.add("kind", "selinux_anomaly")
                   .add("context", name)
                   .add("xattr", xattr_buf);
                builder.add_record(rec);
            }
        }

        if (!analysis.holes.empty()) {
            hole_areas++;
            hole_total += static_cast<int>(analysis.holes.size());
            RecordBuilder rec;
            rec.add("kind", "hole")
               .add("context", name)
               .add_int("count", static_cast<int64_t>(analysis.holes.size()))
               .add_bool("high_priority",
                         is_high_priority_hole_context(name.c_str(), name.size()))
               .add("ranges", format_hole_ranges(analysis.holes));
            builder.add_record(rec);
        }

        for (const auto &anom : analysis.serial_anomalies) {
            RecordBuilder rec;
            rec.add("kind", "serial_modified")
               .add("prop", anom.prop_name)
               .add_uint("write_count", anom.write_count)
               .add("serial", format_hex_u32(anom.serial))
               .add("context", name);
            builder.add_record(rec);
        }

        for (const auto &tail : analysis.nul_tail_anomalies) {
            RecordBuilder rec;
            rec.add("kind", "nul_tail")
               .add("prop", tail.prop_name)
               .add("value", tail.clean_value)
               .add_uint("nonzero_bytes", tail.nonzero_trailing_bytes)
               .add("context", name);
            builder.add_record(rec);
        }
    }

    if (areas_scanned == 0) {
        const int final_err = enum_err != 0 ? enum_err : EACCES;
        builder.set_status(
                (final_err == EACCES || final_err == EPERM) ? Status::RESTRICTED : Status::UNSUPPORTED,
                final_err);
    }
    builder.add_header_int("sdk", sdk_level);
    builder.add_header_int("areas_scanned", areas_scanned);
    builder.add_header_int("hole_areas", hole_areas);
    builder.add_header_int("hole_total", hole_total);
    builder.add_header_int("ro_checked", ro_checked_total);
    return builder.build();
#endif
}
