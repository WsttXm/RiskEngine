#include "detector/mount_forensics.h"

#include "util/mylibc.h"
#include "util/obf_str.h"
#include "util/payload_codec.h"
#include "util/syscall_wrapper.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif

namespace mount_forensics {

namespace {

constexpr uint32_t kStatxBasicStats = 0x000007ffU;
constexpr uint32_t kStatxMntId = 0x00001000U;
constexpr uint64_t kOverlayfsSuperMagic = 0x794c7630ULL;
constexpr uint64_t kTmpfsMagic = 0x01021994ULL;

struct RiskStatxTimestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t reserved;
};

struct RiskStatx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    RiskStatxTimestamp stx_atime;
    RiskStatxTimestamp stx_btime;
    RiskStatxTimestamp stx_ctime;
    RiskStatxTimestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t spare3[12];
};

static_assert(sizeof(RiskStatx) == 256, "RiskStatx must match Linux UAPI struct statx");
static_assert(offsetof(RiskStatx, stx_mnt_id) == 144, "stx_mnt_id offset mismatch");

bool parse_u64_decimal(std::string_view token, uint64_t &out) noexcept {
    if (token.empty()) {
        return false;
    }
    uint64_t acc = 0;
    for (char ch : token) {
        if (ch < '0' || ch > '9') {
            return false;
        }
        uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (acc > (UINT64_MAX - digit) / 10ULL) {
            return false;
        }
        acc = acc * 10ULL + digit;
    }
    out = acc;
    return true;
}

std::string_view trim_spaces(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r')) {
        sv.remove_suffix(1);
    }
    return sv;
}

void split_whitespace(std::string_view line, std::vector<std::string_view> &out) {
    out.clear();
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        while (i < n && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) {
            ++i;
        }
        if (i >= n) {
            break;
        }
        size_t start = i;
        while (i < n && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') {
            ++i;
        }
        out.emplace_back(line.substr(start, i - start));
    }
}

bool sv_equals(std::string_view a, const char *b) noexcept {
    if (!b) {
        return false;
    }
    size_t blen = my_strlen(b);
    return a.size() == blen && (blen == 0 || my_memcmp(a.data(), b, blen) == 0);
}

struct OverlayMountEntry {
    std::string mount_point;
    std::string mount_opts;
    std::string mount_source;
    std::string super_opts;
};

struct MountInfoSummary {
    std::unordered_set<uint64_t> mount_ids;
    std::vector<OverlayMountEntry> overlays;
    int entry_count = 0;
};

struct RoRwFinding {
    std::string path;
    std::string fs_type;
    std::string options;
};

bool sv_starts_with(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() && my_memcmp(s.data(), prefix.data(), prefix.size()) == 0;
}

std::string to_lower_ascii(std::string_view s) {
    std::string out(s);
    for (char &c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

bool is_benign_oem_lowerdir_segment(std::string_view seg) {
    if (seg.empty() || seg[0] != '/') {
        return false;
    }
    if (seg.find("..") != std::string_view::npos) {
        return false;
    }
    auto starts = [&](const auto &obf) -> bool {
        const auto v = obf.view();
        return sv_starts_with(seg, v)
                && (seg.size() == v.size() || seg[v.size()] == '/');
    };
    return starts(OBF("/mi_ext"))
            || starts(OBF("/my_product"))
            || starts(OBF("/my_region"))
            || starts(OBF("/my_carrier"))
            || starts(OBF("/my_company"))
            || starts(OBF("/my_heytap"))
            || starts(OBF("/my_stock"))
            || starts(OBF("/my_manifest"))
            || starts(OBF("/my_bigball"))
            || starts(OBF("/my_engineering"))
            || starts(OBF("/product"))
            || starts(OBF("/system_ext"))
            || starts(OBF("/vendor"))
            || starts(OBF("/odm"))
            || starts(OBF("/system"))
            || starts(OBF("/oem"))
            || starts(OBF("/prism"))
            || starts(OBF("/optics"))
            || starts(OBF("/preload"));
}

bool is_high_sensitivity_overlay_target(std::string_view path) noexcept {
    auto eq = [&](const auto &obf) noexcept -> bool {
        return sv_equals(path, obf.c_str());
    };
    return eq(OBF("/system/bin"))
            || eq(OBF("/system/lib"))
            || eq(OBF("/system/lib64"))
            || eq(OBF("/system/etc/security/cacerts"));
}

bool has_suspicious_overlay_marker(std::string_view lower_text) {
    auto has = [&](const auto &obf) -> bool {
        return lower_text.find(obf.view()) != std::string_view::npos;
    };
    return has(OBF("magisk"))
            || has(OBF("ksu"))
            || has(OBF("kernelsu"))
            || has(OBF("apatch"))
            || has(OBF("susfs"))
            || has(OBF("/data/"))
            || has(OBF("/adb/"))
            || has(OBF("debug_ramdisk"))
            || has(OBF("upperdir="))
            || has(OBF("workdir="));
}

bool is_benign_oem_overlay_entry(const OverlayMountEntry &entry) {
    if (has_exact_rw_option(entry.mount_opts) || has_exact_rw_option(entry.super_opts)) {
        return false;
    }
    const std::string lower_src = to_lower_ascii(entry.mount_source);
    const std::string lower_super = to_lower_ascii(entry.super_opts);
    if (has_suspicious_overlay_marker(lower_src) || has_suspicious_overlay_marker(lower_super)) {
        return false;
    }

    // Require explicit lowerdir= and verify every colon-separated layer resides in stock OEM RO partitions.
    const auto lowerdir_key = OBF("lowerdir=");
    const size_t key_pos = entry.super_opts.find(lowerdir_key.view());
    if (key_pos == std::string::npos) {
        return false;
    }
    const size_t val_start = key_pos + lowerdir_key.size();
    const size_t comma = entry.super_opts.find(',', val_start);
    std::string_view dirs = (comma == std::string::npos)
            ? std::string_view(entry.super_opts).substr(val_start)
            : std::string_view(entry.super_opts).substr(val_start, comma - val_start);
    if (dirs.empty()) {
        return false;
    }

    int segment_count = 0;
    size_t pos = 0;
    while (pos <= dirs.size()) {
        const size_t colon = dirs.find(':', pos);
        std::string_view seg = (colon == std::string_view::npos)
                ? dirs.substr(pos)
                : dirs.substr(pos, colon - pos);
        if (!is_benign_oem_lowerdir_segment(seg)) {
            return false;
        }
        segment_count++;
        if (colon == std::string_view::npos) {
            break;
        }
        pos = colon + 1;
    }
    return segment_count > 0;
}

bool is_benign_oem_overlay_for_path(const MountInfoSummary &summary, std::string_view path) {
    if (is_high_sensitivity_overlay_target(path)) {
        return false;
    }
    const OverlayMountEntry *best = nullptr;
    size_t best_len = 0;
    for (const auto &ov : summary.overlays) {
        const std::string_view mp(ov.mount_point);
        if (mp.empty()) continue;
        const bool match = (path == mp)
                || (sv_starts_with(path, mp) && (mp.back() == '/' || path[mp.size()] == '/'));
        if (match && mp.size() > best_len) {
            best = &ov;
            best_len = mp.size();
        }
    }
    // If statfs reports OVERLAYFS_SUPER_MAGIC yet no visible overlay mount exists in mountinfo,
    // treat it as a hidden/spoofed overlay (never exempt).
    if (best == nullptr) {
        return false;
    }
    return is_benign_oem_overlay_entry(*best);
}

void parse_mountinfo_text(std::string_view text,
                          MountInfoSummary &summary,
                          std::vector<RoRwFinding> &ro_rw_findings,
                          std::unordered_set<std::string> &seen_rw_paths) {
    summary.mount_ids.clear();
    summary.overlays.clear();
    summary.entry_count = 0;
    std::vector<std::string_view> left_tokens;
    std::vector<std::string_view> right_tokens;
    left_tokens.reserve(10);
    right_tokens.reserve(6);

    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string_view line = (nl == std::string_view::npos)
                ? text.substr(pos)
                : text.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? text.size() : (nl + 1);
        line = trim_spaces(line);
        if (line.empty()) {
            continue;
        }
        size_t sep = line.find(" - ");
        if (sep == std::string_view::npos || sep == 0) {
            continue;
        }
        split_whitespace(line.substr(0, sep), left_tokens);
        split_whitespace(line.substr(sep + 3), right_tokens);
        if (left_tokens.size() < 6 || right_tokens.size() < 2) {
            continue;
        }
        uint64_t mnt_id = 0;
        if (!parse_u64_decimal(left_tokens[0], mnt_id)) {
            continue;
        }
        summary.mount_ids.insert(mnt_id);
        summary.entry_count++;

        std::string_view mount_point = left_tokens[4];
        std::string_view mount_opts = left_tokens[5];
        std::string_view fs_type = right_tokens[0];
        if (sv_equals(fs_type, OBF("overlay").c_str())
                || sv_equals(fs_type, OBF("overlayfs").c_str())) {
            OverlayMountEntry ov{};
            ov.mount_point = std::string(mount_point);
            ov.mount_opts = std::string(mount_opts);
            ov.mount_source = right_tokens.size() >= 2 ? std::string(right_tokens[1]) : "";
            ov.super_opts = right_tokens.size() >= 3 ? std::string(right_tokens[2]) : "";
            summary.overlays.push_back(std::move(ov));
        }
        if (is_protected_ro_mount_point(mount_point) && has_exact_rw_option(mount_opts)) {
            std::string path_str(mount_point);
            if (seen_rw_paths.insert(path_str).second) {
                ro_rw_findings.push_back(
                        {std::move(path_str), std::string(fs_type), std::string(mount_opts)});
            }
        }
    }
}

int parse_mounts_text(std::string_view text,
                      std::vector<RoRwFinding> &ro_rw_findings,
                      std::unordered_set<std::string> &seen_rw_paths) {
    int count = 0;
    std::vector<std::string_view> cols;
    cols.reserve(6);

    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string_view line = (nl == std::string_view::npos)
                ? text.substr(pos)
                : text.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? text.size() : (nl + 1);
        line = trim_spaces(line);
        if (line.empty()) {
            continue;
        }
        split_whitespace(line, cols);
        if (cols.size() < 4) {
            continue;
        }
        count++;
        std::string_view mount_point = cols[1];
        std::string_view fs_type = cols[2];
        std::string_view opts = cols[3];
        if (is_protected_ro_mount_point(mount_point) && has_exact_rw_option(opts)) {
            std::string path_str(mount_point);
            if (seen_rw_paths.insert(path_str).second) {
                ro_rw_findings.push_back(
                        {std::move(path_str), std::string(fs_type), std::string(opts)});
            }
        }
    }
    return count;
}

bool read_proc_mount_mtimes(int64_t &t_mounts,
                            int64_t &t_mountinfo,
                            int64_t &t_mountstats) noexcept {
    const auto p_mounts = OBF("/proc/self/mounts");
    const auto p_mountinfo = OBF("/proc/self/mountinfo");
    const auto p_mountstats = OBF("/proc/self/mountstats");

    // Red line: zero-initialize all struct stat {} and compare ONLY when all 3 fstatat == 0.
    struct stat st_mounts {};
    struct stat st_mountinfo {};
    struct stat st_mountstats {};
    const long r1 = my_fstatat(AT_FDCWD, p_mounts.c_str(), &st_mounts, 0);
    const long r2 = my_fstatat(AT_FDCWD, p_mountinfo.c_str(), &st_mountinfo, 0);
    const long r3 = my_fstatat(AT_FDCWD, p_mountstats.c_str(), &st_mountstats, 0);
    if (r1 != 0 || r2 != 0 || r3 != 0) {
        return false;
    }
    t_mounts = static_cast<int64_t>(st_mounts.st_mtime);
    t_mountinfo = static_cast<int64_t>(st_mountinfo.st_mtime);
    t_mountstats = static_cast<int64_t>(st_mountstats.st_mtime);
    return true;
}

}  // namespace

bool has_exact_rw_option(std::string_view options) noexcept {
    if (options.empty()) {
        return false;
    }
    size_t pos = 0;
    while (pos <= options.size()) {
        size_t comma = options.find(',', pos);
        std::string_view tok = (comma == std::string_view::npos)
                ? options.substr(pos)
                : options.substr(pos, comma - pos);
        tok = trim_spaces(tok);
        if (tok.size() == 2 && tok[0] == 'r' && tok[1] == 'w') {
            return true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        pos = comma + 1;
    }
    return false;
}

bool is_protected_ro_mount_point(std::string_view path) noexcept {
    if (path.empty()) {
        return false;
    }
    // Strip trailing slashes except root "/".
    while (path.size() > 1 && path.back() == '/') {
        path.remove_suffix(1);
    }
    auto match = [&](const auto &obf) noexcept -> bool {
        return sv_equals(path, obf.c_str());
    };
    return match(OBF("/system"))
            || match(OBF("/system/bin"))
            || match(OBF("/system/sbin"))
            || match(OBF("/system/xbin"))
            || match(OBF("/system/etc"))
            || match(OBF("/system/etc/security/cacerts"))
            || match(OBF("/system_ext"))
            || match(OBF("/system_ext/bin"))
            || match(OBF("/vendor"))
            || match(OBF("/vendor/bin"))
            || match(OBF("/product"))
            || match(OBF("/product/bin"))
            || match(OBF("/odm"))
            || match(OBF("/sbin"))
            || match(OBF("/etc"));
}

bool is_mount_mtime_inconsistent(bool mounts_ok, int64_t mounts_mtime,
                                 bool mountinfo_ok, int64_t mountinfo_mtime,
                                 bool mountstats_ok, int64_t mountstats_mtime) noexcept {
    if (!mounts_ok || !mountinfo_ok || !mountstats_ok) {
        return false;
    }
    return !(mounts_mtime == mountinfo_mtime && mountinfo_mtime == mountstats_mtime);
}

std::string analyze_mount_tables(std::string_view mounts_text,
                                 std::string_view mountinfo_text) {
    MountInfoSummary info_summary;
    std::vector<RoRwFinding> ro_rw;
    std::unordered_set<std::string> seen_rw;
    parse_mountinfo_text(mountinfo_text, info_summary, ro_rw, seen_rw);
    const int mounts_count = parse_mounts_text(mounts_text, ro_rw, seen_rw);

    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    pb.add_header_int("mounts_count", mounts_count);
    pb.add_header_int("mountinfo_count", info_summary.entry_count);
    for (const auto &f : ro_rw) {
        payload_codec::RecordBuilder rb;
        rb.add("kind", OBF("system_ro_rw_mount").c_str())
          .add("path", f.path)
          .add("fs", f.fs_type)
          .add("opts", f.options);
        pb.add_record(rb);
    }
    return pb.build();
}

}  // namespace mount_forensics

std::string native_get_mount_forensics() {
    using namespace mount_forensics;

    const auto p_mounts = OBF("/proc/self/mounts");
    const auto p_mountinfo = OBF("/proc/self/mountinfo");

    std::string mounts_text = read_file_string(p_mounts.c_str(), 1024 * 1024);
    std::string mountinfo_text = read_file_string(p_mountinfo.c_str(), 1024 * 1024);

    MountInfoSummary info_summary;
    std::vector<RoRwFinding> ro_rw;
    std::unordered_set<std::string> seen_rw;
    parse_mountinfo_text(mountinfo_text, info_summary, ro_rw, seen_rw);
    const int mounts_count = parse_mounts_text(mounts_text, ro_rw, seen_rw);

    payload_codec::PayloadBuilder pb(payload_codec::Status::OK, 0);
    int checks_run = 0;

    if (mounts_count > 0 || info_summary.entry_count > 0) {
        checks_run++;
    }
    for (const auto &f : ro_rw) {
        payload_codec::RecordBuilder rb;
        rb.add("kind", OBF("system_ro_rw_mount").c_str())
          .add("path", f.path)
          .add("fs", f.fs_type)
          .add("opts", f.options);
        pb.add_record(rb);
    }

    // 1. statx(STATX_MNT_ID) vs /proc/self/mountinfo visibility check.
    bool statx_supported = false;
    bool refreshed_mountinfo = false;
    if (info_summary.entry_count > 0) {
        const std::string statx_paths[] = {
                OBF("/data/data").str(),
                OBF("/system/bin").str(),
                OBF("/system/lib64").str(),
                OBF("/vendor/bin").str(),
                OBF("/system/etc/security/cacerts").str(),
        };
        for (const auto &path : statx_paths) {
            RiskStatx stx {};
            const long rc = my_statx(
                    AT_FDCWD, path.c_str(), AT_NO_AUTOMOUNT,
                    kStatxBasicStats | kStatxMntId, &stx);
            if (rc != 0 || (stx.stx_mask & kStatxMntId) == 0) {
                continue;
            }
            statx_supported = true;
            if (info_summary.mount_ids.find(stx.stx_mnt_id) != info_summary.mount_ids.end()) {
                continue;
            }
            // Re-read mountinfo once to rule out non-atomic snapshot race.
            if (!refreshed_mountinfo) {
                refreshed_mountinfo = true;
                std::string fresh_text = read_file_string(p_mountinfo.c_str(), 1024 * 1024);
                MountInfoSummary fresh_summary;
                std::vector<RoRwFinding> ignored_rw;
                std::unordered_set<std::string> ignored_seen;
                parse_mountinfo_text(fresh_text, fresh_summary, ignored_rw, ignored_seen);
                if (fresh_summary.entry_count > 0) {
                    info_summary.mount_ids.insert(
                            fresh_summary.mount_ids.begin(), fresh_summary.mount_ids.end());
                }
            }
            if (info_summary.mount_ids.find(stx.stx_mnt_id) == info_summary.mount_ids.end()) {
                payload_codec::RecordBuilder rb;
                rb.add("kind", OBF("statx_mnt_id_hidden").c_str())
                  .add("path", path)
                  .add_uint("mnt_id", stx.stx_mnt_id);
                pb.add_record(rb);
            }
        }
        if (statx_supported) {
            checks_run++;
        }
    }

    // 2. /proc/self/{mounts,mountinfo,mountstats} st_mtime parity.
    int64_t t1 = 0, t2 = 0, t3 = 0;
    bool mtime_checked = read_proc_mount_mtimes(t1, t2, t3);
    if (mtime_checked) {
        checks_run++;
        if (is_mount_mtime_inconsistent(true, t1, true, t2, true, t3)) {
            // Confirm once to avoid 1-second wall-clock boundary flakes.
            int64_t r1 = 0, r2 = 0, r3 = 0;
            if (read_proc_mount_mtimes(r1, r2, r3)
                    && is_mount_mtime_inconsistent(true, r1, true, r2, true, r3)) {
                payload_codec::RecordBuilder rb;
                rb.add("kind", OBF("mount_mtime_mismatch").c_str())
                  .add_int("mounts", r1)
                  .add_int("mountinfo", r2)
                  .add_int("mountstats", r3);
                pb.add_record(rb);
            }
        }
    }

    // 3. statfs() OVERLAYFS_SUPER_MAGIC / TMPFS_MAGIC on read-only system paths.
    int statfs_checked = 0;
    const std::string statfs_paths[] = {
            OBF("/system/bin").str(),
            OBF("/system/lib64").str(),
            OBF("/system/lib").str(),
            OBF("/system/etc/security/cacerts").str(),
            OBF("/vendor/bin").str(),
            OBF("/product/app").str(),
            OBF("/system_ext/bin").str(),
    };
    for (const auto &path : statfs_paths) {
        struct statfs sfs {};
        if (my_statfs(path.c_str(), &sfs) != 0) {
            continue;
        }
        statfs_checked++;
        const uint64_t magic = static_cast<uint64_t>(static_cast<uint32_t>(sfs.f_type));
        if (magic == kOverlayfsSuperMagic) {
            if (!is_benign_oem_overlay_for_path(info_summary, path)) {
                payload_codec::RecordBuilder rb;
                rb.add("kind", OBF("statfs_overlay_on_system").c_str())
                  .add("path", path)
                  .add("magic", "0x794c7630");
                pb.add_record(rb);
            }
        } else if (magic == kTmpfsMagic) {
            payload_codec::RecordBuilder rb;
            rb.add("kind", OBF("statfs_tmpfs_on_system").c_str())
              .add("path", path)
              .add("magic", "0x01021994");
            pb.add_record(rb);
        }
    }
    if (statfs_checked > 0) {
        checks_run++;
    }

    if (checks_run == 0) {
        pb.set_status(payload_codec::Status::RESTRICTED, EACCES);
    }
    pb.add_header_int("mounts_count", mounts_count);
    pb.add_header_int("mountinfo_count", info_summary.entry_count);
    pb.add_header_int("statx_supported", statx_supported ? 1 : 0);
    pb.add_header_int("mtime_checked", mtime_checked ? 1 : 0);
    pb.add_header_int("statfs_checked", statfs_checked);
    return pb.build();
}
