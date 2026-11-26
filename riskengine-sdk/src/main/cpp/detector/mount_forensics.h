#ifndef RISKENGINE_MOUNT_FORENSICS_H
#define RISKENGINE_MOUNT_FORENSICS_H

#include <cstdint>
#include <string>
#include <string_view>

/**
 * Native mount table deep forensics returning a payload_codec frame.
 *
 * Checks:
 *  1. statx(STATX_MNT_ID) cross-verification against /proc/self/mountinfo
 *     (re-verifies once on initial mismatch to avoid transient non-atomic races).
 *  2. Exact comma-tokenized 'rw' detection on read-only Android system partitions.
 *  3. /proc/self/{mounts,mountinfo,mountstats} st_mtime parity (strictly gated on
 *     all three fstatat() calls returning 0 on zero-initialized struct stat {}).
 *  4. statfs() OVERLAYFS_SUPER_MAGIC / TMPFS_MAGIC checks on read-only system paths.
 *
 * Pure Mount ID numeric gaps (mnt_id_ida allocator reuse) are NEVER scored as risk.
 */
std::string native_get_mount_forensics();

namespace mount_forensics {

bool has_exact_rw_option(std::string_view options) noexcept;
bool is_protected_ro_mount_point(std::string_view path) noexcept;
bool is_mount_mtime_inconsistent(bool mounts_ok, int64_t mounts_mtime,
                                 bool mountinfo_ok, int64_t mountinfo_mtime,
                                 bool mountstats_ok, int64_t mountstats_mtime) noexcept;

/**
 * Pure table analyzer exposed for deterministic host C++ fixture tests.
 * Parses mounts_text and mountinfo_text without touching host procfs.
 */
std::string analyze_mount_tables(std::string_view mounts_text,
                                 std::string_view mountinfo_text);

}  // namespace mount_forensics

#endif  // RISKENGINE_MOUNT_FORENSICS_H
