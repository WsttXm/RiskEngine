# Evidence Contract Record — `mount_analysis`

- **Detector**: `mount_analysis` (`MountAnalysisDetector`)
- **ScanTier**: `FAST` (`/proc/self/mounts`, `/proc/self/mountinfo`, native `mount_forensics`) + `POSTPONED` (ephemeral `RiskIsolatedProbeService` cross-process mount diff)
- **EvidenceFamily**: `root_fw` (deduplicated with `root` and Root manager hits in `threat_apps`)
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java `/proc/self/{mounts,mountinfo}` | `mountinfo:ksu`, `mountinfo:magisk`, `debug_ramdisk_mount`, `mount:magisk`, `mount:ksu`, `mount:apatch` | `root_fw` | `MEDIUM` | Explicit Root framework mount sources/roots visible in process mount tables (with `mountinfo:ksu`/`magisk` superseding generic `debug_ramdisk_mount`) |
| Native `mount_forensics.cpp` | `statx_mnt_id_hidden` | `root_fw` | `STRONG` | `statx(STATX_MNT_ID)` returns a valid mount ID for a protected partition that is absent from `/proc/self/mountinfo` (indicating text/procfs mount hiding) |
| Native `mount_forensics.cpp` | `system_ro_rw_mount`, `statfs_overlay_on_system`, `statfs_tmpfs_on_system`, `mount_mtime_mismatch` | `root_fw` | `MEDIUM` | Exact comma-tokenized `rw` option on read-only system partitions, unexpected `OVERLAYFS_SUPER_MAGIC` / `TMPFS_MAGIC` on system partitions, or 3-way `fstatat` `st_mtime` contradiction across `/proc/self/{mounts,mountinfo,mountstats}` |
| `POSTPONED` `RiskIsolatedProbeService` | `isolated_mount_diff` (`isolated_mount_diff:root:*`, `isolated_mount_diff:hidden:*`) | `root_fw` | `STRONG` / `MEDIUM` | Cross-process mount-table comparison between the main app process and an ephemeral `isolatedProcess="true"` helper exposing selective Shamiko/KernelSU main-process unmounts |

## Producing Subsystem

- Linux VFS mount namespace (`fs/namespace.c`, `fs/proc_namespace.c`) serving `/proc/self/mounts`, `/proc/self/mountinfo`, and `/proc/self/mountstats`.
- Kernel `statx(AT_FDCWD, ..., STATX_MNT_ID)` (`fs/stat.c`) and `statfs` superblock magic (`OVERLAYFS_SUPER_MAGIC = 0x794c7630`, `TMPFS_MAGIC = 0x01021994`).
- Android Zygote isolated-process sandbox (`RiskIsolatedProbeService`, `isolatedProcess="true"`, `exported="false"`), normalized by `MountViewNormalizer`.

## Mechanism (AOSP/Linux/ACK)

- **Native Mount Forensics (`mount_forensics.cpp`)**: Reads an `OBF`-protected list of system read-only partitions, parses `/proc/self/mountinfo` mount IDs, queries `statx(STATX_MNT_ID)` per partition, verifies exact comma-separated `rw` mount flags (never matching `ro,dirsync` or `rw` substrings inside options), checks `statfs` superblock magic, and compares zero-initialized `fstatat` `st_mtime` across `/proc/self/mounts`, `/proc/self/mountinfo`, and `/proc/self/mountstats` with double-read parity.
- **Ephemeral Isolated Cross-Process Diff (`IsolatedProbeClient` + `MountViewNormalizer`)**: Because `/proc/1/mountinfo` is permanently removed (`D01`/`v1.5.0`), `MountAnalysisDetector.detectPostponed()` binds `RiskIsolatedProbeService` on demand, reads the isolated process's `/proc/self/mountinfo`, immediately calls `unbindService()` in `finally` (zero resident process), normalizes dynamic shmem attributes (`size=`, `nr_inodes=`, `nr_blocks=`) and legitimate Android 11+ isolated sandbox mounts, and identifies root mounts selectively unmounted from the main app UID.
- **Cross-Detector Correlation (`C9`)**: When `mount_analysis` detects selective unmount / hidden mounts while runnable `root` returns clean, `CorrelationEngine` escalates `C9:stealth_root_with_unmount` (`HIGH/8`).

## Applicable API Range

- **Java mount tables & native `statfs`/`rw`/`st_mtime`**: Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).
- **`statx(STATX_MNT_ID)`**: Linux kernel `>= 5.8` (gracefully skipped when kernel does not set `STATX_MNT_ID` in `stx_mask`).
- **`RiskIsolatedProbeService`**: Android 11–17 (API 30–37) when `config.isEnableIsolatedProcessProbe()` is `true` and service is present in host manifest.

## Visibility Boundaries

- If a root solution unmounts modules globally or from both the main process and isolated processes (e.g., kernel-level SUSFS unmount across all unprivileged namespaces), `isolated_mount_diff` will observe identical tables and return clean; absence does not prove an unrooted device.
- Hosts stripping `RiskIsolatedProbeService` via `tools:node="remove"` or disabling `enableIsolatedProcessProbe(false)` degrade cleanly to `UNAVAILABLE` for the postponed diff while preserving FAST-tier mount forensics.
- `/proc/1/mountinfo` is intentionally NOT accessed (SELinux-blocked on modern Android).

## False-Positive Defenses

- **Zero Mount ID gap heuristics**: Mount ID discontinuities (`mnt_id_ida` reuse) and anonymous minor gaps are explicitly NOT scored as threats (`D37`).
- **Stock OEM read-only overlay exemption (`D46`)**: `statfs_overlay_on_system` checks `/proc/self/mountinfo` provenance and exempts visible read-only OEM overlays with no `upperdir=`/`rw`/root markers whose `lowerdir` segments all reside inside stock RO partitions (`/mi_ext`, `/my_product`, `/product`, `/vendor`, `/odm`, etc., validated on Xiaomi 15 HyperOS 2), while keeping `/system/{bin,lib,lib64,etc/security/cacerts}` and hidden/module overlays flagged.
- **Exact comma-tokenized `rw` parsing**: Avoids substring false positives on mount option keys/values containing `rw`.
- **`MountViewNormalizer` allowlists (`D30`)**: Strips transient shmem size/inode/block options, allowlists exact Android 11+ Zygote isolated storage bases (`/storage`, `/data/data`, `/data/user`, `/data/user_de`, `/data_mirror`), and restricts `directRootTokens` to `isolatedOnly` entries using boundary-delimited KSU matching (zero FP on `worksuite`/`banksu`).
- **Attribution deduplication**: `mountinfo:ksu` / `mountinfo:magisk` replaces generic `debug_ramdisk_mount`; shares `root_fw` family with `root` to prevent double-scoring.

## Result State Mapping

- **Strong finding (`statx_mnt_id_hidden`, `isolated_mount_diff:root:*`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 8`, `informational = false` (actionable in all 4 scenes).
- **Medium finding (`mountinfo:ksu`, `mountinfo:magisk`, `system_ro_rw_mount`, `statfs_overlay_on_system`, `statfs_tmpfs_on_system`, `mount_mtime_mismatch`, `isolated_mount_diff:hidden:*`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = false`.
- **Clean with usable checks**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
- **All mount sources unreadable**: `DetectionExecutionStatus.UNAVAILABLE` (never escalates to `DANGER`).
