# Evidence Contract Record — `root`

- **Detector**: `root` (`RootDetector`)
- **ScanTier**: `FAST` (core path/native/SELinux/Build.TAGS checks) + `POSTPONED` (`KernelSidechannelProbe`, `SelinuxAuditProbe`)
- **EvidenceFamily**: `root_fw` (aggregated via order-independent family-max with `mount_analysis` and Root manager matches in `threat_apps`)
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java + Native path probe | `su_binary`, `magisk_artifact`, `ksu_artifact`, `apatch_artifact`, `root_modules_dir` | `root_fw` | `STRONG` | Curated single-source paths from `artifact_paths.ini` (`DetectionLists.{SU,MAGISK,KERNELSU,APATCH,MODULE}_PATHS`, including `/system_ext/bin/su`) plus deduplicated Android `$PATH` `su` scan (`JAVA` + `NATIVE` auto-merged in `DataAggregator`) |
| Native path control | `eacces_exists`, `syscall_mismatch`, `listing_mismatch` | `root_fw` | `MEDIUM` / `STRONG` | Per-parent `ENOENT` sentinel reachability check distinguishing confirmed `EACCES` on existing restricted path vs directory permission denial |
| Native Root / SELinux | `ksu_prctl`, `selinux_context`, `root_mount_marker` | `root_fw` | `STRONG` | Direct KernelSU `prctl` magic reply, root SELinux contexts, and native mount marker hits |
| Native / Java weak markers | `busybox`, `selinux_permissive`, `test_keys` | `root_fw` | `WEAK` | Generic BusyBox binary, `/sys/fs/selinux/enforce == 0`, or `Build.TAGS` containing `test-keys` (strictly informational) |
| `POSTPONED` `KernelSidechannelProbe` | `kernelpatch_supercall_hello`, `kernelpatch_truncate_hit`, `ksu_reboot_ioctl`, `susfs_setresuid_anomaly`, `ksu_prctl_timing` | `root_fw` | `STRONG` / `MEDIUM` | Disposable-child KernelPatch `sys_truncate` (`0x8000000000001000LL` supercall hello `0x11581158` + `mincore` residency), KernelSU `reboot`+`ioctl`, SUSFS `setresuid` trap, and ARM64 `prctl(0xDEADBEEF)` 6-vector interleaved `cntvct_el0` timing (`MEDIUM` only) |
| `POSTPONED` `SelinuxAuditProbe` | `netlink_mac_leak`, `netlink_neigh_leak`, `selinux_status_abi_violation`, `selinux_status_header_anomaly`, `selinux_context_type_present`, `devpts_root_xattr` | `root_fw` | `STRONG` | SELinux `policydb_write` Netlink `RTM_GETLINK`/`RTM_GETNEIGH` boundary leaks (zero PII), `/sys/fs/selinux/status` mmap ABI/header tampering, 2-round controlled `/proc/thread-self/attr/current` context probing, and `devpts` xattr checks |

## Producing Subsystem

- Linux VFS (`faccessat`/`fstatat`/`getdents64`) and Android `$PATH` resolution.
- Linux / ACK kernel syscall dispatch (`__NR_truncate`, `__NR_reboot`, `__NR_ioctl`, `__NR_setresuid`, `__NR_prctl`), virtual counter `cntvct_el0`, and `mincore` page residency.
- Linux SELinux LSM (`selinuxfs` `/sys/fs/selinux/{enforce,status}`, `netlink_route_socket` `nlmsgtab` enforcement, `/proc/thread-self/attr/current`).

## Mechanism (AOSP/Linux/ACK)

- **Controlled Path Probing**: Raw Linux syscalls (`my_fstatat`/`my_faccessat`) probe each target alongside a non-existent sibling sentinel in the same parent directory (`is_parent_reachable_control`). Only when the sibling returns `ENOENT` (proving parent traversal succeeded) is an `EACCES` on the target emitted as `eacces_exists`.
- **KernelPatch & APatch (`kernel_sidechannel.cpp`)**: On ACK `<= 6.6` ARM64 kernels, stock `do_sys_truncate` rejects negative length before faulting the path argument page; KernelPatch's patched syscall handler reads `arg0` first (either answering `SUPERCALL_HELLO` `0x11581158` or faulting an untouched `mmap` page observed via `mincore`).
- **KernelSU / SUSFS (`disposable_child`)**: Hazardous syscalls (`reboot`, `setresuid`, `truncate+mincore`) run strictly inside a mutually-excluded, dual-deadline `fork()` child whose signal handlers are reset via pre-resolved Bionic `sigaction` (bypassing ART `libsigchain`). Stock kernels return `EPERM` to unprivileged `setresuid`; legacy SUSFS hooks kill the child with `SIGKILL`.
- **SELinux Netlink & Status ABI (`selinux_audit_probe.cpp`)**: Android 11+ (`targetSdk >= 30`) and Android 13+ deny `nlmsg_readpriv` (`RTM_GETLINK` MAC) and `nlmsg_getneigh` (`RTM_GETNEIGH`) to `untrusted_app`. Kernel-side SELinux policy reloads (`policydb_write` without preserving Android netlink config bits) re-open these dumps; MAC/IP buffers are wiped immediately with `secure_zero` and only boolean/interface-kind flags are emitted.

## Applicable API Range

- **Core path, SELinux enforce, `Build.TAGS`**: Android 11–17 (API 30–37), all 4 ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
- **KernelPatch `sys_truncate` & KernelSU `prctl` timing**: ARM64 only; negative residency trust scope restricted to Linux kernels `<= 6.6`.
- **Netlink `RTM_GETLINK` boundary**: `(sdk >= 30 && targetSdk >= 30) || sdk >= 33`.
- **Netlink `RTM_GETNEIGH` boundary**: `sdk >= 33 && targetSdk >= 32`.

## Visibility Boundaries

- Magisk DenyList, Shamiko, ZygiskNext, and KernelSU unmount modules remove or hide filesystem artifacts from the main process's mount namespace; absence of files never proves a device is unrooted.
- Unreachable parent directories (`0711` or SELinux `search` denial) mark paths unobserved rather than positive or negative; visibility loss NEVER triggers `DANGER` or degrades `SAFE` to `UNKNOWN`.
- Seccomp filters blocking `truncate`/`reboot` in `disposable_child` terminate only the child (exit code `125` via raw `__NR_exit_group`) and report `UNSUPPORTED`/`UNAVAILABLE` without crashing or creating host tombstones.
- Modern APatch (`>= 0x0d09`) uses nofault user copies for excluded `untrusted_app` UIDs; negative `mincore` residency therefore does not exclude APatch.

## False-Positive Defenses

- **Parent-reachability `ENOENT` control**: Eliminates `0711` directory `syscall_mismatch` false positives on stock Android (`D07`).
- **Java `$PATH` Android-prefix filter**: Restricts Java `$PATH` probes to Android system prefixes (`/system/`, `/system_ext/`, `/vendor/`, `/product/`, `/odm/`, `/apex/`, `/sbin`, `/su/`, `/data/`, `/debug_ramdisk/`), preventing host-JVM `/usr/bin/su` false positives (`D36`).
- **BusyBox / `selinux_permissive` / `test_keys` isolation**: Strictly capped at `LOW/1` (`Rank.WEAK`, `informational = true`), never standalone actionable root (`D36`).
- **Control-page & 2-round SELinux controls**: `mincore` requires `control_failed == 0 && control_resident == 0 && pre_resident == 0`; SELinux context probing runs 2 rounds of negative/positive/OEM controls and emits 0 findings on any control failure (`D34`, `D35`).
- **Timing corroboration cap**: ARM64 `ksu_prctl_timing` requires 3 consecutive same-core hits matching both cosine histogram and median/MAD classifiers and is capped strictly at `MEDIUM` (`D34`).
- **Single-family deduplication**: Shares `root_fw` family with `mount_analysis` and Root manager matches in `threat_apps` so overlapping root evidence never double-scores.

## Result State Mapping

- **Strong finding (`su_binary`, `magisk_artifact`, `ksu_artifact`, `apatch_artifact`, `root_modules_dir`, `ksu_prctl`, `kernelpatch_supercall_hello`, `kernelpatch_truncate_hit`, `ksu_reboot_ioctl`, `susfs_setresuid_anomaly`, `netlink_*_leak`, `selinux_status_abi_violation`, `selinux_context_type_present`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 8`, `informational = false` (actionable in all 4 `CollectScene`s; triggers `C4` / `C9` cross-detector escalation in `CorrelationEngine`, aggregated in `PRIVILEGE` via family-max + Corroboration Lift).
- **Medium finding (`eacces_exists`, `syscall_mismatch`, `ksu_prctl_timing`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = false`.
- **Weak-only finding (`busybox`, `selinux_permissive`, `test_keys`)**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 1`, `informational = true`.
- **No findings with usable checks**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0` (`SAFE` or `PARTIAL` if partial sub-checks failed).
- **All checks unavailable**: `DetectionExecutionStatus.UNAVAILABLE` (excluded from clean-device degradation).
