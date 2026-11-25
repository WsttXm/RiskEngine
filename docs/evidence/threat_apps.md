# Evidence Contract Record — `threat_apps`

- **Detector**: `threat_apps` (`ThreatAppDetector`)
- **ScanTier**: `POSTPONED` (5s detector budget, per-probe `SafeExecutor.safeWithTimeoutOrInline`)
- **EvidenceFamily**: `root_fw` (for Root managers — deduplicated automatically with `root` and `mount_analysis`), `hma_hiding` (for HMA / HMA-OSS / Thanox behavioral side-channels), `threat_app` (for general signed threat tools & custom policy matches)
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| `ThreatAppPackageProbe` (`ThreatAppSignatureLibrary` + `ThreatAppPolicy`) | `root_manager_cert`, `root_manager_native_payload`, `root_manager_zygote_preload`, `threat_app_cert`, `threat_app_package`, `threat_app_perm_combo`, `hma_app_cert` | `root_fw` / `hma_hiding` / `threat_app` | `STRONG` / `MEDIUM` | Full v2/v3/v3.1 cert lineage (`apkContentsSigners` + `signingCertificateHistory`) against 10+ official release SHA-256 certs (KernelSU, KSU-Next, SukiSU, Magisk, APatch, HideMyApplist, HMA-OSS, LSPosed, GameGuardian, LuckyPatcher, Shizuku), `Os.stat` on `nativeLibraryDir` (`libksud.so`, `libapd.so`, `libmagisk.so`), public manifest XML `android:zygotePreloadName`, and custom `ThreatAppPolicy` rules |
| `HmaUidVisibilityProbe` (`hma_uid_probe.cpp` via `disposable_child`) | `hma_uid_visibility_hidden`, `hma_seccomp_notif_intercept` | `hma_hiding` | `STRONG` | Disposable-child `syscall(__NR_getpriority, PRIO_USER, uid)` active-app-UID cross-checked against uncached Binder `getPackagesForUid` (when host holds `QUERY_ALL_PACKAGES`), plus zero-permission Linux `>= 5.0` `SECCOMP_FILTER_FLAG_NEW_LISTENER` user-notif interception check |
| `HmaCrossUserProbe` | `hma_cross_user_exception_suppressed` | `hma_hiding` | `STRONG` | Cross-user `MATCH_ANY_USER` exception suppression where HMA returns `NameNotFoundException` or `null` instead of `SecurityException`, validated against pre/post self-controls |
| `HmaOrderedBroadcastProbe` | `hma_broadcast_result_to_missing`, `hma_broadcast_ordered_flag_leak` | `hma_hiding` | `STRONG` | Detects HMA-OSS #164 (missing final `resultTo` callback) and HMA-OSS #173 (erroneous `isOrderedBroadcast() == true`) using initial & interleaved before/between/after host self-control broadcasts on a background `HandlerThread` |
| `HmaPermissionServiceProbe` | `hma_permission_service_uid_diff` | `hma_hiding` | `STRONG` | API `>= 35` diff between `PermissionService` (`Context.checkPermission(perm, -1, uid)` / typed `IBinder.transact` + `Parcel` wire helpers) and `getPackagesForUid` under strict 1000ms wall-clock budget (truncated scans -> `PARTIAL`) |
| `ThanoxIpcProbe` | `thanox_dropbox_ipc` | `hma_hiding` | `STRONG` | Queries `dropbox` Binder service and strictly verifies `interfaceDescriptor == "github.tornaco.android.thanos.core.IThanos"` |

## Producing Subsystem

- Android `PackageManager` (`GET_SIGNING_CERTIFICATES`, `getResourcesForApplication().getAssets().openXmlResourceParser("AndroidManifest.xml")`, `getPackagesForUid`, `MATCH_ANY_USER`) over curated `<queries>` packages synced 1:1 with `artifact_paths.ini` `[threat_app_packages]`.
- Linux kernel `__NR_getpriority(PRIO_USER, uid)` and `SECCOMP_FILTER_FLAG_NEW_LISTENER` executed strictly inside `util/disposable_child` (`hma_uid_probe.cpp`).
- Android `ActivityManager` ordered broadcast delivery, `PermissionManagerService` (API 35+), and `ServiceManager` / `dropbox` Binder interface descriptor.

## Mechanism (AOSP/Linux/ACK)

- **Zero Blocked Hidden-API & Zero `<uses-permission>` (`D66`, `D74`, `D76`)**: Reads `android:zygotePreloadName` via public `openXmlResourceParser("AndroidManifest.xml")` (zero `HiddenApiBypass`), avoids `getInstalledPackages` completely, and uses public APIs / frozen Binder `IBinder.transact` + `Parcel` wire protocol across all HMA probes.
- **Disposable-Child Native HMA Side-Channel (`D75`)**: Executes both `getpriority(PRIO_USER)` scanning and `SECCOMP_FILTER_FLAG_NEW_LISTENER` integrity probing inside a mutually-excluded, dual-deadline `fork()` child with pre-fork raw Bionic `sigaction` reset and raw `__NR_exit_group` termination (zero host seccomp/SIGSYS/tombstone risk).
- **Self-Control-Gated Behavioral Side-Channels (`D75`, `D76`)**: `HmaUidVisibilityProbe`, `HmaCrossUserProbe`, `HmaOrderedBroadcastProbe`, and `HmaPermissionServiceProbe` all require valid pre/post (or interleaved) self-controls and repeat confirmation on suspect targets before emitting any finding.

## Applicable API Range

- **`ThreatAppPackageProbe`, `HmaCrossUserProbe`, `HmaOrderedBroadcastProbe`, `ThanoxIpcProbe`**: Android 11–17 (API 30–37), all 4 ABIs.
- **`HmaUidVisibilityProbe`**: `seccomp-notif` requires Linux kernel `>= 5.0` (cleanly `UNSUPPORTED` on older kernels); foreign-UID vs `getPackagesForUid` cross-check runs only when the host holds `QUERY_ALL_PACKAGES`.
- **`HmaPermissionServiceProbe`**: Strictly gated to Android 15–17 (API `>= 35`) and host `QUERY_ALL_PACKAGES` (returns `UNSUPPORTED`/`UNAVAILABLE` cleanly otherwise).

## Visibility Boundaries

- Zero `<uses-permission>` (especially zero `QUERY_ALL_PACKAGES`) is declared in `riskengine-sdk/src/main/AndroidManifest.xml`; package checks cover only curated `<queries>` entries plus host-configured `ThreatAppPolicy` targets, and foreign-UID cross-checks cleanly skip when the host lacks `QUERY_ALL_PACKAGES`.
- Renamed packages not listed in `<queries>` and hidden from all behavioral side-channels remain outside core zero-permission package visibility.
- Budget truncation in `HmaUidVisibilityProbe`, `HmaOrderedBroadcastProbe`, or `HmaPermissionServiceProbe` (1000ms hard cap) surfaces `DetectionExecutionStatus.PARTIAL` rather than silently claiming clean or escalating to `DANGER`.

## False-Positive Defenses

- **OriginOS / Stock `dropbox` filter (`D76`)**: `ThanoxIpcProbe` strictly requires exact `interfaceDescriptor.equals("github.tornaco.android.thanos.core.IThanos")`, ignoring stock Android and OriginOS `dropbox` Binder replies with zero FP.
- **Zero-permission Android 11+ UID visibility guard (`D75`)**: Gates the foreign-UID vs `getPackagesForUid` cross-check on runtime `QUERY_ALL_PACKAGES` permission plus pre/post self-controls and single-UID TOCTOU recheck so stock Android 11+ package visibility filtering never triggers `hma_uid_visibility_hidden`.
- **Control-failure fail-closed (`D76`)**: Any self-control failure across `HmaCrossUserProbe`, `HmaOrderedBroadcastProbe`, or `HmaPermissionServiceProbe` degrades cleanly to `UNAVAILABLE` (0 findings) and never promotes invalidated runs to `PARTIAL` or `DETECTED`.
- **Root manager family deduplication (`D77`)**: Root manager hits (`root_manager_*`) map to `root_fw` so they automatically deduplicate with `root` and `mount_analysis` in `DataAggregator`, while HMA behavioral side-channels map to orthogonal `hma_hiding`.

## Result State Mapping

- **HMA / Thanox behavioral side-channel hit (`hma_hiding` family)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 7`, `informational = false` (actionable in all 4 scenes).
- **Signed threat tool / Root manager / custom `ThreatAppPolicy` hit (`root_fw` / `threat_app` / `hma_app_cert`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 5`, `informational = false` (actionable in all 4 scenes).
- **Clean with budget truncation**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `DetectionExecutionStatus.PARTIAL`, `score = 0`.
- **Clean (including visibility-limited/unsupported probes)**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
