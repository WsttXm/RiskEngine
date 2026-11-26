# Evidence Contract Record — `multi_instance`

- **Detector**: `multi_instance` (`MultiInstanceDetector`)
- **ScanTier**: `FAST` (directory depth/owner/userId audit, `Process.myUid()` vs `Os.stat().st_uid`, sanitized `/proc/self/maps` multi-APK & container library scan, dynamic `Proxy$` Binder wrapper check) + `POSTPONED` (`disposable_child` `sacrificial_syscall_pack` libc-vs-raw syscall interception trap)
- **EvidenceFamily**: `virtual_container`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java App Data Path & UID Audit | `nested_container_path`, `user_id_path_mismatch`, `data_dir_uid_mismatch` | `virtual_container` | `STRONG` | Nested VirtualApp/ParallelSpace/BlackBox path depth or container engine segments in `filesDir`/`dataDir`/`sourceDir`, `uid/100000` disagreeing with `/data/user/<uId>/`, or `Process.myUid() != Os.stat().st_uid` |
| Java OEM Dual-App Space | `oem_dual_app_user` | `virtual_container` | `WEAK` | Process running under known OEM dual-app/clone user IDs (`999`, `>= 900`, `95`, `128..150`) with consistent path ownership |
| Java `/proc/self/maps` Sanitized Audit | `multi_apk_maps`, `container_native_lib` | `virtual_container` | `STRONG` | Foreign third-party `/data/app/.../*.apk` mapped alongside host APK (after `InstallTokenSanitizer` stripping & WebView/GMS allowlist) or container engine native libraries (`libva*.so`, `libblackbox.so`, `libdkhelper.so`, `libdualspace.so`, `libparallel.so`, `libvirtualapp.so`) |
| Java Dynamic Binder Proxy Audit | `dynamic_binder_proxy` | `virtual_container` | `MEDIUM` / `STRONG` | Runtime `java.lang.reflect.Proxy` (`Proxy$`) wrapping public framework handles (explicitly excluding standard AIDL `$Stub$Proxy`) |
| `POSTPONED` `virtualization_traps.cpp` | `sacrificial_syscall_mismatch` | `virtual_container` | `STRONG` | Disposable-child libc `syscall()` vs raw inline-asm `asm_syscall6` parity mismatch across Child 1A (`statx`, `memfd_create`, `renameat2`) and Child 1B (`openat2`, `pidfd_open`) exposing user-space syscall virtualization/interception |

## Producing Subsystem

- Android `Context` paths (`filesDir`, `dataDir`, `sourceDir`), `Process.myUid()`, and POSIX `Os.stat()`.
- Linux `/proc/self/maps` processed through `InstallTokenSanitizer.stripInstallTokens()`.
- Java dynamic proxy reflection metadata (`Proxy.isProxyClass` / class name inspection, zero hidden-API reflection).
- Linux kernel syscall interface exercised in two split `util/disposable_child` processes (`virtualization_traps.cpp`).

## Mechanism (AOSP/Linux/ACK)

- **Zero Hidden-API Design (`D18`)**: Deliberately avoids fragile non-SDK reflection (`BaseDexClassLoader.pathList`) and instead uses canonical public paths, `uid / 100000` multi-user arithmetic, `Os.stat().st_uid`, and sanitized `/proc/self/maps`.
- **Android Base64 Install-Token Hygiene (`InstallTokenSanitizer`, `D18`)**: Strips random 22–24 char Base64/Base64URL segments (`~~<token>==` and `<pkg>-<token>==`) from `/data/app/...` paths before checking container keywords or extracting APK owner package names, eliminating random-token false positives (`va`, `ksu`, `Riru`).
- **Split Seccomp-Safe `sacrificial_syscall_pack` (`D42`)**: Executes in `detectPostponed()` inside two separate zero-allocation `disposable_child` processes — Child 1A (`statx`/`memfd_create`/`renameat2`) and Child 1B (`openat2`/`pidfd_open`) — so Android 11 seccomp `SIGSYS` on newer syscalls (`openat2`/`pidfd_open`) terminates only Child 1B cleanly without disrupting Child 1A's core parity checks.

## Applicable API Range

- **FAST path & Child 1A (`statx`/`memfd_create`/`renameat2`)**: Android 11–17 (API 30–37), both 64-bit ABIs (`arm64-v8a`, `x86_64`).
- **Child 1B (`openat2`/`pidfd_open`)**: Supported kernels/seccomp policies (gracefully skipped on Android 11 seccomp `SIGSYS`).

## Visibility Boundaries

- Virtual containers that fully hook `/proc/self/maps`, `Os.stat()`, and Java paths while running natively without user-space syscall interception may hide FAST-layer path markers; `sacrificial_syscall_mismatch` targets user-space syscall translators.
- Standard Android Work Profiles (`userId 10..89`) with consistent `uid` and path ownership are legitimately indistinguishable from isolated enterprise profiles and are intentionally NOT flagged.

## False-Positive Defenses

- **Primary user `0` & Work Profile `10..89` exemption (`D18`)**: Zero false positives on primary user `0` and legitimate Android Enterprise Work Profiles (`10..89`) when path user ID matches `uid / 100000`.
- **OEM Dual-App informational tiering (`D18`)**: OEM dual-app spaces (`999`, `>= 900`, `95`, `128..150`) score strictly `LOW/2` informational in `STANDARD` and elevate to actionable only in `LOGIN`/`PAYMENT`.
- **Shared system/WebView/GMS APK allowlist**: Exempts legitimate mapped system APKs (`com.google.android.webview`, `com.google.android.trichromelibrary`, `com.android.chrome`, `com.google.android.gms`, `com.huawei.webview`, `com.heytap.webview`, `com.xiaomi.webview`, `com.android.vending`, etc.) from `multi_apk_maps`.
- **AIDL `$Stub$Proxy` exclusion**: Distinguishes real dynamic `java.lang.reflect.Proxy` wrappers from normal Android AIDL `$Stub$Proxy` binder stubs.
- **`InstallTokenSanitizer` pre-cleaning**: Prevents random Base64 install tokens from triggering container substring matches.

## Result State Mapping

- **Strong virtual container / syscall virtualization (`nested_container_path`, `user_id_path_mismatch`, `data_dir_uid_mismatch`, `multi_apk_maps`, `container_native_lib`, `dynamic_binder_proxy`, `sacrificial_syscall_mismatch`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 5`, `informational = false` (actionable in all 4 scenes).
- **OEM dual-app only (`oem_dual_app_user`)**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 2`, `informational = true` in `STANDARD` (actionable in `LOGIN`/`PAYMENT`).
- **Clean primary user / matching Work Profile**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
