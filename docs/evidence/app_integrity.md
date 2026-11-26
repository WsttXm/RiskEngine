# Evidence Contract Record — `app_integrity`

- **Detector**: `app_integrity` (`AppIntegrityDetector`, backed by native `apk_sig_native.cpp`)
- **ScanTier**: `CRITICAL`
- **EvidenceFamily**: `app_tamper`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java package name pinning | `pkg_name_mismatch` | `app_tamper` | `STRONG` (Hard Trigger) | Runtime `Context.getPackageName()` or `ApplicationInfo.packageName` differs from host-configured `RiskEngineConfig.expectedPackageName` |
| Java + Native APK Signing Scheme v2/v3/v3.1 | `apk_sig_mismatch` | `app_tamper` | `STRONG` (Hard Trigger) | Active signer(s) (`apkContentsSigners` or `signingCertificateHistory[last]`, never `history[0]`) fail configured `expectedSigningCertSha256Base64`, or `apkContentsSigners[0]` contradicts `signingCertificateHistory[last]` |
| Java vs Native cross-verification | `apk_native_java_sig_conflict` | `app_tamper` | `STRONG` (Hard Trigger) | Native raw-syscall `base.apk` Signing Block active signer(s) or v3/v3.1 rotation lineage conflict with Java `PackageManager` `SigningInfo` (exposes Binder/PM hooks) |
| Install source audit | `unofficial_installer` | `app_tamper` | `MEDIUM` | API 30+ `PackageManager.getInstallSourceInfo()` installer/initiating package is outside `DEFAULT_TRUSTED_INSTALLER_PACKAGES` (or host `trustedInstallerPackages` override); skipped on `FLAG_DEBUGGABLE` |
| Release obfuscation sentinel | `release_unobfuscated` | `app_tamper` | `WEAK` | Unkept `ObfuscationSentinel` retains its literal unobfuscated simple class name in a non-debuggable release build (skipped on `FLAG_DEBUGGABLE`) |

## Producing Subsystem

- Android `PackageManager` (`GET_SIGNING_CERTIFICATES`, `getInstallSourceInfo`) and `ApplicationInfo`.
- Native raw Linux syscalls (`my_openat`/`my_fstatat(AT_EMPTY_PATH)`/`my_pread64`/`my_close`) reading the host APK's ZIP EOCD, Central Directory adjacency, and `"APK Sig Block 42"` (`v2`/`v3`/`v3.1` + Proof-of-Rotation `0x3ba06f8c`).
- JVM/ART class metadata (`ObfuscationSentinel.class.getSimpleName()`).

## Mechanism (AOSP/Linux/ACK)

- **Native APK Signing Block Parser (`apk_sig_native.cpp`, `D16`)**: Resolves `base.apk` path via `/proc/self/maps` priority (`exact_pkg_match` > `fallback_maps_match` > `data_app_match` > `fallback`), validates ZIP EOCD + exact Central Directory adjacency + `"APK Sig Block 42"` header/footer parity, parses v2/v3/v3.1 signer certificates and Proof-of-Rotation v1 lineage using bounded `new (std::nothrow)` buffers (2 MiB/scheme, 256 lineage cap), and emits 64-char hex + 44-char standard Base64 SHA-256 digests over `NativePayloadCodec`.
- **AOSP Scheme Precedence & Anti-Smuggling (`D17`)**: Selects effective native scheme using AOSP precedence (`sdkInt >= 33`: `v3.1 > v3 > v2`; otherwise `v3 > v2`), validates **ALL** `apkContentsSigners` even when `hasMultipleSigners() == false` (blocking multi-signer smuggling), and validates active signer against `signingCertificateHistory[last]` (closing v3 key-rotation bugs that mistakenly inspect `history[0]`).
- **R8-Resilient `ObfuscationSentinel` (`D17`)**: Constructs the expected literal name at runtime so R8 identifier-name-string rewriting cannot accidentally rewrite the comparison target; omits `ObfuscationSentinel` from `consumer-rules.pro`.

## Applicable API Range

- Android 11–17 (API 30–37), all 4 ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`). `v3.1` (`0x1b93ad61`) precedence applies on API `>= 33`.

## Visibility Boundaries

- If the host does not configure `expectedPackageName` or `expectedSigningCertSha256Base64`, pinning checks are cleanly skipped (zero FP); Java-vs-Native `apk_native_java_sig_conflict` still runs automatically!
- Legacy v1-only JAR-signed APKs (no APK Signing Block) return native `UNSUPPORTED` without false positives or degrading a clean device to `UNKNOWN`.
- `getInstallSourceInfo()` returning `null` (sideloaded via ADB or local installer) is reported as `unofficial_installer` only on non-debuggable builds.

## False-Positive Defenses

- **Unconfigured pinning zero-FP**: Never flags missing pins; hosts opt into pinning via `RiskEngineConfig.Builder`.
- **Debuggable-build exemptions (`D17`)**: Automatically skips `release_unobfuscated` and `unofficial_installer` when `(appFlags & ApplicationInfo.FLAG_DEBUGGABLE) != 0` so local Android Studio / ADB builds stay zero-FP.
- **Exact-prefix `EvidenceFamily` precedence (`D17`)**: Prevents an embedded package name (e.g. containing `"magisk"` or `"proxy"`) inside `pkg_name_mismatch:` from polluting unrelated evidence families.
- **Tri-state `DevicePosture.unofficialStore` (`D24`)**: Populated in `DataAggregator` only when `app_integrity` executed cleanly.

## Result State Mapping

- **Hard tamper (`pkg_name_mismatch`, `apk_sig_mismatch`, `apk_native_java_sig_conflict`)**: `RiskLevel.DEADLY`, `DetectionStatus.DANGER`, `score = 10`, `informational = false`, reported in `RiskReport.getHardTriggers()` (elevates overall report to `DEADLY` with a `95–100` score floor across all 4 scenes unless suppressed by `RiskPolicy`).
- **Unofficial installer (`unofficial_installer`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = true` in `STANDARD`/`LOGIN` (actionable in `PAYMENT`/`DIAGNOSTIC`).
- **Unobfuscated release (`release_unobfuscated`)**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 2`, `informational = true` in `STANDARD`/`LOGIN` (actionable in `PAYMENT`/`DIAGNOSTIC`).
- **Clean**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
