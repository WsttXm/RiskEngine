# Evidence Contract Record — `consistency`

- **Detector**: `consistency` (`ConsistencyDetector`)
- **ScanTier**: `FAST` (Treble partition fingerprints, `Build` vs properties, core/ABI/API/kernel parity, `BootloaderProbe` fast pass, `BionicPropProbe`, `PlayIntegrityFixProbe`) + `POSTPONED` (ARM64 EL0 `MIDR_EL1`, Hardware Key Attestation `RootOfTrust`, `WidevineParityProbe`)
- **EvidenceFamily**: `prop_tamper`, `boot_integrity`, `hw_spoof`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java / Native Build & Treble parity | `partition_fingerprint_mismatch`, `build_prop_mismatch`, `core_count_mismatch`, `abi_arch_mismatch`, `api_release_mismatch`, `fingerprint_shape_anomaly` | `prop_tamper` / `hw_spoof` | `STRONG` / `WEAK` | Cross-checks `android.os.Build.*` vs native `__system_property_get`, partition fingerprints (`ro.build.fingerprint` vs `ro.system/vendor/product/odm.build.fingerprint`), CPU core counts, and ABI/architecture consistency |
| 3-Source Kernel Identity | `kernel_uname_proc_mismatch`, `kernel_java_native_mismatch` | `prop_tamper` | `STRONG` | Compares raw Linux `__NR_uname`, `/proc/version` (or `/proc/sys/kernel/osrelease`), and Java `System.getProperty("os.version")` to expose SUSFS `newuname` hooks |
| `BionicPropProbe` (`bionic_prop_area.cpp`) | `prop_area_hole_run`, `prop_area_dirty_serial`, `prop_area_nul_tail`, `prop_area_dirty_backup` | `prop_tamper` | `STRONG` / `MEDIUM` | Direct read-only `MAP_PRIVATE` inspection of `/dev/__properties__/*` binary Bionic `prop_area` tries detecting `resetprop --delete` holes (`adbd_config_prop`/`shell_prop` highlighted), modified `serial[23:1]` on 18 security-critical `ro.*` properties, inline NUL-tail residue, and API 30+ 92-byte `dirty_backup_area` |
| `PlayIntegrityFixProbe` | `pif_prop_present`, `pif_spoof_contradiction` | `prop_tamper` | `STRONG` / `MEDIUM` | Native detection of `persist.sys.pihooks*`, `persist.sys.pixelprops*`, `persist.sys.spoof.gms`, and PIF fingerprint contradictions |
| `BootloaderProbe` (FAST + `POSTPONED` Hardware `RootOfTrust`) | `vbmeta_empty_input_digest`, `spoofed_verified_boot_props`, `hw_bootloader_unlocked`, `hw_verified_boot_orange`, `bootloader_unlocked`, `verified_boot_state:orange`, `samsung_knox_warranty_void` | `boot_integrity` | `STRONG` / `MEDIUM` / `WEAK` | 21 Boot/AVB/Knox properties, `/proc/bootconfig`, `/proc/cmdline`, Specter empty-input SHA-256/SHA-512 VBMeta digest trap, and Hardware Key Attestation `RootOfTrust` (`verifiedBootState`/`deviceLocked`) cross-checked against `ro.boot.verifiedbootstate=green` + `ro.boot.flash.locked=1` (`C8:spoofed_verified_boot` `DEADLY/10`) |
| `POSTPONED` ARM64 `MIDR_EL1` | `midr_sysfs_mismatch`, `midr_cpuinfo_mismatch`, `sysfs_cpuinfo_mismatch` | `hw_spoof` | `STRONG` | Disposable-child EL0 `mrs MIDR_EL1` (3 agreeing same-core `my_getcpu`-bracketed reads, `0xfff0ffff` mask) compared against `/sys/devices/system/cpu/cpuN/regs/identification/midr_el1` and `/proc/cpuinfo` |
| `POSTPONED` `WidevineParityProbe` (`widevine_ndk_probe.cpp`) | `widevine_java_ndk_mismatch`, `widevine_l1_sentinel_system_id`, `widevine_hw_session_downgrade` | `hw_spoof` | `STRONG` / `MEDIUM` | Dynamic `dlopen("libmediandk.so")` `AMediaDrm` non-PII `securityLevel`/`systemId` compared against Java `MediaDrm`, plus L1 sentinel `systemId=2147483647` and `HW_SECURE_ALL` downgrade check |

## Producing Subsystem

- Android `init` Bionic property service (`/dev/__properties__` shared-memory tries and `/dev/__properties__/property_info` contexts table).
- Linux kernel `utsname` (`__NR_uname`), `/proc/{version,cmdline,bootconfig,cpuinfo}`, and `/sys/devices/system/cpu/*/regs/identification/midr_el1`.
- ARM64 CPU EL0 `MIDR_EL1` register (trapped & emulated by kernel under `HWCAP_CPUID`).
- Android Hardware Keystore / KeyMint `RootOfTrust` attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`) and Widevine DRM (`MediaDrm` + `libmediandk.so`).

## Mechanism (AOSP/Linux/ACK)

- **Bionic `prop_area` Binary Forensics (`D31`, `D45`)**: Opens `/dev/__properties__/property_info` (`DiskPropertyInfoHeader` contexts table, with 8-context direct fallback when `0711` `/dev/__properties__` denies `getdents64`) using `O_RDONLY | O_CLOEXEC | O_NOFOLLOW` + `MAP_PRIVATE`. Performs iterative DFS (`kMaxVisitedNodes = 65536`) to locate deleted trie holes (`resetprop --delete`), checks `serial[23:1]` (masking `kLongFlag = 1U << 16`) on 18 security-critical `ro.*` properties, skips inline `value[92]` NUL-tail scans on long properties, and checks `dirty_backup_area` on API `>= 30`. Never inspects `st_mtime`.
- **Hardware `RootOfTrust` vs Boot Properties (`D52`)**: When Hardware Key Attestation proves `deviceLocked == false` or `verifiedBootState != VERIFIED` (or `vbmeta_empty_input_digest` matches SHA-256/SHA-512 of empty bytes `e3b0c442...` / `cf83e135...`) while `ro.boot.verifiedbootstate=green` and `ro.boot.flash.locked=1`, emits `spoofed_verified_boot_props`, triggering `CorrelationEngine` `C8:spoofed_verified_boot` (`DEADLY/10` hard trigger).
- **ARM64 `MIDR_EL1` Big.LITTLE Clamping (`D32`)**: Executes inside `disposable_child` gated by `HWCAP_CPUID`; brackets each `mrs` instruction with `my_getcpu()` before and after and requires 3 agreeing same-core readings before comparing masked `0xfff0ffff` IDs.
- **Widevine Dynamic NDK Probe (`D53`)**: Loads `libmediandk.so` dynamically via `dlopen`/`dlsym` (zero link-time `DT_NEEDED`), releases `AMediaDrm` via RAII strictly before `dlclose`, and reads only non-PII `securityLevel` and `systemId` (64-byte ASCII bounded).

## Applicable API Range

- **Treble, Build/Prop parity, 3-Source Kernel, `BionicPropProbe`, `PlayIntegrityFixProbe`, `BootloaderProbe`**: Android 11–17 (API 30–37), all 4 ABIs (`dirty_backup_area` gated to `sdk >= 30`).
- **ARM64 `MIDR_EL1`**: `arm64-v8a` with `HWCAP_CPUID` (cleanly `UNSUPPORTED` on 32-bit/x86).
- **Hardware `RootOfTrust`**: API 30–37 when `enableTeeAttestation` is enabled and hardware attestation is available.
- **Widevine Parity**: API 30–37 on devices shipping `libmediandk.so` and Widevine CDM (`UNAVAILABLE` cleanly otherwise).

## Visibility Boundaries

- SELinux restrictions on `/proc/bootconfig`, `/proc/cmdline`, `/sys/.../midr_el1`, or unprovisioned Keybox / absent Widevine CDM degrade individual sub-probes to `UNAVAILABLE`/`UNSUPPORTED` without producing false positives or lowering `SAFE` to `UNKNOWN`.
- `utsname` fields are capped at 64 bytes by Linux ABI; strings longer than 64 bytes truncate naturally in `__NR_uname`.

## False-Positive Defenses

- **OEM sub-brand & MISSI/QSSI normalization (`D46`)**: Normalizes same-family OEM sub-brands (`xiaomi`/`redmi`/`poco`, `oppo`/`oneplus`/`realme`/`oplus`, `vivo`/`iqoo`, `huawei`/`honor`), ignores SoC reference prefixes (`qti`/`qualcomm`/`mediatek`/`mtk`/`sprd`/`unisoc`/`android`), and compares `ro.build.fingerprint` vs `ro.system.build.fingerprint` by brand family + Android major release rather than raw string equality (validated on Xiaomi 15 HyperOS 2).
- **Samsung-only Knox gate (`D52`)**: `ro.boot.warranty_bit` / `ro.warranty_bit` is checked strictly on Samsung devices (`Build.MANUFACTURER` / `BRAND`).
- **64-byte `utsname` truncation tolerance (`D32`)**: `matchesUtsField()` tolerates 64-byte Linux `utsname` truncation including trimmed boundary whitespace.
- **`prop_area` long-property & `st_mtime` guards (`D31`)**: Masks `kLongFlag` (`1U << 16`), skips inline `value[92]` NUL-tail scans on long properties (e.g. long OEM `ro.build.fingerprint`), and strictly never inspects `st_mtime`.
- **Honest unlocked vs spoofed green boot (`D04`, `D52`)**: Property-only `bootloader_unlocked`/`verified_boot_state:orange` is `MEDIUM/4` informational in `STANDARD` and elevates in `LOGIN`/`PAYMENT`; hardware-confirmed unlock is actionable `MEDIUM/5` (`HIGH/7` in `LOGIN`/`PAYMENT`); only contradiction with spoofed green/locked props triggers `C8` `DEADLY/10`.

## Result State Mapping

- **Strong tampering (`partition_fingerprint_mismatch`, `build_prop_mismatch`, `kernel_*_mismatch`, `prop_area_hole_run`, `prop_area_dirty_serial`, `vbmeta_empty_input_digest`, `spoofed_verified_boot_props`, `midr_*_mismatch`, `widevine_java_ndk_mismatch`)**: `RiskLevel.HIGH`, `DetectionStatus.DANGER`, `score = 8`, `informational = false` (`vbmeta_empty_input_digest` + `C8` escalates to `DEADLY/10` hard trigger).
- **Medium actionable (`hw_bootloader_unlocked`, `hw_verified_boot_orange`, medium `prop_area`/`PIF`/Widevine hits)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 5`, `informational = false` (hardware unlock elevates to `HIGH/7` in `LOGIN`/`PAYMENT`).
- **Property-only bootloader unlock (`bootloader_unlocked`, `verified_boot_state:orange`)**: `RiskLevel.MEDIUM`, `DetectionStatus.WARNING`, `score = 4`, `informational = true` in `STANDARD` (actionable in `LOGIN`/`PAYMENT`).
- **Weak format/prop anomalies**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 2`, `informational = true`.
- **Clean with usable checks**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
