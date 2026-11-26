# Evidence Contract Record — `custom_rom`

- **Detector**: `custom_rom` (`CustomRomDetector`)
- **ScanTier**: `FAST`
- **EvidenceFamily**: `custom_rom`
- **Status**: `reviewed`

## Observable Signals

| Layer / Probe | `EvidenceItem` Code(s) | Family | Rank | Signal Summary |
| :--- | :--- | :--- | :---: | :--- |
| Java System Properties | `community_rom` | `custom_rom` | `WEAK` | Presence of community ROM version properties: `ro.lineage.version` (LineageOS), `ro.cm.version` (CyanogenMod), `ro.mokee.version` (MoKee), `ro.rr.version` (ResurrectionRemix), `ro.pixelexperience.version` (PixelExperience), `ro.modversion` |
| Native `build.prop` parity | `prop_mismatch` | `custom_rom` | `WEAK` | Disk `build.prop` `ro.build.fingerprint` differs from runtime `ro.build.fingerprint` (skipped on HarmonyOS) |
| Native `custom_rom_probe.cpp` | `stagefright_custom_symbol`, `framework_res_multi_dev` | `custom_rom` | `WEAK` | Presence of `_ZN7android15ANetworkSession10threadLoopEv` in `libstagefright.so` (disk ELF `.dynsym`/`.symtab` + `dlopen(RTLD_NOLOAD)`/`dlsym`), or `framework-res.apk` mapped across `> 1` distinct non-zero block devices (skipped on HarmonyOS) |

## Producing Subsystem

- Android `SystemProperties` (`ro.lineage.version`, `ro.cm.version`, `ro.mokee.version`, `ro.rr.version`, `ro.pixelexperience.version`, `ro.modversion`, `ro.build.fingerprint`) and `/system/build.prop`.
- Native `libstagefright.so` ELF symbol tables (`.dynsym`/`.symtab` via raw `my_openat`/`my_mmap` and in-memory `dlopen(RTLD_NOLOAD)`/`dlsym`) and `/proc/self/maps` block device accounting for `framework-res.apk`.
- Huawei HarmonyOS brand query via guarded `com.huawei.system.BuildEx.getOsBrand()` reflection.

## Mechanism (AOSP/Linux/ACK)

- **Community ROM Property Audit**: Checks 6 curated aftermarket ROM version properties while explicitly excluding stock OEM distributions (HyperOS, OneUI, ColorOS, OriginOS, HarmonyOS).
- **Custom Stagefright Symbol & Multi-Device Framework Probe (`D33`)**: Aftermarket AOSP builds (LineageOS / CAF derivatives) commonly compile legacy or custom `ANetworkSession::threadLoop()` symbols into `libstagefright.so` or overlay `framework-res.apk` across multiple block devices; native `custom_rom_probe.cpp` checks both disk ELF tables and live process mappings safely.
- **Informational-Only Context Policy**: A community ROM is treated strictly as device-context telemetry, never proof of compromise or root.

## Applicable API Range

- Android 11–17 (API 30–37), all 4 ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).

## Visibility Boundaries

- Custom ROMs that strip community `ro.*` properties and match stock `libstagefright.so` / `framework-res.apk` layouts will not trigger `custom_rom`.
- If `ro.build.fingerprint` is unavailable, `CustomRomDetector` returns `UNAVAILABLE("system_properties_unavailable")` rather than misclassifying.
- Guarded reflection on `com.huawei.system.BuildEx.getOsBrand()` catches `Exception | LinkageError` and returns `""` cleanly on all non-Huawei devices.

## False-Positive Defenses

- **Authentic Google Pixel exemption (`D33`)**: Suppresses `ro.pixelexperience.version` on authentic `google/Pixel*` devices (`isAuthenticGooglePixel`).
- **HarmonyOS exemption (`D33`)**: When `com.huawei.system.BuildEx.getOsBrand()` returns `"harmony"`, suppresses both `build.prop` fingerprint mismatch and `framework_res_multi_dev` to avoid false positives on Huawei HarmonyOS multi-partition overlays.
- **Strictly `LOW/1` informational (`D33`)**: All `custom_rom` findings are locked to `RiskLevel.LOW`, `score = 1`, `informational = true` in `STANDARD`, `LOGIN`, and `PAYMENT` scenes (actionable ONLY in `DIAGNOSTIC`).

## Result State Mapping

- **Any community ROM / `stagefright_custom_symbol` / `framework_res_multi_dev` / `prop_mismatch` hit**: `RiskLevel.LOW`, `DetectionStatus.WARNING`, `score = 1`, `informational = true` (actionable only in `DIAGNOSTIC`).
- **No hits with readable properties**: `RiskLevel.SAFE`, `DetectionStatus.NORMAL`, `score = 0`.
- **Properties unreadable**: `DetectionExecutionStatus.UNAVAILABLE`.
