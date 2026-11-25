# RiskEngine v2.0.0 Adversarial & OEM Compatibility Matrix

Local-only engineering expectations and release sign-off criteria across stock OEM devices and modern adversarial stacks. This document specifies observable evidence contracts and non-functional budgets; it is **not** a bypass guide.

For per-domain signal mechanics, API ranges, visibility boundaries, and false-positive defenses, see the 16 Evidence Contract Records under [`docs/evidence/`](./evidence/).
For repeatable release validation archives, copy [`docs/validation/TEMPLATE.md`](./validation/TEMPLATE.md) into `docs/validation/YYYY-MM/`.

---

## 1. Stock OEM Clean-Device Matrix (Zero Actionable FP & Zero Crash)

Visibility loss (`SELinux` denial, missing runtime permissions, `UNSUPPORTED`, `EMPTY`) MUST NEVER escalate to `DANGER` or degrade a clean stock device from `SAFE` to `UNKNOWN`.

| OEM / Device Class | Key Platform & OEM Quirks Covered | Expected `RiskLevel` (`STANDARD`) | Expected `TrustTier` | Actionable FP Budget | Crash / Tombstone Budget |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Google Pixel** (Android 11–16, Titan M2 StrongBox) | Batch CA Issuer DN 32-hex `serialNumber` (`D67`), Trusty KeyMint non-AEAD `updateAad` (`D66`), authentic `google/Pixel*` (`custom_rom` exempt), ART `libsigchain.so` signal interposition (`D45`) | `SAFE` (or `LOW` info only if ADB/VPN on) | `STRONG_HARDWARE` | **0** | **0** |
| **Samsung** (One UI, Knox, StrongBox) | Knox `ro.boot.warranty_bit=0`, Samsung `updateAad` quirk exemption (`D56`), Work Profile (`uid/100000 in 10..89`) | `SAFE` | `STRONG_HARDWARE` / `LOCAL_VERIFIED` | **0** | **0** |
| **Xiaomi / Redmi / POCO** (HyperOS 2, Qualcomm / MediaTek) | MISSI/QSSI `ro.build.fingerprint` vs `ro.system.build.fingerprint` brand-family tolerance, stock RO OEM overlays (`/mi_ext`, `/product`), built-in `uinput-goodix`/`uinput-fpc`, MTK KeyMint `updateAad` quirk (`D46`, `D56`) | `SAFE` | `STRONG_HARDWARE` / `LOCAL_VERIFIED` | **0** | **0** |
| **OPPO / OnePlus / realme** (ColorOS) | Sub-brand family normalization (`oppo`/`oneplus`/`realme`/`oplus`), stock RO `/my_product` overlays, OEM dual-app (`user 999`) info-only in `STANDARD` | `SAFE` | `STRONG_HARDWARE` / `LOCAL_VERIFIED` | **0** | **0** |
| **vivo / iQOO** (OriginOS) | OriginOS stock `dropbox` Binder replies strictly ignored by `ThanoxIpcProbe` (requires exact `github.tornaco.android.thanos.core.IThanos`, `D76`) | `SAFE` | `STRONG_HARDWARE` / `LOCAL_VERIFIED` | **0** | **0** |
| **Huawei / HarmonyOS** | `com.huawei.system.BuildEx.getOsBrand()` custom-ROM exemption (`D33`), sub-brand family normalization (`huawei`/`honor`) | `SAFE` | `LOCAL_VERIFIED` | **0** | **0** |
| **Wi-Fi-Only Android Tablet** | Missing telephony / SIM / vibrator (`UNSUPPORTED`/`EMPTY` excluded from `checkCount`, `D04`); zero actionable alerts from `aosp_sensor` or hardware-noise tokens alone | `SAFE` | `STRONG_HARDWARE` / `LOCAL_VERIFIED` | **0** | **0** |

---

## 2. Modern Adversarial Stack Matrix (16 Converged Detection Domains)

| Adversarial Environment | Primary Converged Domain(s) | Expected `EvidenceItem` Code(s) / Family | Minimum Expected Outcome (`STANDARD`) |
| :--- | :--- | :--- | :--- |
| **Magisk** (unhidden) | `root`, `mount_analysis`, `threat_apps` | `magisk_found`, `su_found`, `root_manager_cert` (`root_fw`, family-max + Corroboration Lift) | `HIGH` / `DANGER` |
| **Magisk + Shamiko / DenyList** | `mount_analysis`, `signal_correlation`, `consistency` | `isolated_mount_diff` (`ISOLATED`), `statx_mnt_id_hidden`, `C9:stealth_root_with_unmount` (`root_fw`) | `HIGH` / `DANGER` (never silent `SAFE` when unmounted) |
| **KernelSU / KSU-Next / SukiSU** | `root`, `mount_analysis`, `threat_apps` | `ksu_found`, `ksu_prctl`, `ksu_reboot`, `ksu_ioctl`, `ksu_timing_sidechannel`, `statfs_overlay_on_system`, `root_manager_cert` / `root_manager_native_payload` (`root_fw`) | `HIGH` / `DANGER` |
| **APatch / KernelPatch** | `root`, `threat_apps` | `apatch_found`, `kernelpatch_supercall_hello` (`0x11581158`), `kernelpatch_truncate`, `root_manager_native_payload` (`libapd.so`), `root_manager_zygote_preload` (`root_fw`) | `HIGH` / `DANGER` |
| **SUSFS + `resetprop --delete` / Specter** | `consistency`, `root`, `signal_correlation` | `susfs_probe`, `prop_area_hole` / `prop_area_hole_critical`, `prop_ro_serial_modified`, `prop_ro_nul_tail_residual`, `kernel_uname_osrelease_mismatch`, `midr_sysfs_mismatch`, `vbmeta_empty_input_digest`, `C8:spoofed_verified_boot` (`prop_tamper`/`boot_integrity`/`hw_spoof`) | `HIGH` (`DEADLY` Hard Trigger, score `95–100` on `C8` / empty VBMeta) |
| **ZygiskNext / ReZygisk / NeoZygisk** | `hook_framework` | `zygisk_atexit_anon`, `zygisk_atexit_holes` (`xposed`/`hook_integrity`) | `HIGH` / `DANGER` |
| **LSPosed / Xposed** | `hook_framework`, `threat_apps` | `lsposed_binder_magic` (`0x5F4C5350`), `lsposed_gid_mismatch`, `lsposed_stack_trace`, `lsposed_uncaught_handler`, `threat_app_cert` (`xposed`/`threat_app`) | `WARNING`+ / `HIGH` |
| **Frida (default, renamed gadget, or `/memfd` modded)** | `hook_framework`, `signal_correlation` | `frida_maps`, `frida_dbus_port`, `fd_linjector`, `fd_frida`, `late_frida_fd`, `anon_elf_exec`, `stealth_so_hidden_in_maps`, `inline_hook`, `got_hook`, `text_mismatch`, `late_text_mismatch`, `C6:bridge_or_integrity_tamper` (`frida`/`hook_integrity`) | `DEADLY` Hard Trigger (score `95–100`) |
| **TrickyStore / TEES-RS / PlayIntegrityFix** | `tee_integrity`, `consistency` | `tee_keybox_revoked`, `tee_grant_chain_split`, `tee_binder_ioctl_hook`, `tee_binder_version_mismatch`, `tee_leaf_der_hex_template`, `tee_leaf_der_non_minimal_ber`, `tee_generate_key_parcel_spoof`, `tee_overwrite_stale_chain`, `tee_strongbox_soft_emulation`, `pif_spoof`, `widevine_java_ndk_mismatch` (`tee_tamper`/`hw_spoof`) | `HIGH` (`DEADLY` Hard Trigger, score `95–100` on `tee_grant_chain_split`, `tee_binder_ioctl_hook`, `tee_keybox_revoked`) |
| **HideMyApplist (HMA / HMA-OSS) & Thanox** | `threat_apps` | `hma_app_cert`, `hma_uid_visibility_hidden`, `hma_seccomp_notif_intercept`, `hma_cross_user_exception_suppressed`, `hma_broadcast_result_to_missing`, `hma_broadcast_ordered_flag_leak`, `hma_permission_service_uid_diff`, `thanox_dropbox_ipc` (`hma_hiding`) | `HIGH` / `DANGER` (side-channel) or `MEDIUM` / `WARNING` (cert) |
| **Repackaged / Resigned APK** | `app_integrity` (when pinning configured) | `pkg_name_mismatch`, `apk_sig_mismatch`, `apk_native_java_sig_conflict`, `apk_signing_lineage_mismatch`, `unofficial_installer` (`app_tamper`) | `DEADLY` Hard Trigger, score `95–100` (sig/pkg/conflict) |
| **VirtualApp / BlackBox / Containers** | `multi_instance` | `nested_container_path`, `container_source_dir`, `dir_uid_mismatch`, `multi_apk_maps`, `binder_dynamic_proxy`, `sacrificial_syscall_mismatch` (`virtual_container`) | `MEDIUM`+ / `HIGH` |
| **Emulators (Waydroid / Cuttlefish / WSA / LDPlayer 9 / MuMu 12 / ARM64 AVD)** | `emulator` | `native_bridge`, `avf_virtualization` (`>= 2` markers), `arm64_clock_drift`, `emu_file`, `emu_pkg`, `emu_prop`, `virtual_gpu`, `zero_hw_codec`, `sensor_static_zero_var` (`emulator`) | `MEDIUM`+ / `HIGH` |
| **Commercial ARM Cloud Phone** | `cloud_phone`, `emulator` | `cloud_pkg`, `cloud_prop`, `zero_hw_codec`, `sensor_static_zero_var` (joint-gated) (`emulator`) | `MEDIUM`+ |
| **MitM Proxy / User CA / Mock Location / Vishing** | `network_risk`, `location_risk`, `screen_and_fraud`, `signal_correlation` | `user_ca_cert`, `vpn_active`, `http_proxy`, `proxy_tool_cert`, `location_canary_tamper`, `virtual_display`, `third_party_a11y`, `screen_recording_active`, `C10:vishing_fraud_combo` (`PAYMENT`) | `MEDIUM`–`HIGH` per scene |
| **Hidden `adbd` / Debugger / `ptrace`** | `adb`, `debug` | `adbd_contradiction`, `adbd_hidden_socket`, `adbd_hidden_jdwp_control`, `tracer_pid`, `tracer_pid_mismatch`, `stat_tracing_stop`, `wchan_ptrace_stop` (`adb`/`debugger`) | `HIGH` / `DANGER` |

---

## 3. Non-Functional SLA & Binary Hardening Sign-Off Budgets

| Metric | v2.0.0 Hard Budget | Automated Gate / Verification |
| :--- | :--- | :--- |
| `RiskEngine.init()` main-thread latency | **< 5 ms** (0 sync disk/Keystore/loadLibrary I/O) | `TieredExecutionAndPushModeTest` + real-device trace |
| `CRITICAL` tier P95 latency | **< 20 ms** (Release) | Real-device & L3 instrumentation |
| `FAST` tier P95 latency | **< 100 ms** (Release) | Real-device & L3 instrumentation |
| `SignedRiskEnvelope` (`PERSISTENT_KEY`) P95 | **< 10 ms** (on-SoC TEE) | `SignedEnvelopeTest` + real-device |
| Single-ABI `libriskengine.so` size | **<= 2,000 KiB** (`2,048,000 B`) per ABI | Gate 2 (`scripts/check-elf-hardening.sh`) |
| 4-ABI release AAR size | **<= 8 MiB** (`8,388,608 B`) | Gate 2 (`scripts/check-elf-hardening.sh`) |
| Core Release R8 Dex method count | **< 2,500 methods** | Gate 2 (`scripts/check-jni-and-dex.py`) |
| `libriskengine.so` ELF hardening | **2 JNI exports only** (`JNI_OnLoad`/`JNI_OnUnload`), 16KB `LOAD` align (`0x4000`), stripped, no `.comment` | Gate 2 (`scripts/check-elf-hardening.sh`) |
| Core `:riskengine-sdk` purity | **0** third-party runtime deps, **0** `<uses-permission>`, **16/16** `docs/evidence/*.md`, **41/41** JNI 1:1, Public ABI locked | Gates 1, 3, 4, 5 (`scripts/ci-verify.sh`) |
| Offline C++ L2 & JVM L1 & L3 Instrumentation | 100% pass, **0** skipped/disabled tests | `scripts/ci-verify.sh` + `.github/workflows/ci.yml` KVM matrix |
