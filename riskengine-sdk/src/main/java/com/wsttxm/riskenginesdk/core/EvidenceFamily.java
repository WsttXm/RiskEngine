package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskDimension;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class EvidenceFamily {
    private EvidenceFamily() {}

    public static Set<String> families(List<String> details) {
        return families(details, null);
    }

    public static Set<String> families(List<String> details, List<EvidenceItem> evidenceItems) {
        Set<String> families = new LinkedHashSet<>();
        if (details != null) {
            for (String detail : details) {
                String family = familyOf(detail);
                if (family != null) families.add(family);
            }
        }
        if (evidenceItems != null) {
            for (EvidenceItem item : evidenceItems) {
                if (item == null) continue;
                String family = item.getEvidenceFamily();
                if (family != null && !family.isBlank()) {
                    families.add(family.trim());
                } else {
                    String inferred = familyOf(item.getCode());
                    if (inferred != null) families.add(inferred);
                }
            }
        }
        return families;
    }

    public static String familyOf(String detail) {
        if (detail == null || detail.isBlank()) return null;
        String value = detail.toLowerCase(Locale.ROOT);
        if (value.startsWith("native:")) {
            value = value.substring("native:".length());
        }
        // Exact-prefix families first so embedded package names (e.g. "com.holiday.store"
        // or "com.friday.market") are never misclassified by broad substring checks below.
        if (value.startsWith("apk_sig_mismatch")
                || value.startsWith("pkg_name_mismatch")
                || value.startsWith("apk_native_java_sig_conflict")
                || value.startsWith("apk_signing_lineage_mismatch")
                || value.startsWith("unofficial_installer")
                || value.startsWith("release_unobfuscated")) {
            return "app_tamper";
        }
        if (value.startsWith("tee_")) {
            return "tee_tamper";
        }
        if (value.startsWith("hma_")
                || value.startsWith("thanox_ipc_")
                || value.startsWith("threat_app_cert:hidemyapplist:")
                || value.equals("threat_app_package:com.tsng.hidemyapplist")
                || value.equals("threat_app_package:org.frknkrc44.hma_oss")
                || value.equals("threat_app_package:com.tsng.pzyhrx.hma")) {
            return "hma_hiding";
        }
        if (value.startsWith("threat_app_native_payload:")
                || value.startsWith("threat_app_zygote_preload:")
                || value.startsWith("threat_app_cert:kernelsu:")
                || value.startsWith("threat_app_cert:ksu_next:")
                || value.startsWith("threat_app_cert:sukisu:")
                || value.startsWith("threat_app_cert:magisk:")
                || value.startsWith("threat_app_cert:apatch:")
                || value.startsWith("threat_app_cert:skroot:")
                || value.startsWith("threat_app_cert:supersu:")
                || value.equals("threat_app_package:me.weishu.kernelsu")
                || value.equals("threat_app_package:io.github.a13e300.mksu")
                || value.equals("threat_app_package:com.rifsxd.ksunext")
                || value.equals("threat_app_package:com.sukisu.ultra")
                || value.equals("threat_app_package:com.resukisu.resukisu")
                || value.equals("threat_app_package:com.topjohnwu.magisk")
                || value.equals("threat_app_package:io.github.vvb2060.magisk")
                || value.equals("threat_app_package:me.bmax.apatch")
                || value.equals("threat_app_package:com.linux.permissionmanager")
                || value.equals("threat_app_package:eu.chainfire.supersu")) {
            return "root_fw";
        }
        if (value.startsWith("threat_app_")) {
            return "threat_app";
        }
        if (value.startsWith("bootloader_unlocked")
                || value.startsWith("verified_boot_state:")
                || value.startsWith("key_attestation:")
                || value.startsWith("vbmeta_empty_input_digest")
                || value.startsWith("spoofed_verified_boot")
                || value.startsWith("c8:")
                || value.startsWith("bootconfig_prop_mismatch:")
                || value.startsWith("cmdline_prop_mismatch:")
                || value.startsWith("knox_warranty_void")
                || value.startsWith("verity_mode_disabled:")
                || value.startsWith("partition_verity_disabled:")
                || value.startsWith("attested_vbmeta_")
                || value.startsWith("secureboot_disabled")) {
            return "boot_integrity";
        }
        if (value.startsWith("device_binding_broken")
                || value.startsWith("device_binding_reason:")
                || value.startsWith("hardware_layer_changed")
                || value.startsWith("changed_buckets:")) {
            return "device_binding";
        }
        if (value.startsWith("nested_container_path:")
                || value.startsWith("container_source_dir:")
                || value.startsWith("user_id_path_mismatch:")
                || value.startsWith("dir_uid_mismatch:")
                || value.startsWith("multi_apk_maps:")
                || value.startsWith("container_maps_artifact:")
                || value.startsWith("binder_dynamic_proxy:")
                || value.startsWith("sacrificial_syscall_mismatch")
                || value.startsWith("oem_dual_app:")) {
            return "virtual_container";
        }
        if (value.startsWith("user_ca_cert:")
                || value.startsWith("vpn_active:")
                || value.startsWith("http_proxy:")
                || value.startsWith("proxy_tool_cert:")
                || value.startsWith("proxy_module:")) {
            return "network_mitm";
        }
        if (value.startsWith("location_canary_tamper:")
                || value.startsWith("cached_location_mock:")
                || value.startsWith("mock_location_appop_allowed")) {
            return "location_spoof";
        }
        if (value.startsWith("virtual_display:")
                || value.startsWith("third_party_a11y:")
                || value.startsWith("virtual_input:")
                || value.startsWith("screen_recording_active")
                || value.startsWith("screen_capture_observed")) {
            return "screen_control";
        }
        if (value.startsWith("ongoing_call:")
                || value.startsWith("time_spoofing:")
                || value.startsWith("c10:")
                || value.startsWith("vishing_fraud_combo")) {
            return "fraud_context";
        }
        if (value.startsWith("prop_area_hole")
                || value.startsWith("prop_ro_serial_modified")
                || value.startsWith("prop_ro_nul_tail_residual")
                || value.startsWith("prop_mismatch:")
                || value.startsWith("pif_")
                || value.startsWith("c5:")
                || value.startsWith("resetprop")) {
            return "prop_tamper";
        }
        if (value.startsWith("widevine_")
                || value.startsWith("hw_")
                || value.startsWith("fingerprint_mismatch")
                || value.startsWith("inconsistent_fields:")) {
            return "hw_spoof";
        }
        if (value.startsWith("community_rom:")
                || value.startsWith("custom_rom")
                || value.equals("test_keys")
                || value.startsWith("test_keys:")
                || value.startsWith("lineage")) {
            return "custom_rom";
        }
        if (value.startsWith("settings_adb_")
                || value.startsWith("adb_")
                || value.startsWith("adbd_")
                || value.startsWith("tcp_listen:")) {
            return "adb";
        }
        if (value.startsWith("inline_hook:") || value.startsWith("got_hook:")
                || value.equals("text_mismatch") || value.startsWith("text_mismatch:")
                || value.equals("late_text_mismatch") || value.startsWith("late_text_mismatch:")
                || value.startsWith("jni_self_hook:")
                || value.startsWith("fn_prologue_hook:")
                || value.startsWith("jni_table_hook:") || value.startsWith("jni_slot_hook:")
                || value.startsWith("art_native_flag:")
                || value.startsWith("art_native_cleared:")
                || value.startsWith("memfd_private_elf:") || value.startsWith("late_memfd_elf")
                || value.startsWith("anon_elf_exec:")
                || value.startsWith("stealth_so_hidden_in_maps:")
                || value.startsWith("stealth_so_unlinked:")
                || value.startsWith("sigaction_anon_handler:")
                || value.startsWith("wx_segment:self") || value.startsWith("late_wx_self")) {
            return "hook_integrity";
        }
        if (value.startsWith("late_frida_fd")
                || value.startsWith("fd:linjector") || value.startsWith("fd_linjector")
                || value.startsWith("fd:frida:") || value.startsWith("fd_frida")
                || value.startsWith("thread:pool-frida")
                || value.startsWith("thread:pool-spawner")
                || value.startsWith("thread:frida-helper")
                || value.startsWith("thread:gdbus")
                || value.contains("frida") || value.contains("gadget") || value.contains("gum-js")
                || value.startsWith("unix_socket:")) {
            return "frida";
        }
        if (value.contains("gdb") || value.contains("android_server") || value.contains("lldb")
                || value.contains("ida")
                || value.startsWith("tracer_pid:") || value.startsWith("tracer_pid_mismatch:")
                || value.startsWith("stat_tracing_stop:") || value.startsWith("wchan_ptrace_stop:")
                || value.startsWith("jdwp_thread:") || value.startsWith("jdwp_socket:")
                || value.startsWith("debugger_connected")
                || value.startsWith("late_tracer_attached")) {
            return "debugger";
        }
        if (value.contains("xposed") || value.contains("lsposed") || value.contains("lspd")) {
            return "xposed";
        }
        if (value.contains("magisk") || value.contains("ksu") || value.contains("apatch")
                || value.startsWith("su:") || value.startsWith("su_found:")
                || value.startsWith("path_su:") || value.startsWith("modules_found:")
                || value.startsWith("modules:")
                || value.startsWith("syscall_mismatch")
                || value.startsWith("mount:module")
                || value.startsWith("module_mount")
                || value.startsWith("system_tmpfs_mount:")
                || value.startsWith("mount:system_tmpfs:")
                || value.startsWith("isolated_mount_diff")
                || value.startsWith("statx_mnt_id_hidden")
                || value.startsWith("system_ro_rw_mount")
                || value.startsWith("mount_mtime_mismatch")
                || value.startsWith("statfs_overlay_on_system")
                || value.startsWith("statfs_tmpfs_on_system")
                || value.startsWith("c9:")
                || value.startsWith("stealth_root_with_unmount")
                || value.startsWith("listing_mismatch") || value.startsWith("selinux_context:")) {
            return "root_fw";
        }
        if (value.contains("qemu") || value.contains("goldfish") || value.contains("ranchu")
                || value.startsWith("emu_file:") || value.startsWith("emu_pkg:")
                || value.startsWith("emu_prop:")
                || value.startsWith("native_bridge:")
                || value.startsWith("avf_virtualization:")
                || value.startsWith("arm64_clock_drift")
                || value.startsWith("sched_yield_low_cv")
                || value.startsWith("zero_hw_codec")
                || value.startsWith("sensor_static_zero_var")
                || value.startsWith("cloud_prop:") || value.startsWith("cloud_pkg:")
                || value.startsWith("wired_interface:")
                || value.startsWith("battery_zero:") || value.startsWith("battery_anomaly:")
                || value.startsWith("low_camera_count:") || value.startsWith("very_low_sensor_count:")
                || value.startsWith("virtual_gpu:") || value.startsWith("cpu:hypervisor")) {
            return "emulator";
        }
        return null;
    }

    /**
     * Maps any canonical Evidence Family to its orthogonal {@link RiskDimension}.
     * Returns {@code null} for unrecognized or blank family names.
     */
    public static RiskDimension dimensionOf(String family) {
        if (family == null || family.isBlank()) {
            return null;
        }
        switch (family.trim().toLowerCase(Locale.ROOT)) {
            case "app_tamper":
            case "hook_integrity":
            case "frida":
            case "xposed":
            case "debugger":
            case "tee_tamper":
                return RiskDimension.TAMPERING;
            case "root_fw":
            case "boot_integrity":
            case "prop_tamper":
            case "hw_spoof":
            case "hma_hiding":
            case "device_binding":
            case "custom_rom":
            case "adb":
                return RiskDimension.PRIVILEGE;
            case "emulator":
            case "virtual_container":
            case "threat_app":
                return RiskDimension.ENVIRONMENT;
            case "network_mitm":
            case "location_spoof":
            case "screen_control":
            case "fraud_context":
                return RiskDimension.FRAUD_CONTEXT;
            default:
                return null;
        }
    }

    /**
     * Fallback Evidence Family for a Detection Domain when an actionable result carries
     * no structured EvidenceItem or recognized token prefix.
     */
    static String fallbackFamilyForDetector(String detectorName) {
        if (detectorName == null || detectorName.isBlank()) {
            return "detector:unknown";
        }
        switch (detectorName) {
            case "hook_framework":
            case "hook":
                return "hook_integrity";
            case "debug":
                return "debugger";
            case "app_integrity":
                return "app_tamper";
            case "tee_integrity":
                return "tee_tamper";
            case "root":
            case "mount_analysis":
                return "root_fw";
            case "consistency":
                return "boot_integrity";
            case "custom_rom":
                return "custom_rom";
            case "adb":
                return "adb";
            case "fingerprint_continuity":
                return "device_binding";
            case "multi_source_validation":
                return "hw_spoof";
            case "emulator":
            case "cloud_phone":
                return "emulator";
            case "multi_instance":
                return "virtual_container";
            case "threat_apps":
                return "threat_app";
            case "network_risk":
                return "network_mitm";
            case "location_risk":
                return "location_spoof";
            case "screen_and_fraud":
                return "screen_control";
            default:
                return "detector:" + detectorName;
        }
    }

    /**
     * Returns true when every family in {@code families} is already accounted
     * for by {@code claimed}.
     */
    public static boolean isCoveredBy(Set<String> families, Set<String> claimed) {
        if (families == null || families.isEmpty()) return false;
        if (claimed == null || claimed.isEmpty()) return false;
        for (String family : families) {
            if (!claimed.contains(family)) {
                return false;
            }
        }
        return true;
    }
}
