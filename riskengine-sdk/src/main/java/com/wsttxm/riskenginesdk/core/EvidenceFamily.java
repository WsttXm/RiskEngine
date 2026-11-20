package com.wsttxm.riskenginesdk.core;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class EvidenceFamily {
    private EvidenceFamily() {}

    public static Set<String> families(List<String> details) {
        Set<String> families = new LinkedHashSet<>();
        if (details == null) return families;
        for (String detail : details) {
            String family = familyOf(detail);
            if (family != null) families.add(family);
        }
        return families;
    }

    public static String familyOf(String detail) {
        if (detail == null || detail.isBlank()) return null;
        String value = detail.toLowerCase(Locale.ROOT);
        if (value.startsWith("native:")) {
            value = value.substring("native:".length());
        }
        if (value.contains("frida") || value.contains("gadget") || value.contains("gum-js")
                || value.startsWith("unix_socket:")) {
            return "frida";
        }
        if (value.contains("gdb") || value.contains("android_server") || value.contains("lldb")
                || value.contains("ida") || value.startsWith("sealed:debugger")
                || value.startsWith("tracer_pid:") || value.startsWith("debugger_connected")
                || value.startsWith("late_tracer_attached")) {
            return "debugger";
        }
        if (value.contains("xposed") || value.contains("lsposed") || value.contains("lspd")) {
            return "xposed";
        }
        if (value.startsWith("inline_hook:") || value.startsWith("got_hook:")
                || value.startsWith("jni_table_hook:") || value.startsWith("jni_slot_hook:")
                || value.startsWith("jni_self_hook:") || value.startsWith("art_native_flag:")
                || value.startsWith("art_native_cleared:")
                || value.startsWith("memfd_private_elf:") || value.startsWith("late_memfd_elf")
                || value.startsWith("wx_segment:self") || value.startsWith("late_wx_self")
                || value.startsWith("sealed:hook_inline")
                || value.startsWith("sealed:jni_self_hook")) {
            return "hook_integrity";
        }
        if (value.startsWith("text_mismatch") || value.startsWith("late_text_mismatch")
                || value.startsWith("sealed:text_mismatch")) {
            return "native_integrity";
        }
        if (value.contains("magisk") || value.contains("ksu") || value.contains("apatch")
                || value.startsWith("su:") || value.startsWith("su_found:")
                || value.startsWith("path_su:") || value.startsWith("modules_found:")
                || value.startsWith("modules:") || value.startsWith("mount_hidden")
                || value.startsWith("system_tmpfs_mount:")
                || value.startsWith("mount:system_tmpfs:")
                || value.startsWith("listing_mismatch") || value.startsWith("selinux_context:")
                || value.startsWith("sealed:root") || value.startsWith("sealed:kernel_root")) {
            return "root_fw";
        }
        if (value.startsWith("sealed:hook_framework")) {
            return "hook_framework";
        }
        if (value.contains("qemu") || value.contains("goldfish") || value.contains("ranchu")
                || value.startsWith("emu_file:") || value.startsWith("emu_pkg:")
                || value.startsWith("virtual_gpu:") || value.startsWith("cpu:hypervisor")
                || value.startsWith("sealed:emulator")) {
            return "emulator";
        }
        return null;
    }

    /**
     * Returns true when every family in {@code families} is already accounted
     * for by {@code claimed}, treating the aggregate {@code hook_framework}
     * sealed bit as covered when either {@code frida} or {@code xposed} is claimed.
     */
    public static boolean isCoveredBy(Set<String> families, Set<String> claimed) {
        if (families.isEmpty()) return false;
        for (String family : families) {
            if (claimed.contains(family)) continue;
            if ("hook_framework".equals(family)
                    && (claimed.contains("frida") || claimed.contains("xposed"))) {
                continue;
            }
            return false;
        }
        return true;
    }
}
