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
        if (value.contains("frida") || value.contains("gadget") || value.contains("gum-js")) {
            return "frida";
        }
        if (value.contains("gdb") || value.contains("android_server") || value.contains("lldb")
                || value.contains("ida")) {
            return "debugger";
        }
        if (value.contains("xposed") || value.contains("lsposed") || value.contains("lspd")) {
            return "xposed";
        }
        if (value.startsWith("inline_hook:") || value.startsWith("got_hook:")
                || value.startsWith("jni_table_hook:") || value.startsWith("jni_slot_hook:")
                || value.startsWith("jni_self_hook:")
                || value.startsWith("sealed:hook_inline")
                || value.startsWith("sealed:jni_self_hook")) {
            return "hook_integrity";
        }
        if (value.startsWith("text_mismatch") || value.startsWith("late_text_mismatch")
                || value.startsWith("sealed:text_mismatch")) {
            return "native_integrity";
        }
        if (value.contains("magisk") || value.contains("ksu") || value.contains("apatch")
                || value.startsWith("su:") || value.startsWith("sealed:root")) {
            return "root_fw";
        }
        if (value.startsWith("sealed:hook_framework")) return "hook_framework";
        if (value.startsWith("sealed:emulator")) return "emulator";
        if (value.startsWith("sealed:debugger") || value.startsWith("tracer_pid:")
                || value.startsWith("debugger_connected")) return "debugger";
        if (value.contains("qemu") || value.contains("goldfish") || value.contains("ranchu")) {
            return "qemu";
        }
        return null;
    }
}
