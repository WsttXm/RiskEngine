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
        if (value.contains("magisk") || value.contains("ksu") || value.contains("apatch")
                || value.startsWith("su:")) {
            return "root_fw";
        }
        if (value.contains("qemu") || value.contains("goldfish") || value.contains("ranchu")) {
            return "qemu";
        }
        return null;
    }
}
