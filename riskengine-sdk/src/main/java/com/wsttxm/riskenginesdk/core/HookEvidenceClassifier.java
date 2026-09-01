package com.wsttxm.riskenginesdk.core;

import java.util.Locale;

public final class HookEvidenceClassifier {
    public enum Rank { STRONG, MEDIUM, WEAK, IGNORE }

    private HookEvidenceClassifier() {}

    public static Rank rank(String token) {
        if (token == null || token.isBlank()) return Rank.IGNORE;
        String value = token.toLowerCase(Locale.ROOT);
        if (value.startsWith("inline_hook:")
                || value.startsWith("got_hook:")
                || value.startsWith("jni_table_hook:")
                || value.startsWith("maps:frida")
                || value.startsWith("maps:gadget")
                || value.startsWith("frida_maps")
                || value.startsWith("frida_pid")
                || value.startsWith("frida_pid_port")) {
            return Rank.STRONG;
        }
        if (value.startsWith("thread:gum-js-loop")
                || value.startsWith("thread:frida")
                || value.startsWith("maps:xposed")
                || value.startsWith("maps:lsposed")
                || value.startsWith("maps:substrate")
                || value.startsWith("xposed_hooks_active")
                || value.startsWith("xposed_class_found")
                || value.startsWith("xposed_stack")) {
            return Rank.MEDIUM;
        }
        if (value.startsWith("thread:gmain")) {
            return Rank.IGNORE;
        }
        if (value.startsWith("anon_exec:")
                || value.startsWith("frida_port_open")
                || value.contains("27042")) {
            return Rank.WEAK;
        }
        return Rank.WEAK;
    }
}
