package com.wsttxm.riskenginesdk.core;

import java.util.Locale;

public final class EmulatorEvidenceClassifier {
    public enum Rank { STRONG, WEAK, IGNORE }

    private EmulatorEvidenceClassifier() {}

    public static Rank rank(String token) {
        if (token == null || token.isBlank()) return Rank.IGNORE;
        String value = token.toLowerCase(Locale.ROOT);
        if (value.startsWith("emu_file:")
                || value.startsWith("emu_pkg:")
                || value.startsWith("qemu_prop")
                || value.startsWith("qemu_pipe")
                || value.startsWith("virtual_gpu:")
                || value.startsWith("cpu:hypervisor")
                || value.startsWith("fingerprint:")
                || value.startsWith("model:")
                || value.startsWith("manufacturer:")
                || value.startsWith("product:")
                || value.startsWith("hardware:")
                || value.startsWith("board:")
                || value.startsWith("runtime_arch:x86")
                || value.startsWith("runtime_arch:i386")) {
            return Rank.STRONG;
        }
        if (value.startsWith("generic_fingerprint:")
                || value.startsWith("aosp_sensor")
                || value.startsWith("low_sensor_count")
                || value.startsWith("disk_small")
                || value.startsWith("screen_stock")
                || value.startsWith("no_thermal")
                || value.startsWith("missing_feature")
                || value.startsWith("limited_hardware")
                || value.startsWith("emulator_ip:")
                || value.startsWith("cgroup:")
                || value.startsWith("mount_overlay")
                || value.startsWith("cmdline_mismatch")) {
            return Rank.WEAK;
        }
        return Rank.WEAK;
    }

    public static boolean isHardwareNoise(String token) {
        if (token == null) return false;
        String value = token.toLowerCase(Locale.ROOT);
        return value.startsWith("aosp_sensor")
                || value.startsWith("missing_feature")
                || value.startsWith("limited_hardware");
    }
}
