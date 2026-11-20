package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.generated.DetectionLists;

import java.util.Locale;

/**
 * Classifies GPU vendor/renderer strings while respecting modern Android
 * hardware ANGLE-on-Vulkan drivers (Android 14-16 stock flagship devices).
 */
public final class GpuClassifier {
    private static final String[] HARDWARE_GPU_VENDORS = {
            "adreno", "mali", "immortalis", "powervr", "xclipse",
            "qualcomm", "imagination", "samsung", "nvidia", "tegra", "apple", "amd"
    };

    private GpuClassifier() {}

    /**
     * Returns the matched virtualized GPU marker, or {@code null} when the
     * identity matches a physical GPU (including hardware-backed ANGLE).
     */
    public static String matchVirtualMarker(String vendor, String renderer) {
        String haystack = ((renderer == null ? "" : renderer) + " "
                + (vendor == null ? "" : vendor)).toLowerCase(Locale.ROOT).trim();
        if (haystack.isEmpty()) {
            return null;
        }
        for (String marker : DetectionLists.VIRTUAL_GPU_MARKERS) {
            if (haystack.contains(marker)) {
                return marker;
            }
        }
        if (haystack.contains("angle")) {
            for (String hw : HARDWARE_GPU_VENDORS) {
                if (haystack.contains(hw)) {
                    return null;
                }
            }
            return "angle_soft";
        }
        return null;
    }
}
