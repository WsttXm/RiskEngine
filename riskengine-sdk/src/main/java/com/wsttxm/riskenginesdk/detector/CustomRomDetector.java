package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.ShellExecutor;

import java.util.ArrayList;
import java.util.List;

public class CustomRomDetector extends BaseDetector {
    // Stock OEM Android distributions are intentionally excluded.
    private static final String[][] COMMUNITY_ROM_PROPS = {
            {"ro.lineage.version", "LineageOS"},
            {"ro.cm.version", "CyanogenMod"},
            {"ro.mokee.version", "MoKee"},
            {"ro.rr.version", "ResurrectionRemix"},
            {"ro.pixelexperience.version", "PixelExperience"},
            {"ro.modversion", "ModVersion"}
    };

    public CustomRomDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "custom_rom";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();
        if (readProperty("ro.build.fingerprint").isEmpty()) {
            return unavailable("system_properties_unavailable");
        }
        for (String[] romProperty : COMMUNITY_ROM_PROPS) {
            String value = readProperty(romProperty[0]);
            if (!value.isEmpty()) {
                evidence.add("community_rom:" + romProperty[1] + "=" + value);
            }
        }

        if (!evidence.isEmpty()) {
            // A community ROM is context, not proof of compromise/root.
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence));
        }
        return safe();
    }

    private String readProperty(String name) {
        if (NativeCollectorBridge.isNativeAvailable()) {
            try {
                String value = NativeCollectorBridge.getSystemProperty(name);
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
            } catch (Exception | LinkageError ignored) {
                // Fall through to the bounded shell fallback.
            }
        }
        return ShellExecutor.execute("getprop " + name).trim();
    }
}
