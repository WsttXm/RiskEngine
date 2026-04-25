package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ShellExecutor;

import java.util.ArrayList;
import java.util.List;

public class CustomRomDetector extends BaseDetector {

    private static final String[][] ROM_PROPS = {
            {"ro.miui.ui.version.name", "MIUI"},
            {"ro.build.version.oplusrom", "ColorOS"},
            {"ro.build.display.ftv", "Flyme"},
            {"ro.vivo.os.version", "FuntouchOS"},
            {"ro.build.hw_emui_api_level", "EMUI"},
            {"ro.lineage.version", "LineageOS"},
            {"ro.cm.version", "CyanogenMod"},
            {"ro.mokee.version", "MoKee"},
            {"ro.rr.version", "ResurrectionRemix"},
            {"ro.pixelexperience.version", "PixelExperience"},
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

        // Check ROM-specific properties
        for (String[] romProp : ROM_PROPS) {
            try {
                String value = NativeCollectorBridge.nativeGetSystemProperty(romProp[0]);
                if (value != null && !value.isEmpty()) {
                    evidence.add("rom_detected:" + romProp[1] + "=" + value);
                }
            } catch (Exception ignored) {}
        }

        // Check for custom ROM indicators
        try {
            String prop = NativeCollectorBridge.nativeGetSystemProperty("ro.modversion");
            if (prop != null && !prop.isEmpty()) {
                evidence.add("modversion:" + prop);
            }
        } catch (Exception ignored) {}

        // LineageOS specific
        try {
            String lineage = ShellExecutor.execute("getprop ro.lineage.version");
            if (lineage != null && !lineage.trim().isEmpty()) {
                evidence.add("lineageos:" + lineage.trim());
            }
        } catch (Exception ignored) {}

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.LOW, String.join("; ", evidence));
        }
        return safe();
    }
}
