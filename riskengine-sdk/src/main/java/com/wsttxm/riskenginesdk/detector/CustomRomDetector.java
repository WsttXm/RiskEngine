package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.List;

public class CustomRomDetector extends BaseDetector {
    private final SignalSnapshot signals;
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
        this(context, new SignalSnapshot(context));
    }

    public CustomRomDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "custom_rom";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();
        SignalResult<String> fingerprint = signals.getSystemProperty("ro.build.fingerprint");
        if (!fingerprint.isSuccess() || valueOf(fingerprint).isEmpty()) {
            return unavailable("system_properties_unavailable");
        }
        CheckCoverage coverage = new CheckCoverage();
        coverage.success();
        for (String[] romProperty : COMMUNITY_ROM_PROPS) {
            SignalResult<String> property = signals.getSystemProperty(romProperty[0]);
            if (!property.isSuccess()) {
                coverage.failure(romProperty[0] + ":" + property.getFailureReason());
                continue;
            }
            coverage.success();
            String value = valueOf(property);
            if (!value.isEmpty()) {
                evidence.add("community_rom:" + romProperty[1] + "=" + value);
            }
        }

        if (!evidence.isEmpty()) {
            // A community ROM is context, not proof of compromise/root.
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        }
        return safe(coverage);
    }

    private static String valueOf(SignalResult<String> result) {
        return result.getValue() == null ? "" : result.getValue().trim();
    }
}
