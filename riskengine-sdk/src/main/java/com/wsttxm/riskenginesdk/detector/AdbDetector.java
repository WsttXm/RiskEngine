package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.AdbInspector;

import java.util.ArrayList;
import java.util.List;

public class AdbDetector extends BaseDetector {

    public AdbDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "adb";
    }

    @Override
    protected com.wsttxm.riskenginesdk.model.DetectionResult detect() {
        AdbInspector.Snapshot snapshot = AdbInspector.collect(context);
        List<String> details = new ArrayList<>(snapshot.getDetails());
        if (!snapshot.isEnabled()) {
            return safe();
        }

        int score = snapshot.isWifiEnabled() ? 4 : 2;
        RiskLevel level = snapshot.isWifiEnabled() ? RiskLevel.MEDIUM : RiskLevel.LOW;
        return result(
                level,
                DetectionStatus.WARNING,
                score,
                10,
                true,
                details,
                String.join("; ", details)
        );
    }
}
