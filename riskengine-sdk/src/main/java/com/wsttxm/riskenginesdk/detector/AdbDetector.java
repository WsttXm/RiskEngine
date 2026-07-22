package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.AdbInspector;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.List;

public class AdbDetector extends BaseDetector {
    private final SignalSnapshot signals;

    public AdbDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public AdbDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "adb";
    }

    @Override
    protected com.wsttxm.riskenginesdk.model.DetectionResult detect() {
        AdbInspector.Snapshot snapshot = AdbInspector.collect(signals);
        List<String> details = new ArrayList<>(snapshot.getDetails());
        CheckCoverage coverage = new CheckCoverage();
        for (int i = 0; i < snapshot.getChecksSucceeded(); i++) coverage.success();
        for (String reason : snapshot.getFailureReasons()) coverage.failure(reason);
        if (!snapshot.isEnabled()) {
            return safe(coverage);
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
                String.join("; ", details),
                coverage
        );
    }
}
