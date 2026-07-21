package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

public abstract class BaseDetector implements Callable<DetectionResult> {
    protected final Context context;

    public BaseDetector(Context context) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
    }

    public abstract String getName();

    protected abstract DetectionResult detect();

    @Override
    public DetectionResult call() {
        try {
            return detect();
        } catch (Exception | LinkageError e) {
            CLog.e("Detector [" + getName() + "] failed", e);
            return DetectionResult.unavailable(getName(), e.getClass().getSimpleName());
        }
    }

    protected DetectionResult safe() {
        return result(
                RiskLevel.SAFE,
                DetectionStatus.NORMAL,
                0,
                10,
                false,
                Collections.emptyList(),
                "no risk detected"
        );
    }

    protected DetectionResult risk(RiskLevel level, String evidence) {
        return new DetectionResult(getName(), level, evidence);
    }

    protected DetectionResult unavailable(String reason) {
        return DetectionResult.unavailable(getName(), reason);
    }

    protected DetectionResult result(RiskLevel level,
                                     DetectionStatus status,
                                     int score,
                                     int maxScore,
                                     boolean warnOnly,
                                     List<String> details,
                                     String evidence) {
        return new DetectionResult(getName(), level, status, score, maxScore, warnOnly, details, evidence);
    }
}
