package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.concurrent.Callable;

public abstract class BaseDetector implements Callable<DetectionResult> {
    protected final Context context;

    public BaseDetector(Context context) {
        this.context = context;
    }

    public abstract String getName();

    protected abstract DetectionResult detect();

    @Override
    public DetectionResult call() {
        try {
            return detect();
        } catch (Exception e) {
            CLog.e("Detector [" + getName() + "] failed", e);
            return new DetectionResult(getName(), RiskLevel.SAFE, "detection failed: " + e.getMessage());
        }
    }

    protected DetectionResult safe() {
        return new DetectionResult(getName(), RiskLevel.SAFE, "no risk detected");
    }

    protected DetectionResult risk(RiskLevel level, String evidence) {
        return new DetectionResult(getName(), level, evidence);
    }
}
