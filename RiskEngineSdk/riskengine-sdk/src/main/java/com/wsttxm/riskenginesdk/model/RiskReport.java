package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.List;

public class RiskReport {
    private final DeviceFingerprint fingerprint;
    private final List<DetectionResult> detections;
    private final long timestampMs;
    private final String sdkVersion;
    private RiskLevel overallRiskLevel;

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections) {
        this.fingerprint = fingerprint;
        this.detections = detections;
        this.timestampMs = System.currentTimeMillis();
        this.sdkVersion = "1.0.0";
        this.overallRiskLevel = computeOverallRisk();
    }

    private RiskLevel computeOverallRisk() {
        RiskLevel max = RiskLevel.SAFE;
        for (DetectionResult d : detections) {
            if (d.getRiskLevel().getValue() > max.getValue()) {
                max = d.getRiskLevel();
            }
        }
        if (fingerprint.hasInconsistency() && max.getValue() < RiskLevel.MEDIUM.getValue()) {
            max = RiskLevel.MEDIUM;
        }
        return max;
    }

    public DeviceFingerprint getFingerprint() { return fingerprint; }
    public List<DetectionResult> getDetections() { return detections; }
    public long getTimestampMs() { return timestampMs; }
    public String getSdkVersion() { return sdkVersion; }
    public RiskLevel getOverallRiskLevel() { return overallRiskLevel; }

    public List<DetectionResult> getDetectionsByLevel(RiskLevel minLevel) {
        List<DetectionResult> filtered = new ArrayList<>();
        for (DetectionResult d : detections) {
            if (d.getRiskLevel().getValue() >= minLevel.getValue()) {
                filtered.add(d);
            }
        }
        return filtered;
    }
}
