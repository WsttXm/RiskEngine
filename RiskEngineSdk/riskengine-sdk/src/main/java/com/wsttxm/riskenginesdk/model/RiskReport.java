package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RiskReport {
    private final DeviceFingerprint fingerprint;
    private final List<DetectionResult> detections;
    private final long timestampMs;
    private final String sdkVersion;
    private final int riskScore;
    private final int maxRiskScore;
    private final int warningCount;
    private final int dangerCount;
    private RiskLevel overallRiskLevel;

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections) {
        this.fingerprint = fingerprint;
        this.detections = Collections.unmodifiableList(new ArrayList<>(detections));
        this.timestampMs = System.currentTimeMillis();
        this.sdkVersion = "1.0.0";
        this.riskScore = computeRiskScore();
        this.maxRiskScore = computeMaxRiskScore();
        this.warningCount = computeCount(DetectionStatus.WARNING);
        this.dangerCount = computeCount(DetectionStatus.DANGER);
        this.overallRiskLevel = computeOverallRisk();
    }

    private RiskLevel computeOverallRisk() {
        RiskLevel level;
        if (hasHardTrigger()) {
            level = RiskLevel.DEADLY;
        } else if (riskScore >= 18 || dangerCount >= 3) {
            level = RiskLevel.DEADLY;
        } else if (riskScore >= 10 || dangerCount >= 1) {
            level = RiskLevel.HIGH;
        } else if (riskScore >= 4 || warningCount >= 2) {
            level = RiskLevel.MEDIUM;
        } else if (riskScore > 0 || warningCount >= 1) {
            level = RiskLevel.LOW;
        } else {
            level = RiskLevel.SAFE;
        }

        if (fingerprint.hasInconsistency() && level.getValue() < RiskLevel.MEDIUM.getValue()) {
            level = RiskLevel.MEDIUM;
        }
        return level;
    }

    public DeviceFingerprint getFingerprint() { return fingerprint; }
    public List<DetectionResult> getDetections() { return detections; }
    public long getTimestampMs() { return timestampMs; }
    public String getSdkVersion() { return sdkVersion; }
    public int getRiskScore() { return riskScore; }
    public int getMaxRiskScore() { return maxRiskScore; }
    public int getWarningCount() { return warningCount; }
    public int getDangerCount() { return dangerCount; }
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

    private int computeRiskScore() {
        int total = 0;
        for (DetectionResult detection : detections) {
            if (!detection.isWarnOnly()) {
                total += detection.getScore();
            }
        }
        return total;
    }

    private int computeMaxRiskScore() {
        int total = 0;
        for (DetectionResult detection : detections) {
            total += detection.getMaxScore();
        }
        return total;
    }

    private int computeCount(DetectionStatus status) {
        int count = 0;
        for (DetectionResult detection : detections) {
            if (detection.getStatus() == status) {
                count++;
            }
        }
        return count;
    }

    private boolean hasHardTrigger() {
        for (DetectionResult detection : detections) {
            if (detection.getRiskLevel().getValue() < RiskLevel.HIGH.getValue()) {
                continue;
            }
            String name = detection.getDetectorName();
            List<String> details = detection.getDetails();
            if ("hook_framework".equals(name) && containsAny(details,
                    "dbus_reject", "frida_pid_port", "anon_exec", "trampoline", "sigtrap")) {
                return true;
            }
            if ("method_integrity".equals(name)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAny(List<String> details, String... prefixes) {
        for (String detail : details) {
            for (String prefix : prefixes) {
                if (detail.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }
}
