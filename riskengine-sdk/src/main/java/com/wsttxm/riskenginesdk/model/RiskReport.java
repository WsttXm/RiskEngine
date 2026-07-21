package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.wsttxm.riskenginesdk.BuildConfig;

public class RiskReport {
    private final DeviceFingerprint fingerprint;
    private final List<DetectionResult> detections;
    private final long timestampMs;
    private final String sdkVersion;
    private final int riskScore;
    private final int maxRiskScore;
    private final int warningCount;
    private final int dangerCount;
    private final int unknownCount;
    private final RiskLevel overallRiskLevel;

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections) {
        this.fingerprint = Objects.requireNonNull(fingerprint, "fingerprint must not be null");
        Objects.requireNonNull(detections, "detections must not be null");
        List<DetectionResult> detectionCopy = new ArrayList<>(detections.size());
        for (DetectionResult detection : detections) {
            detectionCopy.add(Objects.requireNonNull(
                    detection, "detections must not contain null"));
        }
        this.fingerprint.freeze();
        this.detections = Collections.unmodifiableList(detectionCopy);
        this.timestampMs = System.currentTimeMillis();
        this.sdkVersion = BuildConfig.SDK_VERSION;
        this.riskScore = computeRiskScore();
        this.maxRiskScore = computeMaxRiskScore();
        this.warningCount = computeCount(DetectionStatus.WARNING);
        this.dangerCount = computeCount(DetectionStatus.DANGER);
        this.unknownCount = computeCount(DetectionStatus.UNKNOWN);
        this.overallRiskLevel = computeOverallRisk();
    }

    private RiskLevel computeOverallRisk() {
        int actionableWarnings = computeActionableCount(DetectionStatus.WARNING);
        int actionableDangers = computeActionableCount(DetectionStatus.DANGER);
        RiskLevel level;
        if (hasHardTrigger()) {
            level = RiskLevel.DEADLY;
        } else if (riskScore >= 18 || actionableDangers >= 3) {
            level = RiskLevel.DEADLY;
        } else if (riskScore >= 10 || actionableDangers >= 1) {
            level = RiskLevel.HIGH;
        } else if (riskScore >= 4 || actionableWarnings >= 2) {
            level = RiskLevel.MEDIUM;
        } else if (riskScore > 0 || warningCount >= 1 || dangerCount >= 1) {
            level = RiskLevel.LOW;
        } else if (unknownCount > 0) {
            level = RiskLevel.UNKNOWN;
        } else {
            level = RiskLevel.SAFE;
        }

        if (fingerprint.hasInconsistency()
                && level != RiskLevel.UNKNOWN
                && level.getValue() < RiskLevel.MEDIUM.getValue()) {
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
    public int getUnknownCount() { return unknownCount; }
    public RiskLevel getOverallRiskLevel() { return overallRiskLevel; }

    public List<DetectionResult> getDetectionsByLevel(RiskLevel minLevel) {
        Objects.requireNonNull(minLevel, "minLevel must not be null");
        List<DetectionResult> filtered = new ArrayList<>();
        for (DetectionResult d : detections) {
            if (d.getRiskLevel().getValue() >= minLevel.getValue()) {
                filtered.add(d);
            }
        }
        return filtered;
    }

    private int computeRiskScore() {
        long total = 0;
        for (DetectionResult detection : detections) {
            if (!detection.isWarnOnly()) {
                total += detection.getScore();
            }
        }
        return (int) Math.min(total, Integer.MAX_VALUE);
    }

    private int computeMaxRiskScore() {
        long total = 0;
        for (DetectionResult detection : detections) {
            total += detection.getMaxScore();
        }
        return (int) Math.min(total, Integer.MAX_VALUE);
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

    private int computeActionableCount(DetectionStatus status) {
        int count = 0;
        for (DetectionResult detection : detections) {
            if (!detection.isWarnOnly() && detection.getStatus() == status) {
                count++;
            }
        }
        return count;
    }

    private boolean hasHardTrigger() {
        for (DetectionResult detection : detections) {
            if (detection.isWarnOnly()) {
                continue;
            }
            if (detection.getRiskLevel().getValue() < RiskLevel.HIGH.getValue()) {
                continue;
            }
            String name = detection.getDetectorName();
            List<String> details = detection.getDetails();
            if ("hook_framework".equals(name) && containsAny(details,
                    "frida_pid_port", "maps:frida", "maps:gadget")) {
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
