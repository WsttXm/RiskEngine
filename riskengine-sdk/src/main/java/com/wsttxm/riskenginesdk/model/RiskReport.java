package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.wsttxm.riskenginesdk.BuildConfig;
import com.wsttxm.riskenginesdk.CollectScene;

public class RiskReport {
    public static final int MEDIUM_THRESHOLD = 4;
    public static final int HIGH_THRESHOLD = 10;
    public static final int DEADLY_THRESHOLD = 18;
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
    private final ReportStatus reportStatus;
    private final int availableDetectionCount;
    private final int checkCount;
    private final int completedCheckCount;
    private final CollectScene collectScene;
    private final FingerprintId fingerprintId;

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections) {
        this(fingerprint, detections, CollectScene.STANDARD, null);
    }

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections,
                      CollectScene collectScene) {
        this(fingerprint, detections, collectScene, null);
    }

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections,
                      CollectScene collectScene, FingerprintId fingerprintId) {
        this.fingerprintId = fingerprintId;
        this.fingerprint = Objects.requireNonNull(fingerprint, "fingerprint must not be null");
        this.collectScene = collectScene == null ? CollectScene.STANDARD : collectScene;
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
        this.availableDetectionCount = computeAvailableDetectionCount();
        this.checkCount = computeCheckCount();
        this.completedCheckCount = computeCompletedCheckCount();
        this.reportStatus = computeReportStatus();
    }

    private RiskLevel computeOverallRisk() {
        int actionableWarnings = computeActionableCount(DetectionStatus.WARNING);
        int actionableDangers = computeActionableCount(DetectionStatus.DANGER);
        RiskLevel level;
        if (hasHardTrigger()) {
            level = RiskLevel.DEADLY;
        } else if (riskScore >= DEADLY_THRESHOLD || actionableDangers >= 3) {
            level = RiskLevel.DEADLY;
        } else if (riskScore >= HIGH_THRESHOLD || actionableDangers >= 1) {
            level = RiskLevel.HIGH;
        } else if (riskScore >= MEDIUM_THRESHOLD || actionableWarnings >= 2) {
            level = RiskLevel.MEDIUM;
        } else if (riskScore > 0 || warningCount >= 1 || dangerCount >= 1) {
            level = RiskLevel.LOW;
        } else if (unknownCount > 0 || hasIncompleteDetectorExecution()) {
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
    /** The layered device fingerprint ID, or null when composition failed. */
    public FingerprintId getFingerprintId() { return fingerprintId; }

    public RiskLevel getOverallRiskLevel() { return overallRiskLevel; }
    public ReportStatus getReportStatus() { return reportStatus; }
    public int getAvailableDetectionCount() { return availableDetectionCount; }
    public int getDetectionCount() { return detections.size(); }
    public int getCheckCount() { return checkCount; }
    public int getCompletedCheckCount() { return completedCheckCount; }
    public int getIncompleteCheckCount() { return Math.max(0, checkCount - completedCheckCount); }
    public int getCoveragePercent() {
        return checkCount == 0 ? 100
                : Math.round(completedCheckCount * 100f / checkCount);
    }
    public int getDisplayThresholdMaximum() { return DEADLY_THRESHOLD; }
    public int getNextRiskThreshold() {
        if (riskScore < MEDIUM_THRESHOLD) return MEDIUM_THRESHOLD;
        if (riskScore < HIGH_THRESHOLD) return HIGH_THRESHOLD;
        if (riskScore < DEADLY_THRESHOLD) return DEADLY_THRESHOLD;
        return DEADLY_THRESHOLD;
    }
    public int getScoreToNextRiskThreshold() {
        return Math.max(0, getNextRiskThreshold() - riskScore);
    }
    public CollectScene getCollectScene() { return collectScene; }

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
            if (!detection.isInformational()) {
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
            if (!detection.isInformational() && detection.getStatus() == status) {
                count++;
            }
        }
        return count;
    }

    private boolean hasHardTrigger() {
        for (DetectionResult detection : detections) {
            if (detection.isInformational()) {
                continue;
            }
            if (detection.getRiskLevel().getValue() < RiskLevel.HIGH.getValue()) {
                continue;
            }
            String name = detection.getDetectorName();
            List<String> details = detection.getDetails();
            if (containsAny(details, "inline_hook:", "got_hook:")) {
                return true;
            }
            if ("hook_framework".equals(name) && containsAny(details,
                    "frida_pid_port", "maps:frida", "maps:gadget")) {
                return true;
            }
            if ("signal_correlation".equals(name) && containsAny(details, "C3:")) {
                return true;
            }
        }
        return false;
    }

    private boolean hasIncompleteDetectorExecution() {
        for (DetectionResult detection : detections) {
            switch (detection.getExecutionStatus()) {
                case PARTIAL:
                case UNAVAILABLE:
                case TIMEOUT:
                case ERROR:
                    return true;
                default:
                    break;
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

    private int computeAvailableDetectionCount() {
        int count = 0;
        for (DetectionResult detection : detections) {
            switch (detection.getExecutionStatus()) {
                case SAFE:
                case RISK:
                case PARTIAL:
                    count++;
                    break;
                default:
                    break;
            }
        }
        return count;
    }

    private int computeCheckCount() {
        int count = 0;
        for (DetectionResult detection : detections) {
            if (!detection.getDetectorName().startsWith("collector:")) {
                count++;
            }
        }
        for (String fieldName : fingerprint.getResults().keySet()) {
            if (!isSyntheticCollector(fieldName)) {
                count++;
            }
        }
        return count;
    }

    private int computeCompletedCheckCount() {
        int count = 0;
        for (DetectionResult detection : detections) {
            if (detection.getDetectorName().startsWith("collector:")) {
                continue;
            }
            switch (detection.getExecutionStatus()) {
                case SAFE:
                case RISK:
                    count++;
                    break;
                default:
                    break;
            }
        }
        for (CollectorResult result : fingerprint.getResults().values()) {
            if (!isSyntheticCollector(result.getFieldName())
                    && result.getStatus() == CollectorResult.Status.SUCCESS) {
                count++;
            }
        }
        return count;
    }

    private boolean isSyntheticCollector(String fieldName) {
        return "hook_memory_signals".equals(fieldName)
                || "runtime_integrity_score_inputs".equals(fieldName);
    }

    private ReportStatus computeReportStatus() {
        if (checkCount == 0 || completedCheckCount == checkCount) {
            return ReportStatus.COMPLETE;
        }
        return completedCheckCount == 0 && availableDetectionCount == 0
                ? ReportStatus.UNAVAILABLE
                : ReportStatus.PARTIAL;
    }
}
