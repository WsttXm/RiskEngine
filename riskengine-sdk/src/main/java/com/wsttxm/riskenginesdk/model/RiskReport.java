package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.wsttxm.riskenginesdk.BuildConfig;
import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.RiskPolicy;
import com.wsttxm.riskenginesdk.collector.java_layer.SecurityPostureCollector;
import com.wsttxm.riskenginesdk.core.RiskScoringEngine;

public class RiskReport {
    public enum TrustTier {
        STRONG_HARDWARE,
        LOCAL_VERIFIED,
        DEGRADED,
        COMPROMISED
    }

    public static final int MEDIUM_THRESHOLD = RiskScoringEngine.MEDIUM_THRESHOLD;
    public static final int HIGH_THRESHOLD = RiskScoringEngine.HIGH_THRESHOLD;
    public static final int DEADLY_THRESHOLD = RiskScoringEngine.DEADLY_THRESHOLD;
    public static final int MAX_RISK_SCORE = RiskScoringEngine.MAX_SCORE;
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
    private final RiskAction recommendedAction;
    private final Map<RiskDimension, Integer> dimensionScores;
    private final ScoreBreakdown scoreBreakdown;
    private final List<String> hardTriggers;
    private final int confidencePercent;
    private final ReportStatus reportStatus;
    private final int availableDetectionCount;
    private final int checkCount;
    private final int completedCheckCount;
    private final int unsupportedCheckCount;
    private final CollectScene collectScene;
    private final RiskPolicy riskPolicy;
    private final FingerprintId fingerprintId;
    private final DevicePosture devicePosture;
    private final int anchorDriftCount;
    private final TrustTier trustTier;

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections) {
        this(fingerprint, detections, CollectScene.STANDARD, null, null, 0);
    }

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections,
                      CollectScene collectScene) {
        this(fingerprint, detections, collectScene, null, null, 0);
    }

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections,
                      CollectScene collectScene, FingerprintId fingerprintId) {
        this(fingerprint, detections, collectScene, fingerprintId, null, 0);
    }

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections,
                      CollectScene collectScene, FingerprintId fingerprintId,
                      DevicePosture devicePosture, int anchorDriftCount) {
        this(fingerprint,
                detections,
                RiskPolicy.forScene(collectScene == null ? CollectScene.STANDARD : collectScene),
                fingerprintId,
                devicePosture,
                anchorDriftCount);
    }

    public RiskReport(DeviceFingerprint fingerprint, List<DetectionResult> detections,
                      RiskPolicy riskPolicy, FingerprintId fingerprintId,
                      DevicePosture devicePosture, int anchorDriftCount) {
        this.fingerprintId = fingerprintId;
        this.fingerprint = Objects.requireNonNull(fingerprint, "fingerprint must not be null");
        this.riskPolicy = riskPolicy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : riskPolicy;
        this.collectScene = this.riskPolicy.getBaseScene();
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
        this.warningCount = computeCount(DetectionStatus.WARNING);
        this.dangerCount = computeCount(DetectionStatus.DANGER);
        this.unknownCount = computeCount(DetectionStatus.UNKNOWN);
        RiskScoringEngine.Evaluation eval = RiskScoringEngine.evaluate(
                this.fingerprint, this.detections, this.riskPolicy);
        this.riskScore = eval.riskScore;
        this.maxRiskScore = MAX_RISK_SCORE;
        this.overallRiskLevel = eval.overallRiskLevel;
        this.recommendedAction = eval.recommendedAction;
        this.dimensionScores = eval.dimensionScores;
        this.scoreBreakdown = eval.scoreBreakdown;
        this.hardTriggers = eval.hardTriggers;
        this.confidencePercent = eval.confidencePercent;
        this.availableDetectionCount = computeAvailableDetectionCount();
        this.checkCount = computeCheckCount();
        this.completedCheckCount = computeCompletedCheckCount();
        this.unsupportedCheckCount = computeUnsupportedCheckCount();
        this.reportStatus = computeReportStatus();
        this.devicePosture = devicePosture != null
                ? devicePosture
                : SecurityPostureCollector.fromFingerprint(this.fingerprint);
        this.anchorDriftCount = Math.max(0, anchorDriftCount);
        this.trustTier = computeTrustTier();
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
    /** Non-threat device security hygiene snapshot. */
    public DevicePosture getDevicePosture() { return devicePosture; }
    /** Number of observed hardware drifts against the immutable initial anchor. */
    public int getAnchorDriftCount() { return anchorDriftCount; }
    /** High-level trust tier derived from risk level, report completeness, and hardware posture. */
    public TrustTier getTrustTier() { return trustTier; }

    public RiskLevel getOverallRiskLevel() { return overallRiskLevel; }
    /** Recommended local business action derived from the risk assessment and scene policy. */
    public RiskAction getRecommendedAction() { return recommendedAction; }
    /** Normalized 0–100 sub-scores across the four orthogonal Risk Dimensions. */
    public Map<RiskDimension, Integer> getDimensionScores() { return dimensionScores; }
    /** Convenience accessor returning the 0–100 sub-score for a single {@link RiskDimension}. */
    public int getDimensionScore(RiskDimension dimension) {
        if (dimension == null) return 0;
        Integer value = dimensionScores.get(dimension);
        return value == null ? 0 : value;
    }
    /** Auditable, item-by-item explanation of how the final 0–100 score was produced. */
    public ScoreBreakdown getScoreBreakdown() { return scoreBreakdown; }
    /** Deterministic, sorted list of active Hard Triggers matched by this report. */
    public List<String> getHardTriggers() { return hardTriggers; }
    /** Tier-weighted Assessment Confidence (0–100%), decoupled from the risk score. */
    public int getConfidencePercent() { return confidencePercent; }
    public ReportStatus getReportStatus() { return reportStatus; }
    public int getAvailableDetectionCount() { return availableDetectionCount; }
    public int getDetectionCount() { return detections.size(); }
    public int getCheckCount() { return checkCount; }
    public int getCompletedCheckCount() { return completedCheckCount; }
    public int getUnsupportedCheckCount() { return unsupportedCheckCount; }
    public int getIncompleteCheckCount() { return Math.max(0, checkCount - completedCheckCount); }
    public int getCoveragePercent() {
        return checkCount == 0 ? 100
                : Math.round(completedCheckCount * 100f / checkCount);
    }
    public int getDisplayThresholdMaximum() { return MAX_RISK_SCORE; }
    public int getNextRiskThreshold() {
        int challenge = riskPolicy.getChallengeThreshold();
        int restrict = riskPolicy.getRestrictThreshold();
        int block = riskPolicy.getBlockThreshold();
        if (riskScore < challenge) return challenge;
        if (riskScore < restrict) return restrict;
        if (riskScore < block) return block;
        return block;
    }
    public int getScoreToNextRiskThreshold() {
        return Math.max(0, getNextRiskThreshold() - riskScore);
    }
    public CollectScene getCollectScene() { return collectScene; }
    /** Effective local {@link RiskPolicy} used to evaluate this report. */
    public RiskPolicy getRiskPolicy() { return riskPolicy; }

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

    private int computeCount(DetectionStatus status) {
        int count = 0;
        for (DetectionResult detection : detections) {
            if (detection.getStatus() == status) {
                count++;
            }
        }
        return count;
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
        for (CollectorResult result : fingerprint.getResults().values()) {
            if (!isSyntheticCollector(result.getFieldName())
                    && !isUnsupportedCollectorStatus(result.getStatus())) {
                count++;
            }
        }
        return count;
    }

    private int computeUnsupportedCheckCount() {
        int count = 0;
        for (CollectorResult result : fingerprint.getResults().values()) {
            if (!isSyntheticCollector(result.getFieldName())
                    && isUnsupportedCollectorStatus(result.getStatus())) {
                count++;
            }
        }
        return count;
    }

    private static boolean isUnsupportedCollectorStatus(CollectorResult.Status status) {
        return status == CollectorResult.Status.UNSUPPORTED
                || status == CollectorResult.Status.EMPTY;
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
                || "runtime_integrity_score_inputs".equals(fieldName)
                || "fingerprint_id".equals(fieldName);
    }

    private ReportStatus computeReportStatus() {
        if (checkCount == 0 || completedCheckCount == checkCount) {
            return ReportStatus.COMPLETE;
        }
        return completedCheckCount == 0 && availableDetectionCount == 0
                ? ReportStatus.UNAVAILABLE
                : ReportStatus.PARTIAL;
    }

    private DetectionResult findDetection(String detectorName) {
        for (DetectionResult d : detections) {
            if (detectorName.equals(d.getDetectorName())) {
                return d;
            }
        }
        return null;
    }

    private static boolean isTeeHardwareVerifiedLocked(DetectionResult teeDet) {
        if (teeDet == null
                || teeDet.getRiskLevel() != RiskLevel.SAFE
                || teeDet.getStatus() != DetectionStatus.NORMAL
                || teeDet.getScore() != 0) {
            return false;
        }
        String ev = teeDet.getEvidence();
        return ev != null && ev.startsWith("hardware_attested_locked_verified:");
    }

    private TrustTier computeTrustTier() {
        if (overallRiskLevel == RiskLevel.HIGH || overallRiskLevel == RiskLevel.DEADLY) {
            return TrustTier.COMPROMISED;
        }
        if (overallRiskLevel == RiskLevel.MEDIUM
                || overallRiskLevel == RiskLevel.UNKNOWN
                || reportStatus != ReportStatus.COMPLETE) {
            return TrustTier.DEGRADED;
        }
        if (overallRiskLevel == RiskLevel.SAFE) {
            DetectionResult teeDet = findDetection("tee_integrity");
            if (teeDet != null) {
                return isTeeHardwareVerifiedLocked(teeDet)
                        ? TrustTier.STRONG_HARDWARE
                        : TrustTier.LOCAL_VERIFIED;
            }
            if (devicePosture != null
                    && devicePosture.isHardwareKeystoreBacked()
                    && devicePosture.isStorageEncrypted()
                    && devicePosture.isDeviceSecure()) {
                return TrustTier.STRONG_HARDWARE;
            }
        }
        return TrustTier.LOCAL_VERIFIED;
    }
}
