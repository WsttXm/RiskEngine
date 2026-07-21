package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DetectionResult {
    private final String detectorName;
    private final RiskLevel riskLevel;
    private final DetectionStatus status;
    private final int score;
    private final int maxScore;
    private final boolean warnOnly;
    private final List<String> details;
    private final String evidence;
    private final long timestampMs;

    public DetectionResult(String detectorName, RiskLevel riskLevel, String evidence) {
        this(
                detectorName,
                riskLevel,
                defaultStatusFor(riskLevel),
                defaultScoreFor(riskLevel),
                10,
                false,
                deriveDetails(evidence),
                evidence,
                System.currentTimeMillis()
        );
    }

    public DetectionResult(String detectorName,
                           RiskLevel riskLevel,
                           DetectionStatus status,
                           int score,
                           int maxScore,
                           boolean warnOnly,
                           List<String> details,
                           String evidence) {
        this(detectorName, riskLevel, status, score, maxScore, warnOnly, details, evidence,
                System.currentTimeMillis());
    }

    public DetectionResult(String detectorName,
                           RiskLevel riskLevel,
                           DetectionStatus status,
                           int score,
                           int maxScore,
                           boolean warnOnly,
                           List<String> details,
                           String evidence,
                           long timestampMs) {
        this.detectorName = detectorName == null || detectorName.isBlank()
                ? "unknown"
                : detectorName;
        this.riskLevel = riskLevel == null ? RiskLevel.UNKNOWN : riskLevel;
        this.status = status != null ? status : defaultStatusFor(this.riskLevel);
        this.score = Math.max(0, score);
        this.maxScore = Math.max(this.score, Math.max(1, maxScore));
        this.warnOnly = warnOnly;
        this.details = sanitizeDetails(details);
        this.evidence = (evidence == null || evidence.isEmpty())
                ? String.join("; ", this.details)
                : evidence;
        this.timestampMs = timestampMs;
    }

    public String getDetectorName() { return detectorName; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public DetectionStatus getStatus() { return status; }
    public int getScore() { return score; }
    public int getMaxScore() { return maxScore; }
    public boolean isWarnOnly() { return warnOnly; }
    public List<String> getDetails() { return details; }
    public String getEvidence() { return evidence; }
    public long getTimestampMs() { return timestampMs; }

    public static DetectionResult unavailable(String detectorName, String reason) {
        String detail = "detection_unavailable:"
                + ((reason == null || reason.isBlank()) ? "unknown" : reason);
        return new DetectionResult(
                detectorName,
                RiskLevel.UNKNOWN,
                DetectionStatus.UNKNOWN,
                0,
                1,
                true,
                Collections.singletonList(detail),
                detail
        );
    }

    private static DetectionStatus defaultStatusFor(RiskLevel riskLevel) {
        if (riskLevel == null || riskLevel == RiskLevel.UNKNOWN) {
            return DetectionStatus.UNKNOWN;
        }
        if (riskLevel == RiskLevel.SAFE) {
            return DetectionStatus.NORMAL;
        }
        if (riskLevel == RiskLevel.LOW || riskLevel == RiskLevel.MEDIUM) {
            return DetectionStatus.WARNING;
        }
        return DetectionStatus.DANGER;
    }

    private static int defaultScoreFor(RiskLevel riskLevel) {
        if (riskLevel == null) {
            return 0;
        }
        switch (riskLevel) {
            case UNKNOWN:
                return 0;
            case LOW:
                return 2;
            case MEDIUM:
                return 4;
            case HIGH:
                return 7;
            case DEADLY:
                return 10;
            case SAFE:
            default:
                return 0;
        }
    }

    private static List<String> deriveDetails(String evidence) {
        if (evidence == null || evidence.isBlank()) {
            return Collections.emptyList();
        }
        String[] tokens = evidence.split(";\\s*");
        List<String> details = new ArrayList<>();
        for (String token : tokens) {
            if (!token.isBlank()) {
                details.add(token.trim());
            }
        }
        return details;
    }

    private static List<String> sanitizeDetails(List<String> details) {
        if (details == null || details.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> copy = new ArrayList<>(details.size());
        for (String detail : details) {
            if (detail != null && !detail.isBlank()) {
                copy.add(detail);
            }
        }
        return Collections.unmodifiableList(copy);
    }
}
