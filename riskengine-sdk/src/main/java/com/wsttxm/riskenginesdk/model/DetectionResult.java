package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class DetectionResult {
    private final String detectorName;
    private final RiskLevel riskLevel;
    private final DetectionStatus status;
    private final DetectionExecutionStatus executionStatus;
    private final int score;
    private final int maxScore;
    private final boolean warnOnly;
    private final int checksAttempted;
    private final int checksSucceeded;
    private final int checksFailed;
    private final List<String> failureReasons;
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
                defaultExecutionStatusFor(riskLevel),
                1,
                riskLevel == RiskLevel.UNKNOWN ? 0 : 1,
                riskLevel == RiskLevel.UNKNOWN ? 1 : 0,
                Collections.emptyList(),
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
        this(detectorName, riskLevel, status, score, maxScore, warnOnly,
                defaultExecutionStatusFor(riskLevel), 1,
                riskLevel == RiskLevel.UNKNOWN ? 0 : 1,
                riskLevel == RiskLevel.UNKNOWN ? 1 : 0,
                Collections.emptyList(), details, evidence, timestampMs);
    }

    public DetectionResult(String detectorName,
                           RiskLevel riskLevel,
                           DetectionStatus status,
                           int score,
                           int maxScore,
                           boolean informational,
                           DetectionExecutionStatus executionStatus,
                           int checksAttempted,
                           int checksSucceeded,
                           int checksFailed,
                           List<String> failureReasons,
                           List<String> details,
                           String evidence) {
        this(detectorName, riskLevel, status, score, maxScore, informational,
                executionStatus, checksAttempted, checksSucceeded, checksFailed,
                failureReasons, details, evidence, System.currentTimeMillis());
    }

    private DetectionResult(String detectorName,
                            RiskLevel riskLevel,
                            DetectionStatus status,
                            int score,
                            int maxScore,
                            boolean informational,
                            DetectionExecutionStatus executionStatus,
                            int checksAttempted,
                            int checksSucceeded,
                            int checksFailed,
                            List<String> failureReasons,
                            List<String> details,
                            String evidence,
                            long timestampMs) {
        this.detectorName = detectorName == null || detectorName.isBlank()
                ? "unknown"
                : detectorName;
        this.riskLevel = riskLevel == null ? RiskLevel.UNKNOWN : riskLevel;
        this.status = status != null ? status : defaultStatusFor(this.riskLevel);
        this.executionStatus = executionStatus != null
                ? executionStatus
                : defaultExecutionStatusFor(this.riskLevel);
        this.score = Math.max(0, score);
        this.maxScore = Math.max(this.score, Math.max(1, maxScore));
        this.warnOnly = informational;
        this.checksAttempted = Math.max(0, checksAttempted);
        this.checksSucceeded = Math.min(this.checksAttempted, Math.max(0, checksSucceeded));
        this.checksFailed = Math.min(
                Math.max(0, this.checksAttempted - this.checksSucceeded),
                Math.max(0, checksFailed));
        this.failureReasons = sanitizeDetails(failureReasons);
        this.details = sanitizeDetails(details);
        this.evidence = (evidence == null || evidence.isEmpty())
                ? String.join("; ", this.details)
                : evidence;
        this.timestampMs = timestampMs;
    }

    public String getDetectorName() { return detectorName; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public DetectionStatus getStatus() { return status; }
    public DetectionExecutionStatus getExecutionStatus() { return executionStatus; }
    public int getScore() { return score; }
    public int getMaxScore() { return maxScore; }
    /** @deprecated Use {@link #isInformational()} for clearer semantics. */
    @Deprecated
    public boolean isWarnOnly() { return warnOnly; }
    public boolean isInformational() { return warnOnly; }
    public int getChecksAttempted() { return checksAttempted; }
    public int getChecksSucceeded() { return checksSucceeded; }
    public int getChecksFailed() { return checksFailed; }
    public List<String> getFailureReasons() { return failureReasons; }
    public List<String> getDetails() { return details; }
    public String getEvidence() { return evidence; }
    public long getTimestampMs() { return timestampMs; }

    public static DetectionResult unavailable(String detectorName, String reason) {
        return executionFailure(detectorName, DetectionExecutionStatus.UNAVAILABLE, reason);
    }

    public static DetectionResult timeout(String detectorName, String reason) {
        return executionFailure(detectorName, DetectionExecutionStatus.TIMEOUT, reason);
    }

    public static DetectionResult error(String detectorName, String reason) {
        return executionFailure(detectorName, DetectionExecutionStatus.ERROR, reason);
    }

    public static DetectionResult disabled(String detectorName) {
        return executionFailure(detectorName, DetectionExecutionStatus.DISABLED, "disabled_by_config");
    }

    private static DetectionResult executionFailure(String detectorName,
                                                    DetectionExecutionStatus executionStatus,
                                                    String reason) {
        String detail = executionStatus.name().toLowerCase(Locale.ROOT) + ":"
                + ((reason == null || reason.isBlank()) ? "unknown" : reason);
        return new DetectionResult(
                detectorName,
                RiskLevel.UNKNOWN,
                DetectionStatus.UNKNOWN,
                0,
                1,
                true,
                executionStatus,
                1,
                0,
                1,
                Collections.singletonList(detail),
                Collections.singletonList(detail),
                detail
        );
    }

    private static DetectionExecutionStatus defaultExecutionStatusFor(RiskLevel riskLevel) {
        if (riskLevel == null || riskLevel == RiskLevel.UNKNOWN) {
            return DetectionExecutionStatus.UNAVAILABLE;
        }
        return riskLevel == RiskLevel.SAFE
                ? DetectionExecutionStatus.SAFE
                : DetectionExecutionStatus.RISK;
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
