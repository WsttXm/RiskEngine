package com.wsttxm.riskenginesdk.model;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.RiskPolicy;
import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.core.RiskScoringEngine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable summary delivered when a {@link ScanTier} stage finishes executing.
 */
public final class TierReport {

    private final ScanTier tier;
    private final List<DetectionResult> detections;
    private final RiskLevel highestRiskLevel;
    private final int riskScore;
    private final long elapsedMs;
    private final long timestampMs;
    private final boolean partial;

    public TierReport(ScanTier tier,
                      List<DetectionResult> detections,
                      long elapsedMs) {
        this(tier, detections, elapsedMs, System.currentTimeMillis());
    }

    public TierReport(ScanTier tier,
                      List<DetectionResult> detections,
                      long elapsedMs,
                      long timestampMs) {
        this(tier, detections, elapsedMs, timestampMs, RiskPolicy.forScene(CollectScene.STANDARD));
    }

    public TierReport(ScanTier tier,
                      List<DetectionResult> detections,
                      long elapsedMs,
                      long timestampMs,
                      RiskPolicy riskPolicy) {
        this.tier = Objects.requireNonNull(tier, "tier must not be null");
        Objects.requireNonNull(detections, "detections must not be null");
        List<DetectionResult> copy = new ArrayList<>(detections.size());
        boolean hasPartial = false;

        for (DetectionResult item : detections) {
            Objects.requireNonNull(item, "detections must not contain null");
            copy.add(item);
            DetectionExecutionStatus execStatus = item.getExecutionStatus();
            if (execStatus == DetectionExecutionStatus.PARTIAL
                    || execStatus == DetectionExecutionStatus.TIMEOUT
                    || execStatus == DetectionExecutionStatus.ERROR
                    || execStatus == DetectionExecutionStatus.UNAVAILABLE) {
                hasPartial = true;
            }
        }

        List<DetectionResult> unmodifiableCopy = Collections.unmodifiableList(copy);
        RiskPolicy effectivePolicy = riskPolicy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : riskPolicy;
        RiskScoringEngine.Evaluation eval = RiskScoringEngine.evaluateTier(
                this.tier, unmodifiableCopy, effectivePolicy);

        this.detections = unmodifiableCopy;
        this.highestRiskLevel = eval.overallRiskLevel;
        this.riskScore = eval.riskScore;
        this.elapsedMs = Math.max(0L, elapsedMs);
        this.timestampMs = timestampMs > 0 ? timestampMs : System.currentTimeMillis();
        this.partial = hasPartial;
    }

    public ScanTier getTier() {
        return tier;
    }

    public List<DetectionResult> getDetections() {
        return detections;
    }

    public RiskLevel getHighestRiskLevel() {
        return highestRiskLevel;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public long getElapsedMs() {
        return elapsedMs;
    }

    public long getTimestampMs() {
        return timestampMs;
    }

    public boolean isPartial() {
        return partial;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TierReport)) return false;
        TierReport that = (TierReport) o;
        return riskScore == that.riskScore
                && elapsedMs == that.elapsedMs
                && timestampMs == that.timestampMs
                && partial == that.partial
                && tier == that.tier
                && detections.equals(that.detections)
                && highestRiskLevel == that.highestRiskLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(tier, detections, highestRiskLevel, riskScore,
                elapsedMs, timestampMs, partial);
    }

    @Override
    public String toString() {
        return "TierReport{"
                + "tier=" + tier
                + ", detections=" + detections.size()
                + ", highestRiskLevel=" + highestRiskLevel
                + ", riskScore=" + riskScore
                + ", elapsedMs=" + elapsedMs
                + ", partial=" + partial
                + '}';
    }
}
