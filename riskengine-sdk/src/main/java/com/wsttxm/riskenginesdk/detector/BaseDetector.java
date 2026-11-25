package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

public abstract class BaseDetector implements Callable<DetectionResult> {
    protected final Context context;

    public BaseDetector(Context context) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
    }

    public abstract String getName();

    /** Scheduling latency tier for this detector; defaults to {@link ScanTier#FAST}. */
    public ScanTier getScanTier() {
        return ScanTier.FAST;
    }

    /** Per-detector execution timeout budget; defaults to its {@link ScanTier} budget. */
    public long getTimeoutMs() {
        ScanTier tier = getScanTier();
        return tier == null ? ScanTier.FAST.getDefaultTimeoutMs() : tier.getDefaultTimeoutMs();
    }

    /**
     * Returns {@code true} when this detector mounts heavy probes (e.g. disposable fork child,
     * isolated process mount diff, timing side-channels) that should run asynchronously in Stage 3
     * ({@link ScanTier#POSTPONED}) via {@link #detectPostponed(DetectionResult)} after the fast pass.
     */
    public boolean hasPostponedProbes() {
        return false;
    }

    /** Per-detector timeout budget for {@link #detectPostponed(DetectionResult)}. */
    public long getPostponedTimeoutMs() {
        return ScanTier.POSTPONED.getDefaultTimeoutMs();
    }

    /**
     * Optional Stage 3 postponed-probe pass that merges heavier probe findings into
     * {@code priorResult} produced during the fast pass. Defaults to returning {@code priorResult}
     * unchanged for 100% backward compatibility.
     */
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        return priorResult;
    }

    /**
     * Crash-safe invocation wrapper around {@link #detectPostponed(DetectionResult)}.
     * Falls back cleanly to {@code priorResult} on {@code null} or any throwable.
     */
    public final DetectionResult callPostponed(DetectionResult priorResult) {
        try {
            DetectionResult updated = detectPostponed(priorResult);
            if (updated == null) {
                return priorResult;
            }
            return updated.withScanTier(getScanTier());
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Detector [" + getName() + "] postponed pass failed", e);
            return priorResult;
        }
    }

    protected abstract DetectionResult detect();

    @Override
    public DetectionResult call() {
        try {
            DetectionResult result = detect();
            if (result == null) {
                return DetectionResult.error(getName(), "null_result").withScanTier(getScanTier());
            }
            return result.withScanTier(getScanTier());
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Detector [" + getName() + "] failed", e);
            return DetectionResult.error(getName(), e.getClass().getSimpleName())
                    .withScanTier(getScanTier());
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
        return new DetectionResult(getName(), level, evidence).withScanTier(getScanTier());
    }

    protected DetectionResult unavailable(String reason) {
        return DetectionResult.unavailable(getName(), reason).withScanTier(getScanTier());
    }

    protected DetectionResult result(RiskLevel level,
                                     DetectionStatus status,
                                     int score,
                                     int maxScore,
                                     boolean warnOnly,
                                     List<String> details,
                                     String evidence) {
        return new DetectionResult(getName(), level, status, score, maxScore, warnOnly, details, evidence)
                .withScanTier(getScanTier());
    }

    protected DetectionResult result(RiskLevel level,
                                     DetectionStatus status,
                                     int score,
                                     int maxScore,
                                     boolean informational,
                                     List<String> details,
                                     String evidence,
                                     CheckCoverage coverage) {
        if (coverage == null || coverage.attempted == 0) {
            return DetectionResult.unavailable(getName(), "no_checks_attempted")
                    .withScanTier(getScanTier());
        }
        if (coverage.succeeded == 0) {
            return DetectionResult.unavailable(getName(), coverage.summaryReason())
                    .withScanTier(getScanTier());
        }
        DetectionExecutionStatus executionStatus;
        if (coverage.failed > 0) {
            executionStatus = DetectionExecutionStatus.PARTIAL;
        } else if (level == RiskLevel.SAFE) {
            executionStatus = DetectionExecutionStatus.SAFE;
        } else {
            executionStatus = DetectionExecutionStatus.RISK;
        }
        return new DetectionResult(
                getName(), level, status, score, maxScore, informational,
                executionStatus, coverage.attempted, coverage.succeeded, coverage.failed,
                coverage.failureReasons, details, evidence).withScanTier(getScanTier());
    }

    protected DetectionResult safe(CheckCoverage coverage) {
        return result(RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                Collections.emptyList(), "no risk detected", coverage);
    }

    /** Tracks whether each logical detector check was actually executed. */
    protected static final class CheckCoverage {
        private int attempted;
        private int succeeded;
        private int failed;
        private final List<String> failureReasons = new ArrayList<>();

        public CheckCoverage() {}

        public void success() {
            attempted++;
            succeeded++;
        }

        public void failure(String reason) {
            attempted++;
            failed++;
            failureReasons.add(reason == null || reason.isBlank() ? "unknown" : reason);
        }

        private String summaryReason() {
            return failureReasons.isEmpty()
                    ? "all_checks_failed"
                    : String.join(",", failureReasons);
        }
    }
}
