package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

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

    protected abstract DetectionResult detect();

    @Override
    public DetectionResult call() {
        try {
            return detect();
        } catch (Exception | LinkageError e) {
            CLog.e("Detector [" + getName() + "] failed", e);
            return DetectionResult.error(getName(), e.getClass().getSimpleName());
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
        return new DetectionResult(getName(), level, evidence);
    }

    protected DetectionResult unavailable(String reason) {
        return DetectionResult.unavailable(getName(), reason);
    }

    protected DetectionResult result(RiskLevel level,
                                     DetectionStatus status,
                                     int score,
                                     int maxScore,
                                     boolean warnOnly,
                                     List<String> details,
                                     String evidence) {
        return new DetectionResult(getName(), level, status, score, maxScore, warnOnly, details, evidence);
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
            return DetectionResult.unavailable(getName(), "no_checks_attempted");
        }
        if (coverage.succeeded == 0) {
            return DetectionResult.unavailable(getName(), coverage.summaryReason());
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
                coverage.failureReasons, details, evidence);
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
