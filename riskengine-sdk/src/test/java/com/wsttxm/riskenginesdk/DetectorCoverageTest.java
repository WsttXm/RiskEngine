package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DetectorCoverageTest {
    @Test
    public void allFailedSubchecksBecomeUnavailable() {
        DetectionResult result = new CoverageDetector(false).call();
        assertEquals(DetectionExecutionStatus.UNAVAILABLE, result.getExecutionStatus());
        assertEquals(RiskLevel.UNKNOWN, result.getRiskLevel());
    }

    @Test
    public void mixedSubchecksBecomePartial() {
        DetectionResult result = new CoverageDetector(true).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, result.getExecutionStatus());
        assertEquals(2, result.getChecksAttempted());
        assertEquals(1, result.getChecksSucceeded());
        assertEquals(1, result.getChecksFailed());
    }

    private static final class CoverageDetector extends BaseDetector {
        private final boolean oneSucceeded;

        private CoverageDetector(boolean oneSucceeded) {
            super(null);
            this.oneSucceeded = oneSucceeded;
        }

        @Override public String getName() { return "coverage"; }

        @Override protected DetectionResult detect() {
            CheckCoverage coverage = new CheckCoverage();
            if (oneSucceeded) coverage.success();
            else coverage.failure("first_failed");
            coverage.failure("second_failed");
            return safe(coverage);
        }
    }
}
