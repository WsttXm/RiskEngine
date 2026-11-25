package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.ReportStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.List;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class FailureSemanticsTest {
    @Test
    public void detectorFailureIsUnknownRatherThanSafe() {
        BaseDetector detector = new BaseDetector(null) {
            @Override public String getName() { return "broken"; }
            @Override protected DetectionResult detect() { throw new IllegalStateException("boom"); }
        };

        DetectionResult result = detector.call();
        assertEquals(DetectionStatus.UNKNOWN, result.getStatus());
        assertEquals(RiskLevel.UNKNOWN, result.getRiskLevel());
        assertEquals(DetectionExecutionStatus.ERROR, result.getExecutionStatus());
    }

    @Test
    public void unknownCoverageProducesUnknownOverallLevel() {
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                List.of(DetectionResult.unavailable("broken", "timeout")));

        assertEquals(1, report.getUnknownCount());
        assertEquals(RiskLevel.UNKNOWN, report.getOverallRiskLevel());
        assertEquals(ReportStatus.UNAVAILABLE, report.getReportStatus());
    }

    @Test
    public void timeoutAndUnavailableRemainDistinguishable() {
        assertEquals(DetectionExecutionStatus.TIMEOUT,
                DetectionResult.timeout("slow", "deadline").getExecutionStatus());
        assertEquals(DetectionExecutionStatus.UNAVAILABLE,
                DetectionResult.unavailable("missing", "unsupported").getExecutionStatus());
    }

    @Test
    public void partiallyExecutedSafeCheckCannotProduceSafeReport() {
        DetectionResult partial = new DetectionResult(
                "partial", RiskLevel.SAFE, DetectionStatus.NORMAL,
                0, 10, false, DetectionExecutionStatus.PARTIAL,
                2, 1, 1, List.of("second_check_failed"),
                Collections.emptyList(), "");

        RiskReport report = new RiskReport(new DeviceFingerprint(), List.of(partial));

        assertEquals(RiskLevel.UNKNOWN, report.getOverallRiskLevel());
        assertEquals(ReportStatus.PARTIAL, report.getReportStatus());
        assertEquals(0, report.getCompletedCheckCount());
    }

    @Test
    public void collectorFailureIsVisibleInAggregatedCoverage() {
        BaseCollector collector = new BaseCollector(null) {
            @Override public String getName() { return "broken_collector"; }
            @Override protected void collect(CollectorResult result) {
                throw new IllegalStateException("boom");
            }
        };

        CollectorResult result = collector.call();
        RiskReport report = new DataAggregator().aggregate(List.of(result), List.of());

        assertEquals(CollectorResult.Status.ERROR, result.getStatus());
        assertEquals(RiskLevel.UNKNOWN, report.getOverallRiskLevel());
        assertTrue(report.getUnknownCount() > 0);
    }

    @Test
    public void unavailableNativeLibraryIsReportedAsUnsupported() {
        if (NativeCollectorBridge.isNativeAvailable()) {
            return;
        }
        CollectorResult result = new NativeCollectorBridge(null).getCpuInfoCollector().call();
        assertEquals(CollectorResult.Status.UNSUPPORTED, result.getStatus());
    }

    @Test
    public void nullRiskLevelIsNormalizedToUnknown() {
        DetectionResult result = new DetectionResult("invalid", null, "");

        assertEquals(RiskLevel.UNKNOWN, result.getRiskLevel());
        assertEquals(DetectionStatus.UNKNOWN, result.getStatus());
    }

    @Test
    public void unknownEnumValuesDoNotShiftExistingOrdinals() {
        assertEquals(0, RiskLevel.SAFE.ordinal());
        assertEquals(4, RiskLevel.DEADLY.ordinal());
        assertEquals(0, DetectionStatus.NORMAL.ordinal());
        assertEquals(2, DetectionStatus.DANGER.ordinal());
    }

    @Test
    public void collectorErrorAndTimeoutStillDegradeCoverageWhileUnsupportedDoesNot() {
        CollectorResult timeoutCollector = new CollectorResult("slow_collector");
        timeoutCollector.markError("timeout");
        CollectorResult unsupportedCollector = new CollectorResult("optional_collector");
        unsupportedCollector.markUnsupported("feature_absent");
        DetectionResult cleanDetector = new DetectionResult(
                "root", RiskLevel.SAFE, DetectionStatus.NORMAL,
                0, 10, false, List.of(), "");

        RiskReport report = new DataAggregator().aggregate(
                List.of(timeoutCollector, unsupportedCollector), List.of(cleanDetector));

        // Per ADR-0002 / tiered Assessment Confidence: collector timeout degrades reportStatus
        // and coveragePercent honestly while Detection Domain confidence remains 100% (SAFE).
        assertEquals(RiskLevel.SAFE, report.getOverallRiskLevel());
        assertEquals(100, report.getConfidencePercent());
        assertEquals(50, report.getCoveragePercent());
        assertEquals(ReportStatus.PARTIAL, report.getReportStatus());
        assertEquals(1, report.getUnsupportedCheckCount());
        assertEquals(1, report.getIncompleteCheckCount());
        assertEquals(1, report.getUnknownCount());
        DetectionResult coverageGap = report.getDetections().stream()
                .filter(d -> "collector:slow_collector".equals(d.getDetectorName()))
                .findFirst().orElseThrow();
        assertEquals(DetectionExecutionStatus.TIMEOUT, coverageGap.getExecutionStatus());
    }

    @Test
    public void systemPropertiesNativePartialSelinuxFailureKeepsSuccessAndRecordsPartialErrors() {
        CollectorResult result = new CollectorResult("system_properties_native");
        NativeCollectorBridge.collectSystemProperties(result, 34, prop -> {
            if ("ro.kernel.qemu".equals(prop) || "ro.boot.qemu".equals(prop)) {
                return SignalResult.error("selinux_denied");
            }
            if ("ro.product.model".equals(prop)) {
                return SignalResult.success("Pixel 9");
            }
            return SignalResult.empty("");
        });
        result.finish();

        assertEquals(CollectorResult.Status.SUCCESS, result.getStatus());
        assertEquals("Pixel 9", result.getValues().get("ro.product.model"));
        assertEquals("ro.kernel.qemu,ro.boot.qemu", result.getValues().get("partial_errors"));

        // Must not degrade a clean report from SAFE to UNKNOWN.
        RiskReport report = new DataAggregator().aggregate(List.of(result), List.of());
        assertEquals(RiskLevel.SAFE, report.getOverallRiskLevel());
        assertEquals(0, report.getUnknownCount());
    }

    @Test
    public void systemPropertiesNativeMarksErrorOnlyWhenAllPropertiesFail() {
        CollectorResult result = new CollectorResult("system_properties_native");
        NativeCollectorBridge.collectSystemProperties(result, 34,
                prop -> SignalResult.error("selinux_denied"));
        result.finish();

        assertEquals(CollectorResult.Status.ERROR, result.getStatus());
        assertTrue(result.getError().startsWith("all_properties_failed:"));

        RiskReport report = new DataAggregator().aggregate(List.of(result), List.of());
        assertEquals(RiskLevel.UNKNOWN, report.getOverallRiskLevel());
        assertEquals(1, report.getUnknownCount());
    }
}
