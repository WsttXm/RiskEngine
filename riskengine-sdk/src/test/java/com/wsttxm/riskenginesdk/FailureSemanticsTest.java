package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.List;

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
    }

    @Test
    public void unknownCoverageProducesUnknownOverallLevel() {
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                List.of(DetectionResult.unavailable("broken", "timeout")));

        assertEquals(1, report.getUnknownCount());
        assertEquals(RiskLevel.UNKNOWN, report.getOverallRiskLevel());
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
}
