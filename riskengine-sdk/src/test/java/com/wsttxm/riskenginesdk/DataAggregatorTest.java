package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DataAggregatorTest {
    @Test
    public void synthesizedFieldsAreExposedButNotDoubleCountedInCoverage() {
        CollectorResult collector = new CollectorResult("build_props");
        collector.addValue("model", "test");
        DetectionResult hook = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("maps:frida"), "maps:frida");

        RiskReport report = new DataAggregator().aggregate(
                List.of(collector), List.of(hook));

        assertTrue(report.getFingerprint().getResults().containsKey("hook_memory_signals"));
        assertTrue(report.getFingerprint().getResults()
                .containsKey("runtime_integrity_score_inputs"));
        assertEquals(2, report.getCheckCount());
        assertEquals(2, report.getCompletedCheckCount());
        assertEquals(100, report.getCoveragePercent());
    }
}
