package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class CollectorResultTest {
    @Test
    public void independentAttributesAreNotCompared() {
        CollectorResult result = new CollectorResult("build_props");
        result.addValue("brand", "Google");
        result.addValue("model", "Pixel");

        assertTrue(result.isConsistent());
    }

    @Test
    public void observationsOfSameFieldAreCompared() {
        CollectorResult result = new CollectorResult("android_id", true);
        result.addValue("settings", "one");
        result.addValue("resolver", "two");

        assertFalse(result.isConsistent());
    }

    @Test
    public void normalAggregateDoesNotCreateSyntheticInconsistency() {
        CollectorResult build = new CollectorResult("build_props");
        build.addValue("brand", "Google");
        build.addValue("model", "Pixel");
        build.finish();

        DetectionResult safe = new DetectionResult("root", RiskLevel.SAFE, "");
        RiskReport report = new DataAggregator().aggregate(
                Collections.singletonList(build), Collections.singletonList(safe));

        assertFalse(report.getFingerprint().hasInconsistency());
        assertEquals(RiskLevel.SAFE, report.getOverallRiskLevel());
    }

    @Test
    public void reportFreezesFingerprintAndCollectorResults() {
        CollectorResult value = new CollectorResult("field");
        value.addValue("source", "value");
        DeviceFingerprint fingerprint = new DeviceFingerprint();
        fingerprint.addResult(value);
        new RiskReport(fingerprint, List.of());

        assertThrows(IllegalStateException.class,
                () -> value.addValue("other", "changed"));
        assertThrows(IllegalStateException.class,
                () -> fingerprint.addResult(new CollectorResult("other")));
    }

    @Test
    public void blankValuesDoNotPretendCollectionSucceeded() {
        CollectorResult result = new CollectorResult("empty");
        result.addValue("source", "  ");
        result.finish();

        assertEquals(CollectorResult.Status.EMPTY, result.getStatus());
        assertTrue(result.getValues().isEmpty());
    }

    @Test
    public void addingDataAfterFinishRestoresSuccessStatus() {
        CollectorResult result = new CollectorResult("late");
        result.finish();
        result.addValue("source", "value");

        assertEquals(CollectorResult.Status.SUCCESS, result.getStatus());
    }
}
