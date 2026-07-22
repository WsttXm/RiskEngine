package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.json.JSONObject;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RiskReportJsonSerializerTest {
    @Test
    public void existingReportCanBeSerializedWithoutCollectingAgain() throws Exception {
        RiskReport report = new RiskReport(new DeviceFingerprint(),
                List.of(DetectionResult.timeout("slow", "deadline")));

        JSONObject json = new JSONObject(RiskEngine.reportToJson(report));

        assertEquals("UNKNOWN", json.getString("overallRiskLevel"));
        assertEquals("UNAVAILABLE", json.getString("reportStatus"));
        assertEquals("TIMEOUT", json.getJSONArray("detections")
                .getJSONObject(0).getString("executionStatus"));
        assertTrue(json.has("coveragePercent"));
    }
}
