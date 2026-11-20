package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.json.JSONObject;
import org.junit.Test;

import java.util.List;
import java.util.Map;

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

    @Test
    public void topLevelFingerprintIdIsSerializedWhenPresent() throws Exception {
        FingerprintId fpId = new FingerprintId(
                "comp123", "hw123", "sys123", "vol123",
                9, 13, 6, 11,
                List.of("gpu_info.vendor", "gpu_info.renderer"),
                Map.of("gpu", "abcdef0123456789"));
        RiskReport report = new RiskReport(new DeviceFingerprint(), List.of(),
                CollectScene.STANDARD, fpId);

        JSONObject json = new JSONObject(RiskEngine.reportToJson(report));
        assertTrue(json.has("fingerprintId"));
        JSONObject fpJson = json.getJSONObject("fingerprintId");
        assertEquals("comp123", fpJson.getString("compositeId"));
        assertEquals("hw123", fpJson.getString("hardwareId"));
        assertTrue(fpJson.getBoolean("hardwareLayerReliable"));
        assertEquals("abcdef0123456789",
                fpJson.getJSONObject("hardwareBucketDigests").getString("gpu"));
    }
}
