package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RiskReportJsonSerializerTest {
    @Test
    public void existingReportCanBeSerializedWithoutCollectingAgain() throws Exception {
        RiskReport report = new RiskReport(new DeviceFingerprint(),
                List.of(DetectionResult.timeout("slow", "deadline")));

        JSONObject json = new JSONObject(RiskEngine.reportToJson(report));

        assertEquals("UNKNOWN", json.getString("overallRiskLevel"));
        assertEquals("REVIEW", json.getString("recommendedAction"));
        assertEquals(0, json.getInt("confidencePercent"));
        assertEquals(100, json.getInt("maxRiskScore"));
        assertEquals(100, json.getInt("displayThresholdMaximum"));
        assertEquals(0, json.getJSONArray("hardTriggers").length());
        assertEquals(0, json.getJSONArray("scoreBreakdown").length());
        JSONObject dims = json.getJSONObject("dimensionScores");
        assertEquals(4, dims.length());
        assertEquals(0, dims.getInt("TAMPERING"));
        assertEquals(0, dims.getInt("PRIVILEGE"));
        assertEquals(0, dims.getInt("ENVIRONMENT"));
        assertEquals(0, dims.getInt("FRAUD_CONTEXT"));
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
                Map.of("gpu", "abcdef0123456789", "cpu", "0123456789abcdef"));
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

    @Test
    public void additiveJsonV2FieldsAreEmittedWithoutBreakingV1Schema() throws Exception {
        CollectorResult unsupported = new CollectorResult("cellular_info");
        unsupported.markUnsupported("no_telephony_feature");
        CollectorResult ok = new CollectorResult("device_info");
        ok.addValue("model", "Pixel");

        EvidenceItem javaItem = new EvidenceItem(
                "frida_maps",
                EvidenceItem.SourceLayer.JAVA,
                "/data/local/tmp/frida.so",
                "maps_match",
                "frida",
                EvidenceItem.Rank.MEDIUM);
        EvidenceItem nativeItem = new EvidenceItem(
                "frida_maps",
                EvidenceItem.SourceLayer.NATIVE,
                "/data/local/tmp/frida.so",
                "native_maps_match",
                "frida",
                EvidenceItem.Rank.STRONG);

        DetectionResult hookResult = new DetectionResult(
                "hook_framework",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                9,
                10,
                false,
                DetectionExecutionStatus.RISK,
                2,
                2,
                0,
                Collections.emptyList(),
                List.of("maps:frida"),
                Arrays.asList(javaItem, nativeItem),
                "maps:frida");

        RiskReport report = new DataAggregator().aggregate(
                Arrays.asList(unsupported, ok), Collections.singletonList(hookResult));
        JSONObject json = new JSONObject(RiskEngine.reportToJson(report));

        // Additive v2 root fields
        assertEquals(2, json.getInt("schemaVersion"));
        assertEquals(1, json.getInt("unsupportedCheckCount"));
        assertEquals(100, json.getInt("maxRiskScore"));
        assertEquals(100, json.getInt("displayThresholdMaximum"));
        assertEquals(report.getRiskScore(), json.getInt("riskScore"));
        assertTrue("Hard trigger must floor normalized score >= 95", json.getInt("riskScore") >= 95);
        assertEquals("BLOCK", json.getString("recommendedAction"));
        assertEquals(100, json.getInt("confidencePercent"));

        JSONArray hardTriggers = json.getJSONArray("hardTriggers");
        assertEquals(1, hardTriggers.length());
        assertEquals("maps:frida", hardTriggers.getString(0));

        JSONObject dimensions = json.getJSONObject("dimensionScores");
        assertEquals(4, dimensions.length());
        assertTrue(dimensions.getInt("TAMPERING") >= 75);
        assertEquals(0, dimensions.getInt("PRIVILEGE"));
        assertEquals(0, dimensions.getInt("ENVIRONMENT"));
        assertEquals(0, dimensions.getInt("FRAUD_CONTEXT"));

        JSONArray breakdown = json.getJSONArray("scoreBreakdown");
        assertTrue("Expected FAMILY, CORROBORATION_LIFT, and HARD_TRIGGER_FLOOR entries",
                breakdown.length() >= 3);
        boolean sawFamily = false;
        boolean sawLift = false;
        boolean sawHardTriggerFloor = false;
        for (int i = 0; i < breakdown.length(); i++) {
            JSONObject entry = breakdown.getJSONObject(i);
            String category = entry.getString("category");
            if ("FAMILY".equals(category) && "frida".equals(entry.getString("key"))) {
                sawFamily = true;
                assertEquals("TAMPERING", entry.getString("dimension"));
                assertEquals("hook_framework", entry.getString("source"));
                assertTrue(entry.getInt("points") > 0);
            } else if ("CORROBORATION_LIFT".equals(category) && "frida".equals(entry.getString("key"))) {
                sawLift = true;
                assertEquals("TAMPERING", entry.getString("dimension"));
                assertTrue(entry.getString("source").contains("JAVA"));
                assertTrue(entry.getString("source").contains("NATIVE"));
                assertTrue(entry.getInt("points") > 0);
            } else if ("HARD_TRIGGER_FLOOR".equals(category)) {
                sawHardTriggerFloor = true;
                assertEquals("maps:frida", entry.getString("key"));
                assertFalse("Cross-dimension HARD_TRIGGER_FLOOR omits dimension",
                        entry.has("dimension"));
                assertEquals("hard_trigger", entry.getString("source"));
                assertTrue(entry.getInt("points") > 0);
            }
        }
        assertTrue("Expected FAMILY entry in scoreBreakdown", sawFamily);
        assertTrue("Expected CORROBORATION_LIFT entry in scoreBreakdown", sawLift);
        assertTrue("Expected HARD_TRIGGER_FLOOR entry in scoreBreakdown", sawHardTriggerFloor);

        // Existing v1 root fields remain intact (hook_framework DANGER hard-triggers DEADLY)
        assertEquals("DEADLY", json.getString("overallRiskLevel"));
        assertTrue(json.has("sdkVersion"));
        assertFalse(json.has("details"));

        JSONObject det = json.getJSONArray("detections").getJSONObject(0);
        assertEquals("hook_framework", det.getString("detectorName"));
        assertEquals("maps:frida", det.getJSONArray("details").getString(0));

        // Additive v2 detection fields
        JSONArray families = det.getJSONArray("evidenceFamilies");
        assertEquals(1, families.length());
        assertEquals("frida", families.getString(0));

        JSONArray items = det.getJSONArray("evidenceItems");
        assertEquals(1, items.length());
        JSONObject itemJson = items.getJSONObject(0);
        assertEquals("frida_maps", itemJson.getString("code"));
        assertEquals("NATIVE", itemJson.getString("primarySource"));
        assertEquals("/data/local/tmp/frida.so", itemJson.getString("location"));
        assertEquals("frida", itemJson.getString("family"));
        assertEquals("STRONG", itemJson.getString("rank"));
        JSONArray mergedSources = itemJson.getJSONArray("mergedSources");
        assertEquals(2, mergedSources.length());
        assertEquals("JAVA", mergedSources.getString(0));
        assertEquals("NATIVE", mergedSources.getString(1));
    }
}
