package com.wsttxm.riskenginesdk.util;

import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Map;

/** Self-contained JSON serialization that adds no runtime dependency to the AAR. */
public final class RiskReportJsonSerializer {
    private RiskReportJsonSerializer() {}

    public static String serialize(RiskReport report) {
        try {
            JSONObject root = new JSONObject();
            root.put("timestampMs", report.getTimestampMs());
            root.put("sdkVersion", report.getSdkVersion());
            root.put("riskScore", report.getRiskScore());
            root.put("maxRiskScore", report.getMaxRiskScore());
            root.put("displayThresholdMaximum", report.getDisplayThresholdMaximum());
            root.put("warningCount", report.getWarningCount());
            root.put("dangerCount", report.getDangerCount());
            root.put("unknownCount", report.getUnknownCount());
            root.put("availableDetectionCount", report.getAvailableDetectionCount());
            root.put("detectionCount", report.getDetectionCount());
            root.put("checkCount", report.getCheckCount());
            root.put("completedCheckCount", report.getCompletedCheckCount());
            root.put("incompleteCheckCount", report.getIncompleteCheckCount());
            root.put("coveragePercent", report.getCoveragePercent());
            root.put("reportStatus", report.getReportStatus().name());
            root.put("overallRiskLevel", report.getOverallRiskLevel().name());
            root.put("collectScene", report.getCollectScene().name());

            JSONObject fingerprint = new JSONObject();
            for (Map.Entry<String, CollectorResult> entry
                    : report.getFingerprint().getResults().entrySet()) {
                fingerprint.put(entry.getKey(), collectorToJson(entry.getValue()));
            }
            root.put("fingerprint", fingerprint);

            JSONArray detections = new JSONArray();
            for (DetectionResult detection : report.getDetections()) {
                detections.put(detectionToJson(detection));
            }
            root.put("detections", detections);
            return root.toString();
        } catch (JSONException e) {
            throw new IllegalStateException("Unable to serialize risk report", e);
        }
    }

    private static JSONObject collectorToJson(CollectorResult result) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("fieldName", result.getFieldName());
        json.put("status", result.getStatus().name());
        json.put("compareSources", result.isCompareSources());
        json.put("consistent", result.isConsistent());
        json.put("timestampMs", result.getTimestampMs());
        if (result.getCanonicalValue() != null) {
            json.put("canonicalValue", result.getCanonicalValue());
        }
        if (result.getError() != null) {
            json.put("error", result.getError());
        }
        JSONObject values = new JSONObject();
        for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
            values.put(entry.getKey(), entry.getValue());
        }
        json.put("values", values);
        return json;
    }

    private static JSONObject detectionToJson(DetectionResult result) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("detectorName", result.getDetectorName());
        json.put("riskLevel", result.getRiskLevel().name());
        json.put("status", result.getStatus().name());
        json.put("executionStatus", result.getExecutionStatus().name());
        json.put("score", result.getScore());
        json.put("maxScore", result.getMaxScore());
        json.put("informational", result.isInformational());
        json.put("checksAttempted", result.getChecksAttempted());
        json.put("checksSucceeded", result.getChecksSucceeded());
        json.put("checksFailed", result.getChecksFailed());
        json.put("failureReasons", new JSONArray(result.getFailureReasons()));
        json.put("details", new JSONArray(result.getDetails()));
        json.put("evidence", result.getEvidence());
        json.put("timestampMs", result.getTimestampMs());
        return json;
    }
}
