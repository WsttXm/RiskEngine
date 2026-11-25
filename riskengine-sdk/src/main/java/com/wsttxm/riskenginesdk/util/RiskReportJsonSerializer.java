package com.wsttxm.riskenginesdk.util;

import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskDimension;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.ScoreBreakdown;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Self-contained JSON serialization that adds no runtime dependency to the AAR. */
public final class RiskReportJsonSerializer {
    private RiskReportJsonSerializer() {}

    public static String serialize(RiskReport report) {
        return serialize(report, null);
    }

    /**
     * Serializes a {@link RiskReport} to JSON v2, optionally appending the additive
     * {@code signedEnvelope} object when {@code envelope} is non-null.
     */
    public static String serialize(RiskReport report, SignedRiskEnvelope envelope) {
        return toJsonObject(report, envelope).toString();
    }

    /**
     * Builds the structured JSON v2 {@link JSONObject} for {@code report}, optionally appending
     * {@code signedEnvelope}. Used both by {@link #serialize} and canonical report hashing.
     */
    public static JSONObject toJsonObject(RiskReport report, SignedRiskEnvelope envelope) {
        try {
            JSONObject root = new JSONObject();
            root.put("schemaVersion", 2);
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
            root.put("unsupportedCheckCount", report.getUnsupportedCheckCount());
            root.put("incompleteCheckCount", report.getIncompleteCheckCount());
            root.put("coveragePercent", report.getCoveragePercent());
            root.put("confidencePercent", report.getConfidencePercent());
            root.put("reportStatus", report.getReportStatus().name());
            root.put("overallRiskLevel", report.getOverallRiskLevel().name());
            root.put("recommendedAction", report.getRecommendedAction().name());
            root.put("hardTriggers", new JSONArray(report.getHardTriggers()));
            root.put("dimensionScores", dimensionScoresToJson(report));
            root.put("scoreBreakdown", scoreBreakdownToJson(report.getScoreBreakdown()));
            root.put("trustTier", report.getTrustTier().name());
            root.put("collectScene", report.getCollectScene().name());
            root.put("devicePosture", devicePostureToJson(report.getDevicePosture()));

            JSONObject fingerprint = new JSONObject();
            for (Map.Entry<String, CollectorResult> entry
                    : report.getFingerprint().getResults().entrySet()) {
                fingerprint.put(entry.getKey(), collectorToJson(entry.getValue()));
            }
            root.put("fingerprint", fingerprint);

            FingerprintId fpId = report.getFingerprintId();
            if (fpId != null) {
                root.put("fingerprintId", fingerprintIdToJson(fpId, report.getAnchorDriftCount()));
            }

            JSONArray detections = new JSONArray();
            for (DetectionResult detection : report.getDetections()) {
                detections.put(detectionToJson(detection));
            }
            root.put("detections", detections);

            if (envelope != null) {
                root.put("signedEnvelope", signedEnvelopeToJson(envelope));
            }
            return root;
        } catch (JSONException e) {
            throw new IllegalStateException("Unable to serialize risk report", e);
        }
    }

    private static JSONObject dimensionScoresToJson(RiskReport report) throws JSONException {
        JSONObject json = new JSONObject();
        for (RiskDimension dim : RiskDimension.values()) {
            json.put(dim.name(), report.getDimensionScore(dim));
        }
        return json;
    }

    private static JSONArray scoreBreakdownToJson(ScoreBreakdown breakdown) throws JSONException {
        JSONArray array = new JSONArray();
        if (breakdown == null) {
            return array;
        }
        for (ScoreBreakdown.Entry entry : breakdown.getEntries()) {
            JSONObject obj = new JSONObject();
            obj.put("category", entry.getCategory().name());
            obj.put("key", entry.getKey());
            if (entry.getDimension() != null) {
                obj.put("dimension", entry.getDimension().name());
            }
            obj.put("points", entry.getPoints());
            obj.put("source", entry.getSource());
            array.put(obj);
        }
        return array;
    }

    private static JSONObject signedEnvelopeToJson(SignedRiskEnvelope envelope)
            throws JSONException {
        JSONObject json = new JSONObject();
        json.put("payload", new JSONObject(envelope.getCanonicalPayloadJson()));
        json.put("signatureBase64", envelope.getSignatureBase64());
        json.put("certChainPem", new JSONArray(envelope.getCertChainPem()));
        json.put("attestationMode", envelope.getAttestationMode().name());
        json.put("keySecurityLevel", envelope.getKeySecurityLevel().name());
        return json;
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

    private static JSONObject devicePostureToJson(DevicePosture posture) throws JSONException {
        DevicePosture effective = posture == null ? DevicePosture.empty() : posture;
        JSONObject json = new JSONObject();
        json.put("hasPasscode", effective.getDeviceSecure() != null
                ? effective.getDeviceSecure() : JSONObject.NULL);
        json.put("storageEncrypted", effective.isStorageEncrypted());
        json.put("storageEncryptionStatus", effective.getStorageEncryptionStatus().name());
        json.put("keystoreLevel", effective.getKeystoreSecurityLevel().name());
        json.put("biometricStatus", effective.getBiometricStatus().name());
        json.put("devMode", effective.getDeveloperOptionsEnabled() != null
                ? effective.getDeveloperOptionsEnabled() : JSONObject.NULL);
        json.put("adbEnabled", effective.getAdbEnabled() != null
                ? effective.getAdbEnabled() : JSONObject.NULL);
        json.put("systemVpn", effective.getSystemVpn() != null
                ? effective.getSystemVpn() : JSONObject.NULL);
        json.put("unofficialStore", effective.getUnofficialStore() != null
                ? effective.getUnofficialStore() : JSONObject.NULL);
        json.put("lockscreenOrBiometricReset", effective.isLockscreenOrBiometricReset());
        return json;
    }

    private static JSONObject fingerprintIdToJson(FingerprintId fpId, int anchorDriftCount)
            throws JSONException {
        JSONObject json = new JSONObject();
        json.put("version", fpId.getVersion().name());
        json.put("stability", fpId.getStability().name());
        json.put("anchorDriftCount", Math.max(0, anchorDriftCount));
        json.put("compositeId", fpId.getCompositeId());
        json.put("hardwareId", fpId.getHardwareId());
        json.put("systemId", fpId.getSystemId());
        json.put("volatileId", fpId.getVolatileId());
        json.put("hardwareFieldsPresent", fpId.getHardwareFieldsPresent());
        json.put("hardwareFieldsTotal", fpId.getHardwareFieldsTotal());
        json.put("hardwareCoveragePercent", fpId.getHardwareCoveragePercent());
        json.put("hardwareLayerReliable", fpId.isHardwareLayerReliable());
        json.put("systemFieldsPresent", fpId.getSystemFieldsPresent());
        json.put("systemFieldsTotal", fpId.getSystemFieldsTotal());
        json.put("contributingFields", new JSONArray(fpId.getContributingFields()));
        JSONObject buckets = new JSONObject();
        for (Map.Entry<String, String> entry : fpId.getHardwareBucketDigests().entrySet()) {
            buckets.put(entry.getKey(), entry.getValue());
        }
        json.put("hardwareBucketDigests", buckets);
        return json;
    }

    private static JSONObject detectionToJson(DetectionResult result) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("detectorName", result.getDetectorName());
        json.put("scanTier", result.getScanTier().name());
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
        json.put("evidenceFamilies", new JSONArray(collectEvidenceFamilies(result)));
        JSONArray items = new JSONArray();
        for (EvidenceItem item : result.getEvidenceItems()) {
            items.put(evidenceItemToJson(item));
        }
        json.put("evidenceItems", items);
        json.put("timestampMs", result.getTimestampMs());
        return json;
    }

    private static Set<String> collectEvidenceFamilies(DetectionResult result) {
        Set<String> families = new LinkedHashSet<>(EvidenceFamily.families(result.getDetails()));
        for (EvidenceItem item : result.getEvidenceItems()) {
            if (item.getEvidenceFamily() != null && !item.getEvidenceFamily().isBlank()) {
                families.add(item.getEvidenceFamily());
            }
        }
        return families;
    }

    private static JSONObject evidenceItemToJson(EvidenceItem item) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("code", item.getCode());
        json.put("primarySource", item.getPrimarySource().name());
        JSONArray merged = new JSONArray();
        for (EvidenceItem.SourceLayer layer : item.getMergedSources()) {
            merged.put(layer.name());
        }
        json.put("mergedSources", merged);
        json.put("location", item.getLocation());
        json.put("value", item.getValue());
        if (item.getEvidenceFamily() != null) {
            json.put("family", item.getEvidenceFamily());
        }
        json.put("rank", item.getRank().name());
        return json;
    }
}
