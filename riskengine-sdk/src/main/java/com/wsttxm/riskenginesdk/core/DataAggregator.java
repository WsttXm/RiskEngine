package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class DataAggregator {

    public RiskReport aggregate(List<CollectorResult> collectorResults,
                                List<DetectionResult> detectionResults) {
        return aggregate(collectorResults, detectionResults, CollectScene.STANDARD);
    }

    private final FingerprintStore fingerprintStore;

    public DataAggregator() {
        this(null);
    }

    /**
     * @param fingerprintStore local salt and continuity store. When null the
     *                         fingerprint ID is still computed but with a
     *                         non-persistent salt and no continuity reporting.
     */
    public DataAggregator(FingerprintStore fingerprintStore) {
        this.fingerprintStore = fingerprintStore;
    }

    public RiskReport aggregate(List<CollectorResult> collectorResults,
                                List<DetectionResult> detectionResults,
                                CollectScene scene) {
        Objects.requireNonNull(collectorResults, "collectorResults must not be null");
        Objects.requireNonNull(detectionResults, "detectionResults must not be null");
        DeviceFingerprint fingerprint = new DeviceFingerprint();

        for (CollectorResult cr : collectorResults) {
            fingerprint.addResult(cr);
        }

        List<DetectionResult> allDetections = CorrelationEngine.applyScene(
                CorrelationEngine.dedupeFamilies(detectionResults), scene);
        DetectionResult correlated = CorrelationEngine.correlate(allDetections, scene);
        if (correlated != null) {
            allDetections.add(correlated);
        }
        addCollectionCoverageSignal(collectorResults, allDetections);
        if (fingerprint.hasInconsistency()) {
            List<String> inconsistent = fingerprint.getInconsistentFields();
            List<String> details = List.of("inconsistent_fields:" + String.join(",", inconsistent));
            String evidence = details.get(0);
            allDetections.add(new DetectionResult(
                    "multi_source_validation",
                    RiskLevel.MEDIUM,
                    DetectionStatus.WARNING,
                    4,
                    10,
                    false,
                    details,
                    evidence
            ));
            CLog.w("Multi-source validation detected inconsistency: " + evidence);
        }

        addSyntheticFingerprintSignals(fingerprint, allDetections);
        FingerprintId fingerprintId = buildFingerprintId(fingerprint, allDetections);
        return new RiskReport(fingerprint, allDetections, scene, fingerprintId);
    }

    /**
     * Composes the layered fingerprint ID and records continuity.
     *
     * A hardware layer that changed between runs is surfaced as a detection,
     * because on a device whose hardware genuinely cannot change it indicates
     * spoofed values. A degraded collection is reported as coverage loss rather
     * than a mismatch, so a missing GPU read is never mistaken for tampering.
     */
    private FingerprintId buildFingerprintId(DeviceFingerprint fingerprint,
                                             List<DetectionResult> detections) {
        try {
            String salt = fingerprintStore == null
                    ? "riskengine" : fingerprintStore.getOrCreateSalt();
            FingerprintId id = FingerprintIdBuilder.build(fingerprint, salt);

            CollectorResult idResult = new CollectorResult("fingerprint_id");
            if (!id.getCompositeId().isEmpty()) {
                idResult.addValue("composite", id.getCompositeId());
            }
            if (!id.getHardwareId().isEmpty()) {
                idResult.addValue("hardware", id.getHardwareId());
            }
            if (!id.getSystemId().isEmpty()) {
                idResult.addValue("system", id.getSystemId());
            }
            if (!id.getVolatileId().isEmpty()) {
                idResult.addValue("volatile", id.getVolatileId());
            }
            idResult.addValue("hardware_coverage",
                    id.getHardwareFieldsPresent() + "/" + id.getHardwareFieldsTotal());
            idResult.addValue("system_coverage",
                    id.getSystemFieldsPresent() + "/" + id.getSystemFieldsTotal());
            idResult.addValue("hardware_layer_reliable",
                    String.valueOf(id.isHardwareLayerReliable()));

            if (fingerprintStore != null) {
                FingerprintStore.Continuity continuity =
                        fingerprintStore.recordAndCompare(id);
                idResult.addValue("continuity", continuity.getState().name());
                idResult.addValue("observation_count",
                        String.valueOf(continuity.getObservationCount()));
                if (continuity.getState() == FingerprintStore.State.HARDWARE_CHANGED) {
                    List<String> details =
                            List.of("hardware_layer_changed_between_observations");
                    detections.add(new DetectionResult(
                            "fingerprint_continuity",
                            RiskLevel.MEDIUM,
                            DetectionStatus.WARNING,
                            4, 10, false,
                            details, details.get(0)));
                    CLog.w("Fingerprint hardware layer changed between observations");
                }
            }
            fingerprint.addResult(idResult);
            return id;
        } catch (Exception e) {
            CLog.e("Fingerprint ID composition failed", e);
            return null;
        }
    }

    private void addCollectionCoverageSignal(List<CollectorResult> collectorResults,
                                             List<DetectionResult> detections) {
        for (CollectorResult result : collectorResults) {
            if (result.getStatus() != CollectorResult.Status.SUCCESS) {
                detections.add(DetectionResult.unavailable(
                        "collector:" + result.getFieldName(),
                        result.getStatus() + (result.getError() == null
                                ? "" : ":" + result.getError())));
            }
        }
    }

    private void addSyntheticFingerprintSignals(DeviceFingerprint fingerprint,
                                                List<DetectionResult> detections) {
        CollectorResult hookSignals = buildHookMemorySignals(detections);
        if (hookSignals != null) {
            fingerprint.addResult(hookSignals);
        }

        CollectorResult runtimeInputs = buildRuntimeIntegrityInputs(detections);
        if (runtimeInputs != null) {
            fingerprint.addResult(runtimeInputs);
        }
    }

    private CollectorResult buildHookMemorySignals(List<DetectionResult> detections) {
        for (DetectionResult detection : detections) {
            if (!"hook_framework".equals(detection.getDetectorName())) {
                continue;
            }
            List<String> details = detection.getDetails().stream()
                    .filter(detail -> detail.startsWith("anon_exec:")
                            || detail.startsWith("maps:")
                            || detail.startsWith("frida_pid_port:"))
                    .collect(Collectors.toList());
            if (details.isEmpty()) {
                return null;
            }

            CollectorResult result = new CollectorResult("hook_memory_signals");
            result.addValue("summary", "present");
            result.addValue("signals", String.join(",", details));
            result.addValue("count", String.valueOf(details.size()));
            return result;
        }
        return null;
    }

    private CollectorResult buildRuntimeIntegrityInputs(List<DetectionResult> detections) {
        if (detections.isEmpty()) {
            return null;
        }

        CollectorResult result = new CollectorResult("runtime_integrity_score_inputs");
        int dangerCount = 0;
        int warningCount = 0;
        long score = 0;
        List<String> statusMap = new ArrayList<>();
        for (DetectionResult detection : detections) {
            if (detection.getStatus() == DetectionStatus.DANGER) {
                dangerCount++;
            } else if (detection.getStatus() == DetectionStatus.WARNING) {
                warningCount++;
            }
            if (!detection.isInformational()) {
                score += detection.getScore();
            }
            statusMap.add(detection.getDetectorName() + ":" + detection.getStatus());
        }

        result.addValue("summary", "score=" + score + ",danger=" + dangerCount + ",warning=" + warningCount);
        result.addValue("detectors", String.join(",", statusMap));
        return result;
    }
}
