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
    private final String ephemeralSalt;

    public DataAggregator() {
        this(null);
    }

    /**
     * @param fingerprintStore local salt and continuity store. When null the
     *                         fingerprint ID is still computed using an
     *                         ephemeral per-instance salt without continuity.
     */
    public DataAggregator(FingerprintStore fingerprintStore) {
        this.fingerprintStore = fingerprintStore;
        this.ephemeralSalt = fingerprintStore == null
                ? FingerprintStore.generateRandomHex(16)
                : null;
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

        FingerprintId fingerprintId = buildFingerprintId(fingerprint, allDetections);
        addSyntheticFingerprintSignals(fingerprint, allDetections);
        return new RiskReport(fingerprint, allDetections, scene, fingerprintId);
    }

    /**
     * Composes the layered fingerprint ID and records continuity.
     *
     * Runs before synthetic runtime_integrity_score_inputs so any
     * fingerprint_continuity finding is reflected in the score summary.
     */
    private FingerprintId buildFingerprintId(DeviceFingerprint fingerprint,
                                             List<DetectionResult> detections) {
        try {
            String salt = fingerprintStore == null
                    ? ephemeralSalt : fingerprintStore.getOrCreateSalt();
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
                if (!continuity.getChangedBuckets().isEmpty()) {
                    idResult.addValue("changed_buckets",
                            String.join(",", continuity.getChangedBuckets()));
                }
                if (continuity.getState() == FingerprintStore.State.HARDWARE_CHANGED) {
                    List<String> details = new ArrayList<>();
                    details.add("hardware_layer_changed_between_observations");
                    if (!continuity.getChangedBuckets().isEmpty()) {
                        details.add("changed_buckets:"
                                + String.join(",", continuity.getChangedBuckets()));
                    }
                    detections.add(new DetectionResult(
                            "fingerprint_continuity",
                            RiskLevel.MEDIUM,
                            DetectionStatus.WARNING,
                            4, 10, false,
                            details, String.join("; ", details)));
                    CLog.w("Fingerprint hardware layer changed between observations: "
                            + String.join(",", continuity.getChangedBuckets()));
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
