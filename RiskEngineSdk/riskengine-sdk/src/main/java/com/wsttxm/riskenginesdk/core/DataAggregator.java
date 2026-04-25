package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class DataAggregator {

    public RiskReport aggregate(List<CollectorResult> collectorResults,
                                List<DetectionResult> detectionResults) {
        DeviceFingerprint fingerprint = new DeviceFingerprint();

        for (CollectorResult cr : collectorResults) {
            fingerprint.addResult(cr);
        }

        // Add inconsistency detections
        List<DetectionResult> allDetections = new ArrayList<>(detectionResults);
        if (fingerprint.hasInconsistency()) {
            List<String> inconsistent = fingerprint.getInconsistentFields();
            List<String> details = List.of("inconsistent_fields:" + String.join(",", inconsistent));
            String evidence = details.get(0);
            allDetections.add(new DetectionResult(
                    "multi_source_validation",
                    RiskLevel.HIGH,
                    DetectionStatus.DANGER,
                    6,
                    10,
                    false,
                    details,
                    evidence
            ));
            CLog.w("Multi-source validation detected inconsistency: " + evidence);
        }

        addSyntheticFingerprintSignals(fingerprint, allDetections);
        return new RiskReport(fingerprint, allDetections);
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
                            || detail.startsWith("trampoline:")
                            || detail.startsWith("maps:")
                            || detail.startsWith("dbus_reject:"))
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
        int score = 0;
        List<String> statusMap = new ArrayList<>();
        for (DetectionResult detection : detections) {
            if (detection.getStatus() == DetectionStatus.DANGER) {
                dangerCount++;
            } else if (detection.getStatus() == DetectionStatus.WARNING) {
                warningCount++;
            }
            if (!detection.isWarnOnly()) {
                score += detection.getScore();
            }
            statusMap.add(detection.getDetectorName() + ":" + detection.getStatus());
        }

        result.addValue("summary", "score=" + score + ",danger=" + dangerCount + ",warning=" + warningCount);
        result.addValue("detectors", String.join(",", statusMap));
        return result;
    }
}
