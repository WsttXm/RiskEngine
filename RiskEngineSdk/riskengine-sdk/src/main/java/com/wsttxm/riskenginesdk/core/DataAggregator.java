package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;

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
            String evidence = "inconsistent_fields:" + String.join(",", inconsistent);
            allDetections.add(new DetectionResult(
                    "multi_source_validation",
                    RiskLevel.HIGH,
                    evidence
            ));
            CLog.w("Multi-source validation detected inconsistency: " + evidence);
        }

        return new RiskReport(fingerprint, allDetections);
    }
}
