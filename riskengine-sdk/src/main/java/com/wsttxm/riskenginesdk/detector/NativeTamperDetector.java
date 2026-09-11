package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.List;

public class NativeTamperDetector extends BaseDetector {
    private final SignalSnapshot signals;
    private final CollectScene scene;

    public NativeTamperDetector(Context context, SignalSnapshot signals) {
        this(context, signals, CollectScene.STANDARD);
    }

    public NativeTamperDetector(Context context, SignalSnapshot signals, CollectScene scene) {
        super(context);
        this.signals = signals;
        this.scene = scene == null ? CollectScene.STANDARD : scene;
    }

    @Override
    public String getName() {
        return "native_tamper";
    }

    @Override
    protected DetectionResult detect() {
        CheckCoverage coverage = new CheckCoverage();
        SignalResult<String> result = signals.getSoIntegrity();
        if (!result.isSuccess()) {
            coverage.failure("so_integrity:" + result.getFailureReason());
            return unavailable(result.getFailureReason() == null
                    ? "so_integrity_unavailable" : result.getFailureReason());
        }
        coverage.success();
        String value = result.getValue() == null ? "" : result.getValue().trim();
        if (value.isEmpty()) {
            return safe(coverage);
        }
        List<String> details = new ArrayList<>();
        boolean actionable = false;
        for (String token : value.split(",")) {
            if (token.isBlank()) continue;
            String item = token.trim();
            details.add(item);
            if (item.equals("text_mismatch") || item.startsWith("text_mismatch:anonymous")) {
                actionable = true;
            }
        }
        if (!actionable) {
            // "Our library vanished from the map" is a coverage gap in a
            // diagnostic context, but in a login or payment flow it is the
            // expected shape of an attack: hide the checker, then report clean.
            // Escalate there rather than letting it read as merely unavailable.
            boolean sensitiveScene = scene == CollectScene.LOGIN
                    || scene == CollectScene.PAYMENT;
            boolean missingOrUnreadable = false;
            for (String item : details) {
                if (item.startsWith("text_mismatch:missing_map")
                        || item.startsWith("text_mismatch:file_unreadable")
                        || item.startsWith("text_mismatch:unreadable_segments")) {
                    missingOrUnreadable = true;
                    break;
                }
            }
            if (sensitiveScene && missingOrUnreadable) {
                return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                        details, String.join("; ", details), coverage);
            }
            return unavailable(String.join(",", details));
        }
        return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                details, String.join("; ", details), coverage);
    }
}
