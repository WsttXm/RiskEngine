package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.List;

public class NativeTamperDetector extends BaseDetector {
    private final SignalSnapshot signals;

    public NativeTamperDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
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
            return unavailable(String.join(",", details));
        }
        return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                details, String.join("; ", details), coverage);
    }
}
