package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.RiskReport;

public interface RiskEngineCallback {
    void onSuccess(RiskReport report);
    void onError(Throwable error);
}
