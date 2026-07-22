package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.RiskReport;

public interface RiskEngineCallback {
    /** Invoked on a RiskEngine coordinator thread, never implicitly on the main thread. */
    void onSuccess(RiskReport report);
    /** Invoked on the calling or coordinator thread depending on where the failure occurs. */
    void onError(Throwable error);
}
