package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.TierReport;

/**
 * Push-mode tiered readiness listener delivering progressively richer results in strict
 * {@code CRITICAL -> FAST -> POSTPONED} order.
 */
public interface ExecutionStateListener {

    /** Invoked immediately after CRITICAL-tier detectors complete. */
    default void onCriticalChecksFinished(TierReport criticalReport) {}

    /** Invoked after FAST-tier detectors complete. */
    default void onFastChecksFinished(TierReport fastReport) {}

    /** Invoked after collectors, POSTPONED checks, and full aggregation complete. */
    default void onPostponedChecksFinished(RiskReport fullReport) {}
}
