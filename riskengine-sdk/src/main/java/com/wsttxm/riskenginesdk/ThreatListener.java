package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.ThreatEvent;

/**
 * Push-mode threat listener invoked when high-priority threats are detected during
 * tiered scans or asynchronously by the native periodic monitor / screen hooks.
 */
public interface ThreatListener {

    /** Unified entry point for actionable threats across all tiers and runtime events. */
    default void onThreatDetected(ThreatEvent event) {}

    /** Dedicated real-time callback for post-init runtime tamper or screen capture/recording events. */
    default void onRuntimeTamperDetected(ThreatEvent event) {}
}
