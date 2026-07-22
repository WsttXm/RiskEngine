package com.wsttxm.riskenginesdk;

/** Controls optional identifier collection while leaving risk detection enabled. */
public enum PrivacyProfile {
    /** No persistent or resettable identifiers are collected. */
    MINIMAL,
    /** App-scoped Android ID hash only; the default for normal integrations. */
    BALANCED,
    /** Adds boot and Widevine hashes for opt-in troubleshooting. */
    DIAGNOSTIC
}
