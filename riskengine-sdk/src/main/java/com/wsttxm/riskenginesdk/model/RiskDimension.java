package com.wsttxm.riskenginesdk.model;

/**
 * Orthogonal risk dimensions along which device security and fraud evidence is scored.
 */
public enum RiskDimension {
    /** Active runtime code injection, hooking, debugging, app integrity, or TEE tampering. */
    TAMPERING,
    /** Root frameworks, boot integrity, property/hardware spoofing, hiding tools, custom ROM, or ADB. */
    PRIVILEGE,
    /** Emulators, cloud phones, virtual containers, or known threat applications. */
    ENVIRONMENT,
    /** Network MITM proxies, location spoofing, remote screen control, or call-fraud context. */
    FRAUD_CONTEXT
}
