package com.wsttxm.riskenginesdk;

/**
 * Explicit version contract for device fingerprint generation.
 *
 * <p>Host applications should pin a concrete version ({@link #V1} or {@link #V2}) to prevent
 * unexpected fingerprint drift across SDK upgrades.
 */
public enum FingerprintVersion {
    /**
     * Bit-exact v1.x algorithm (13 hardware fields, 11 system fields, 3 volatile fields).
     * Pin this version when migrating existing v1.x installs that require unchanged IDs.
     */
    V1(1),

    /**
     * v2 algorithm adding stability-scoped composition, volatile-stripped CPU info normalization,
     * and Phase 1 zero-permission high-entropy collectors.
     */
    V2(2),

    /**
     * Alias for the newest schema version.
     *
     * @deprecated Explicitly pin {@link #V1} or {@link #V2} to prevent silent fingerprint drift
     *     when upgrading the SDK.
     */
    @Deprecated
    LATEST(2);

    private final int code;

    FingerprintVersion(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    /** Resolves {@link #LATEST} to the concrete current version ({@link #V2}). */
    public FingerprintVersion resolve() {
        return this == LATEST ? V2 : this;
    }
}
