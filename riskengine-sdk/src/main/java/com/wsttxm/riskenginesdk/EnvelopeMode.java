package com.wsttxm.riskenginesdk;

/**
 * Attestation and key-lifecycle mode for {@link RiskEngine#collectSignedEnvelopeSync}.
 */
public enum EnvelopeMode {
    /**
     * Signs the canonical envelope payload using a persistent non-exportable hardware ECDSA P-256
     * key ({@code riskengine_envelope_sign_key}, StrongBox &rarr; TEE fallback) and attaches its
     * cached hardware attestation certificate chain. Targets {@code < 10ms} P95 signing latency
     * with zero key generation on the hot path.
     */
    PERSISTENT_KEY,

    /**
     * Generates a fresh one-time hardware ECDSA P-256 keypair binding {@code serverChallenge}
     * directly into X.509 OID {@code 1.3.6.1.4.1.11129.2.1.17} via
     * {@code setAttestationChallenge(serverChallenge)}, signs the canonical payload, and deletes
     * the temporary alias immediately in {@code finally}. Intended for high-value actions such as
     * payment or registration.
     */
    FRESH_ATTESTATION
}
