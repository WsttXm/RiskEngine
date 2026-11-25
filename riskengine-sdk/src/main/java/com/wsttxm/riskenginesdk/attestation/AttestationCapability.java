package com.wsttxm.riskenginesdk.attestation;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Shared Android Hardware Key Attestation capability (StrongBox -> TEE graceful fallback).
 *
 * <p>Generates an ephemeral EC P-256 key with a fresh 32-byte random attestation challenge,
 * extracts and parses the certificate chain (root-first OID {@code .17}, RKP OID {@code .30},
 * Google Root + monotonic offline CRL verification), and ALWAYS deletes the temporary keystore
 * alias in {@code finally}. Intended to be cached once per scan in {@code SignalSnapshot}.</p>
 */
public final class AttestationCapability {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS_PREFIX = "riskengine_ephem_attest_";
    private static final int CHALLENGE_BYTES = 32;

    /** Abstraction over AndroidKeyStore key generation for deterministic pure-JVM unit testing. */
    public interface KeyAttestationBackend {
        List<X509Certificate> generateAttestationChain(
                String alias, byte[] challenge, boolean strongBox) throws Exception;

        void deleteAlias(String alias);
    }

    /** Immutable snapshot produced by a single attestation probe. */
    public static final class AttestationSnapshot {
        private final boolean available;
        private final boolean usedStrongBox;
        private final boolean fallbackFromStrongBox;
        private final AttestationRecord record;
        private final CertificateTrustAnalyzer.TrustResult trust;
        private final RkpExtensionParser.RkpParseResult rkp;
        private final List<X509Certificate> certificateChain;
        private final long generationLatencyMs;
        private final String failureReason;

        private AttestationSnapshot(Builder b) {
            this.available = b.available;
            this.usedStrongBox = b.usedStrongBox;
            this.fallbackFromStrongBox = b.fallbackFromStrongBox;
            this.record = b.record;
            this.trust = b.trust;
            this.rkp = b.rkp;
            this.certificateChain = Collections.unmodifiableList(new ArrayList<>(b.certificateChain));
            this.generationLatencyMs = b.generationLatencyMs;
            this.failureReason = b.failureReason;
        }

        public boolean isAvailable() {
            return available;
        }

        public boolean isUsedStrongBox() {
            return usedStrongBox;
        }

        public boolean isFallbackFromStrongBox() {
            return fallbackFromStrongBox;
        }

        public AttestationRecord getRecord() {
            return record;
        }

        public CertificateTrustAnalyzer.TrustResult getTrust() {
            return trust;
        }

        public RkpExtensionParser.RkpParseResult getRkp() {
            return rkp;
        }

        public List<X509Certificate> getCertificateChain() {
            return certificateChain;
        }

        public long getGenerationLatencyMs() {
            return generationLatencyMs;
        }

        public String getFailureReason() {
            return failureReason;
        }

        /** True when chain is trusted by Google hardware root, unrevoked, valid, locked and VERIFIED. */
        public boolean isHardwareVerifiedLocked() {
            if (!available || record == null || !record.isValid() || !record.isChallengeMatched()) {
                return false;
            }
            if (record.isLeafShadowAttempted()) {
                return false;
            }
            if (trust == null || !trust.isFullyTrustedGoogleHardware()) {
                return false;
            }
            if (rkp != null && rkp.isPresent() && !rkp.isValid()) {
                return false;
            }
            if (!record.getAttestationSecurityLevel().isHardwareBacked()
                    || !record.getKeymasterSecurityLevel().isHardwareBacked()) {
                return false;
            }
            AttestationRecord.RootOfTrust rot = record.getRootOfTrust();
            return rot != null
                    && rot.isHardwareEnforced()
                    && rot.isDeviceLocked()
                    && rot.getVerifiedBootState() == AttestationRecord.VerifiedBootState.VERIFIED;
        }

        public static AttestationSnapshot unavailable(String reason) {
            return new Builder().available(false).failureReason(reason).build();
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private boolean available;
            private boolean usedStrongBox;
            private boolean fallbackFromStrongBox;
            private AttestationRecord record;
            private CertificateTrustAnalyzer.TrustResult trust;
            private RkpExtensionParser.RkpParseResult rkp;
            private List<X509Certificate> certificateChain = Collections.emptyList();
            private long generationLatencyMs;
            private String failureReason;

            public Builder available(boolean v) {
                this.available = v;
                return this;
            }

            public Builder usedStrongBox(boolean v) {
                this.usedStrongBox = v;
                return this;
            }

            public Builder fallbackFromStrongBox(boolean v) {
                this.fallbackFromStrongBox = v;
                return this;
            }

            public Builder record(AttestationRecord v) {
                this.record = v;
                return this;
            }

            public Builder trust(CertificateTrustAnalyzer.TrustResult v) {
                this.trust = v;
                return this;
            }

            public Builder rkp(RkpExtensionParser.RkpParseResult v) {
                this.rkp = v;
                return this;
            }

            public Builder certificateChain(List<X509Certificate> v) {
                this.certificateChain = v == null ? Collections.<X509Certificate>emptyList() : v;
                return this;
            }

            public Builder generationLatencyMs(long v) {
                this.generationLatencyMs = v;
                return this;
            }

            public Builder failureReason(String v) {
                this.failureReason = v;
                return this;
            }

            public AttestationSnapshot build() {
                return new AttestationSnapshot(this);
            }
        }
    }

    private final KeyAttestationBackend backend;
    private final AttestationExtensionParser extensionParser;
    private final CertificateTrustAnalyzer trustAnalyzer;
    private final RkpExtensionParser rkpParser;
    private final SecureRandom secureRandom;

    public AttestationCapability() {
        this(
                new AndroidKeyStoreBackend(),
                new AttestationExtensionParser(),
                new CertificateTrustAnalyzer(GoogleAttestationRootStore.getDefault()),
                new RkpExtensionParser(),
                new SecureRandom());
    }

    public AttestationCapability(
            KeyAttestationBackend backend,
            AttestationExtensionParser extensionParser,
            CertificateTrustAnalyzer trustAnalyzer,
            RkpExtensionParser rkpParser,
            SecureRandom secureRandom) {
        this.backend = backend == null ? new AndroidKeyStoreBackend() : backend;
        this.extensionParser = extensionParser == null ? new AttestationExtensionParser() : extensionParser;
        this.trustAnalyzer = trustAnalyzer == null
                ? new CertificateTrustAnalyzer(GoogleAttestationRootStore.getDefault())
                : trustAnalyzer;
        this.rkpParser = rkpParser == null ? new RkpExtensionParser() : rkpParser;
        this.secureRandom = secureRandom == null ? new SecureRandom() : secureRandom;
    }

    /** Executes StrongBox -> TEE ephemeral attestation and returns an immutable snapshot. */
    public AttestationSnapshot collect() {
        return collect(new Date());
    }

    public AttestationSnapshot collect(Date evaluationTime) {
        byte[] challenge = new byte[CHALLENGE_BYTES];
        try {
            secureRandom.nextBytes(challenge);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return AttestationSnapshot.unavailable("challenge_rng_failed:" + e.getClass().getSimpleName());
        }

        long startNanos = System.nanoTime();
        List<X509Certificate> chain = null;
        boolean usedStrongBox = false;
        boolean fallbackFromStrongBox = false;
        String strongBoxErr = null;

        // 1. Try StrongBox first
        String sbAlias = ALIAS_PREFIX + "sb_" + UUID.randomUUID().toString().replace("-", "");
        try {
            chain = backend.generateAttestationChain(sbAlias, challenge, true);
            if (chain != null && !chain.isEmpty()) {
                usedStrongBox = true;
            } else {
                fallbackFromStrongBox = true;
                strongBoxErr = "empty_strongbox_chain";
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            fallbackFromStrongBox = true;
            strongBoxErr = e.getClass().getSimpleName();
        } finally {
            safeDeleteAlias(sbAlias);
        }

        // 2. Graceful fallback to TEE if StrongBox unavailable or failed
        if (chain == null || chain.isEmpty()) {
            String teeAlias = ALIAS_PREFIX + "tee_" + UUID.randomUUID().toString().replace("-", "");
            try {
                chain = backend.generateAttestationChain(teeAlias, challenge, false);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                long latencyMs = Math.max(0L, (System.nanoTime() - startNanos) / 1_000_000L);
                return AttestationSnapshot.builder()
                        .available(false)
                        .fallbackFromStrongBox(fallbackFromStrongBox)
                        .generationLatencyMs(latencyMs)
                        .failureReason("tee_attestation_failed:" + e.getClass().getSimpleName()
                                + (strongBoxErr != null ? ";sb=" + strongBoxErr : ""))
                        .build();
            } finally {
                safeDeleteAlias(teeAlias);
            }
        }

        long latencyMs = Math.max(0L, (System.nanoTime() - startNanos) / 1_000_000L);
        if (chain == null || chain.isEmpty()) {
            return AttestationSnapshot.builder()
                    .available(false)
                    .fallbackFromStrongBox(fallbackFromStrongBox)
                    .generationLatencyMs(latencyMs)
                    .failureReason("empty_attestation_chain")
                    .build();
        }

        try {
            AttestationRecord record = extensionParser.parse(chain, challenge);
            CertificateTrustAnalyzer.TrustResult trust = trustAnalyzer.inspect(chain, evaluationTime);
            RkpExtensionParser.RkpParseResult rkp = rkpParser.parseChain(chain, record);
            return AttestationSnapshot.builder()
                    .available(true)
                    .usedStrongBox(usedStrongBox)
                    .fallbackFromStrongBox(fallbackFromStrongBox)
                    .record(record)
                    .trust(trust)
                    .rkp(rkp)
                    .certificateChain(chain)
                    .generationLatencyMs(latencyMs)
                    .build();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return AttestationSnapshot.builder()
                    .available(false)
                    .usedStrongBox(usedStrongBox)
                    .fallbackFromStrongBox(fallbackFromStrongBox)
                    .generationLatencyMs(latencyMs)
                    .failureReason("attestation_analysis_failed:" + e.getClass().getSimpleName())
                    .build();
        }
    }

    private void safeDeleteAlias(String alias) {
        try {
            backend.deleteAlias(alias);
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Best-effort cleanup; never throw out of finally
        }
    }

    private static final class AndroidKeyStoreBackend implements KeyAttestationBackend {
        @Override
        public List<X509Certificate> generateAttestationChain(
                String alias, byte[] challenge, boolean strongBox) throws Exception {
            KeyGenParameterSpec.Builder specBuilder = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setIsStrongBoxBacked(strongBox);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            kpg.initialize(specBuilder.build());
            kpg.generateKeyPair();

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            Certificate[] rawChain = ks.getCertificateChain(alias);
            if (rawChain == null || rawChain.length == 0) {
                return Collections.emptyList();
            }
            List<X509Certificate> out = new ArrayList<>(rawChain.length);
            for (Certificate cert : rawChain) {
                if (cert instanceof X509Certificate) {
                    out.add((X509Certificate) cert);
                }
            }
            return out;
        }

        @Override
        public void deleteAlias(String alias) {
            try {
                KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
                ks.load(null);
                if (ks.containsAlias(alias)) {
                    ks.deleteEntry(alias);
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Ignore cleanup error
            }
        }
    }
}
