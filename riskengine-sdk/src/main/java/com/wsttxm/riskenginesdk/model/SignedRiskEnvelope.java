package com.wsttxm.riskenginesdk.model;

import com.wsttxm.riskenginesdk.EnvelopeMode;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.util.RiskReportJsonSerializer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Hardware-attested cryptographically signed risk envelope (RFC §4.8.3 / §5.3).
 *
 * <p>Binds a collected {@link RiskReport}, a server-issued nonce ({@code challenge}), and a
 * recursively key-sorted UTF-8 canonical JSON payload under an ECDSA P-256 signature backed by
 * StrongBox or TEE. When hardware Keystore is unavailable or returns software-only backing,
 * {@link #getAttestationMode()} explicitly reports {@link AttestationMode#SOFTWARE_FALLBACK} and
 * NEVER spoofs hardware backing.</p>
 */
public final class SignedRiskEnvelope {

    public static final int PROTOCOL_VERSION = 2;

    /** Effective attestation mode achieved when signing the envelope. */
    public enum AttestationMode {
        PERSISTENT_KEY,
        FRESH_ATTESTATION,
        SOFTWARE_FALLBACK
    }

    private final RiskReport report;
    private final EnvelopeMode requestedMode;
    private final AttestationMode attestationMode;
    private final AttestationRecord.SecurityLevel keySecurityLevel;
    private final String canonicalPayloadJson;
    private final byte[] signatureBytes;
    private final String signatureBase64;
    private final List<String> certChainPem;
    private final List<byte[]> certChainDer;
    private final String challengeBase64Url;
    private final String reportSha256;
    private final long monotonicTimeMs;
    private final List<String> hardTriggers;
    private final long signingLatencyMs;

    public SignedRiskEnvelope(
            RiskReport report,
            EnvelopeMode requestedMode,
            AttestationMode attestationMode,
            AttestationRecord.SecurityLevel keySecurityLevel,
            String canonicalPayloadJson,
            byte[] signatureBytes,
            String signatureBase64,
            List<String> certChainPem,
            List<byte[]> certChainDer,
            String challengeBase64Url,
            String reportSha256,
            long monotonicTimeMs,
            List<String> hardTriggers,
            long signingLatencyMs) {
        this.report = Objects.requireNonNull(report, "report must not be null");
        this.requestedMode = Objects.requireNonNull(requestedMode, "requestedMode must not be null");
        this.attestationMode = Objects.requireNonNull(
                attestationMode, "attestationMode must not be null");
        this.keySecurityLevel = keySecurityLevel == null
                ? AttestationRecord.SecurityLevel.SOFTWARE
                : keySecurityLevel;
        this.canonicalPayloadJson = Objects.requireNonNull(
                canonicalPayloadJson, "canonicalPayloadJson must not be null");
        this.signatureBytes = signatureBytes == null
                ? new byte[0]
                : Arrays.copyOf(signatureBytes, signatureBytes.length);
        this.signatureBase64 = Objects.requireNonNull(
                signatureBase64, "signatureBase64 must not be null");
        this.certChainPem = certChainPem == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<>(certChainPem));
        List<byte[]> derCopy = new ArrayList<>();
        if (certChainDer != null) {
            for (byte[] der : certChainDer) {
                if (der != null && der.length > 0) {
                    derCopy.add(Arrays.copyOf(der, der.length));
                }
            }
        }
        this.certChainDer = Collections.unmodifiableList(derCopy);
        this.challengeBase64Url = challengeBase64Url == null ? "" : challengeBase64Url;
        this.reportSha256 = reportSha256 == null ? "" : reportSha256;
        this.monotonicTimeMs = monotonicTimeMs;
        this.hardTriggers = hardTriggers == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<>(hardTriggers));
        this.signingLatencyMs = Math.max(0L, signingLatencyMs);
    }

    public RiskReport getReport() {
        return report;
    }

    public EnvelopeMode getRequestedMode() {
        return requestedMode;
    }

    public AttestationMode getAttestationMode() {
        return attestationMode;
    }

    public AttestationRecord.SecurityLevel getKeySecurityLevel() {
        return keySecurityLevel;
    }

    public boolean isHardwareBacked() {
        return attestationMode != AttestationMode.SOFTWARE_FALLBACK
                && keySecurityLevel.isHardwareBacked();
    }

    /** Exact UTF-8 canonical JSON payload string covered by {@link #getSignatureBase64()}. */
    public String getCanonicalPayloadJson() {
        return canonicalPayloadJson;
    }

    /** Exact UTF-8 canonical payload bytes covered by {@code SHA256withECDSA}. */
    public byte[] getCanonicalPayloadBytes() {
        return canonicalPayloadJson.getBytes(StandardCharsets.UTF_8);
    }

    public byte[] getSignatureBytes() {
        return Arrays.copyOf(signatureBytes, signatureBytes.length);
    }

    public String getSignatureBase64() {
        return signatureBase64;
    }

    public List<String> getCertChainPem() {
        return certChainPem;
    }

    public List<byte[]> getCertChainDer() {
        List<byte[]> copy = new ArrayList<>(certChainDer.size());
        for (byte[] der : certChainDer) {
            copy.add(Arrays.copyOf(der, der.length));
        }
        return Collections.unmodifiableList(copy);
    }

    public String getChallengeBase64Url() {
        return challengeBase64Url;
    }

    public String getReportSha256() {
        return reportSha256;
    }

    public long getMonotonicTimeMs() {
        return monotonicTimeMs;
    }

    public List<String> getHardTriggers() {
        return hardTriggers;
    }

    public long getSigningLatencyMs() {
        return signingLatencyMs;
    }

    /** Serializes the full v2 {@link RiskReport} JSON including the {@code signedEnvelope} object. */
    public String toReportJson() {
        return RiskReportJsonSerializer.serialize(report, this);
    }
}
