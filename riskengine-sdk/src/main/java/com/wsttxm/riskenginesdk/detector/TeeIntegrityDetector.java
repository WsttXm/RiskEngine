package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.attestation.CertificateTrustAnalyzer;
import com.wsttxm.riskenginesdk.attestation.RkpExtensionParser;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.tee.GrantDomainSplitProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.Keystore2DeepProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.TeeNativeProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.VintfHalAndErrorPathProbe;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 15th converged top-level detector: Hardware Root of Trust &amp; TEE Integrity
 * ({@code tee_integrity}, strictly {@link ScanTier#POSTPONED}).
 *
 * <p>Orchestrates all 5 Phase 3 TEE / KeyMint / Keystore2 verification probes under bounded
 * {@link SafeExecutor#safeWithTimeoutOrInline} budgets:
 * <ol>
 *   <li>{@link AttestationCapability}: StrongBox &rarr; TEE ephemeral EC P-256 attestation,
 *       root-first OID {@code .17}, canonical CBOR RKP OID {@code .30}, Google Root SPKI anchor,
 *       and monotonic offline revoked-keybox CRL floor.</li>
 *   <li>{@link TeeNativeProbe}: 5-vector TrickyStore / Binder interceptor native check (including
 *       POSTPONED 3-round rotating-order Binder Honeypot timing) + cross-layer Leaf DER check.</li>
 *   <li>{@link GrantDomainSplitProbe}: ephemeral dynamic isolated-UID {@code Domain.APP} vs
 *       {@code Domain.GRANT} certificate chain-split detection.</li>
 *   <li>{@link Keystore2DeepProbe}: {@code generateKey} reply parcel {@code TAG_USER_ID}, API 35+
 *       post-processing parity, overwrite-readback anti-cache trap, and StrongBox constraints.</li>
 *   <li>{@link VintfHalAndErrorPathProbe}: VINTF KeyMint/Keymaster HAL version parity and
 *       {@code OperationErrorPath} with Samsung &amp; Xiaomi MediaTek quirk exemptions.</li>
 * </ol></p>
 *
 * <p>Visibility loss or absent TEE hardware is NEVER treated as a threat and NEVER degrades a
 * clean device from {@code SAFE} to {@code UNKNOWN}.</p>
 */
public class TeeIntegrityDetector extends BaseDetector {

    public static final String DETECTOR_NAME = "tee_integrity";
    public static final String FAMILY_TEE_TAMPER = TeeNativeProbe.FAMILY_TEE_TAMPER;
    public static final String EVIDENCE_HW_ATTESTED_LOCKED_PREFIX =
            "hardware_attested_locked_verified:";

    public static final String CODE_KEYBOX_REVOKED = "tee_keybox_revoked";
    public static final String CODE_CHAIN_SIGNATURE_INVALID = "tee_chain_signature_invalid";
    public static final String CODE_ISSUER_CHAIN_INVALID = "tee_issuer_chain_invalid";
    public static final String CODE_AOSP_ROOT_SPOOFED_HW = "tee_aosp_root_spoofed_hw";
    public static final String CODE_ATTESTATION_EXTENSION_INVALID =
            "tee_attestation_extension_invalid";
    public static final String CODE_CHALLENGE_MISMATCH = "tee_challenge_mismatch";
    public static final String CODE_LEAF_EXTENSION_SHADOW = "tee_leaf_extension_shadow";
    public static final String CODE_RKP_EXTENSION_INVALID = "tee_rkp_extension_invalid";

    private static final long DETECTOR_TIMEOUT_MS = 5_000L;
    private static final long ATTESTATION_SUB_TIMEOUT_MS = 2_000L;
    private static final long NATIVE_PROBE_SUB_TIMEOUT_MS = 1_200L;
    private static final long GRANT_PROBE_SUB_TIMEOUT_MS = 2_500L;
    private static final long DEEP_PROBE_SUB_TIMEOUT_MS = 2_000L;
    private static final long VINTF_PROBE_SUB_TIMEOUT_MS = 1_200L;

    /** Injectable seam for deterministic pure-JVM unit tests. */
    public interface TeeEnvironment {
        AttestationCapability.AttestationSnapshot collectAttestation();

        TeeNativeProbe.ProbeResult runNativeProbe(byte[] leafCertDer);

        GrantDomainSplitProbe.ProbeResult runGrantDomainSplitProbe(boolean isolatedProbeEnabled);

        Keystore2DeepProbe.ProbeResult runKeystore2DeepProbe(
                AttestationCapability.AttestationSnapshot snapshot);

        VintfHalAndErrorPathProbe.ProbeResult runVintfAndErrorPathProbe(
                AttestationCapability.AttestationSnapshot snapshot);
    }

    private final RiskEngineConfig config;
    private final SignalSnapshot signals;
    private final TeeEnvironment env;

    public TeeIntegrityDetector(Context context, RiskEngineConfig config, SignalSnapshot signals) {
        this(context, config, signals, null);
    }

    public static TeeIntegrityDetector createForTest(
            Context context,
            RiskEngineConfig config,
            SignalSnapshot signals,
            TeeEnvironment env) {
        return new TeeIntegrityDetector(context, config, signals, env);
    }

    private TeeIntegrityDetector(
            Context context,
            RiskEngineConfig config,
            SignalSnapshot signals,
            TeeEnvironment env) {
        super(context);
        this.config = config != null ? config : new RiskEngineConfig.Builder().build();
        this.signals = signals;
        this.env = env != null ? env : new DefaultTeeEnvironment(this.context, this.signals);
    }

    @Override
    public String getName() {
        return DETECTOR_NAME;
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.POSTPONED;
    }

    @Override
    public long getTimeoutMs() {
        return DETECTOR_TIMEOUT_MS;
    }

    @Override
    protected DetectionResult detect() {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> evidenceItems = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();
        boolean anyProbeSucceeded = false;

        // 1. Hardware Key Attestation (StrongBox -> TEE fallback)
        final AttestationCapability.AttestationSnapshot attSnap =
                SafeExecutor.safeWithTimeoutOrInline(
                        ATTESTATION_SUB_TIMEOUT_MS,
                        env::collectAttestation).getOrNull();

        byte[] leafCertDer = null;
        boolean hardwareVerifiedLocked = false;
        AttestationRecord.SecurityLevel verifiedTier = AttestationRecord.SecurityLevel.UNKNOWN;

        if (attSnap != null && attSnap.isAvailable()) {
            coverage.success();
            anyProbeSucceeded = true;
            leafCertDer = extractLeafDer(attSnap.getCertificateChain());
            evaluateAttestationSnapshot(attSnap, strong, evidenceItems);
            if (strong.isEmpty() && attSnap.isHardwareVerifiedLocked()) {
                hardwareVerifiedLocked = true;
                verifiedTier = attSnap.getRecord().getAttestationSecurityLevel();
            }
        }

        // 2. Native 5-vector TrickyStore / Binder interceptor + cross-layer Leaf DER check
        final byte[] finalLeafDer = leafCertDer;
        TeeNativeProbe.ProbeResult nativeRes = SafeExecutor.safeWithTimeoutOrInline(
                NATIVE_PROBE_SUB_TIMEOUT_MS,
                () -> env.runNativeProbe(finalLeafDer)).getOrNull();
        if (nativeRes != null && nativeRes.isUsable()) {
            coverage.success();
            anyProbeSucceeded = true;
            strong.addAll(nativeRes.getStrongTokens());
            medium.addAll(nativeRes.getMediumTokens());
            evidenceItems.addAll(nativeRes.getEvidenceItems());
        }

        // 3. Ephemeral isolated-UID Keystore2 Domain.APP vs Domain.GRANT chain-split probe
        final boolean isolatedEnabled = config.isEnableIsolatedProcessProbe();
        GrantDomainSplitProbe.ProbeResult grantRes = SafeExecutor.safeWithTimeoutOrInline(
                GRANT_PROBE_SUB_TIMEOUT_MS,
                () -> env.runGrantDomainSplitProbe(isolatedEnabled)).getOrNull();
        if (grantRes != null && grantRes.isUsable()) {
            coverage.success();
            anyProbeSucceeded = true;
            strong.addAll(grantRes.getStrongTokens());
            evidenceItems.addAll(grantRes.getEvidenceItems());
        }

        // 4. Keystore2 deep forensics (Reply Parcel TAG_USER_ID, Post-Processing, Overwrite, StrongBox)
        Keystore2DeepProbe.ProbeResult deepRes = SafeExecutor.safeWithTimeoutOrInline(
                DEEP_PROBE_SUB_TIMEOUT_MS,
                () -> env.runKeystore2DeepProbe(attSnap)).getOrNull();
        if (deepRes != null && deepRes.isUsable()) {
            coverage.success();
            anyProbeSucceeded = true;
            strong.addAll(deepRes.getStrongTokens());
            medium.addAll(deepRes.getMediumTokens());
            evidenceItems.addAll(deepRes.getEvidenceItems());
        }

        // 5. VINTF KeyMint/Keymaster HAL parity & OperationErrorPath with OEM quirks
        VintfHalAndErrorPathProbe.ProbeResult vintfRes = SafeExecutor.safeWithTimeoutOrInline(
                VINTF_PROBE_SUB_TIMEOUT_MS,
                () -> env.runVintfAndErrorPathProbe(attSnap)).getOrNull();
        if (vintfRes != null && vintfRes.isUsable()) {
            coverage.success();
            anyProbeSucceeded = true;
            strong.addAll(vintfRes.getStrongTokens());
            medium.addAll(vintfRes.getMediumTokens());
            evidenceItems.addAll(vintfRes.getEvidenceItems());
        }

        // Visibility loss / absent hardware TEE is NEVER a threat and must NOT degrade SAFE -> UNKNOWN
        if (!anyProbeSucceeded) {
            coverage.success();
        }

        List<EvidenceItem> mergedEvidence = DataAggregator.mergeEvidenceItems(evidenceItems);
        List<String> details = new ArrayList<>(strong.size() + medium.size());
        details.addAll(strong);
        for (String m : medium) {
            if (!strong.contains(m)) {
                details.add(m);
            }
        }

        if (!strong.isEmpty()) {
            String summary = String.join("; ", details);
            return result(
                    RiskLevel.HIGH,
                    DetectionStatus.DANGER,
                    9,
                    10,
                    false,
                    details,
                    summary,
                    coverage).withEvidenceItems(mergedEvidence);
        }

        if (!medium.isEmpty()) {
            String summary = String.join("; ", details);
            return result(
                    RiskLevel.MEDIUM,
                    DetectionStatus.WARNING,
                    4,
                    10,
                    false,
                    details,
                    summary,
                    coverage).withEvidenceItems(mergedEvidence);
        }

        String cleanSummary = hardwareVerifiedLocked
                ? EVIDENCE_HW_ATTESTED_LOCKED_PREFIX + verifiedTier.name()
                : "no risk detected";
        return result(
                RiskLevel.SAFE,
                DetectionStatus.NORMAL,
                0,
                10,
                false,
                details,
                cleanSummary,
                coverage).withEvidenceItems(mergedEvidence);
    }

    private static void evaluateAttestationSnapshot(
            AttestationCapability.AttestationSnapshot snap,
            Set<String> strong,
            List<EvidenceItem> items) {
        CertificateTrustAnalyzer.TrustResult trust = snap.getTrust();
        AttestationRecord record = snap.getRecord();

        if (trust != null) {
            if (trust.isAnyCertRevoked()) {
                String serials = String.join(",", trust.getRevokedSerials());
                strong.add(CODE_KEYBOX_REVOKED + ":" + serials);
                items.add(new EvidenceItem(
                        CODE_KEYBOX_REVOKED,
                        EvidenceItem.SourceLayer.HARDWARE,
                        EnumSet.of(EvidenceItem.SourceLayer.HARDWARE, EvidenceItem.SourceLayer.JAVA),
                        "GoogleAttestationRootStore:CRL",
                        serials,
                        FAMILY_TEE_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
            if (!trust.isChainSignatureValid()) {
                String sigErr = trust.getSignatureError() != null
                        ? trust.getSignatureError()
                        : "invalid_signature";
                strong.add(CODE_CHAIN_SIGNATURE_INVALID);
                items.add(new EvidenceItem(
                        CODE_CHAIN_SIGNATURE_INVALID,
                        EvidenceItem.SourceLayer.HARDWARE,
                        EnumSet.of(EvidenceItem.SourceLayer.HARDWARE, EvidenceItem.SourceLayer.JAVA),
                        "X509CertificateChain",
                        sigErr,
                        FAMILY_TEE_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
            if (!trust.isIssuerChainValid()) {
                String issErr = String.join(",", trust.getIssuerMismatches());
                strong.add(CODE_ISSUER_CHAIN_INVALID);
                items.add(new EvidenceItem(
                        CODE_ISSUER_CHAIN_INVALID,
                        EvidenceItem.SourceLayer.HARDWARE,
                        EnumSet.of(EvidenceItem.SourceLayer.HARDWARE, EvidenceItem.SourceLayer.JAVA),
                        "X509CertificateChain:RFC5280",
                        issErr,
                        FAMILY_TEE_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
            if (trust.getTrustRoot() == CertificateTrustAnalyzer.TrustRoot.AOSP_SOFTWARE
                    && record != null
                    && record.isValid()
                    && (record.getAttestationSecurityLevel().isHardwareBacked()
                            || record.getKeymasterSecurityLevel().isHardwareBacked())) {
                strong.add(CODE_AOSP_ROOT_SPOOFED_HW);
                items.add(new EvidenceItem(
                        CODE_AOSP_ROOT_SPOOFED_HW,
                        EvidenceItem.SourceLayer.HARDWARE,
                        EnumSet.of(EvidenceItem.SourceLayer.HARDWARE, EvidenceItem.SourceLayer.JAVA),
                        "X509CertificateChain:root",
                        "AOSP_SOFTWARE_root_claiming_"
                                + record.getAttestationSecurityLevel().name(),
                        FAMILY_TEE_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
        }

        if (record != null) {
            if (!record.isValid()) {
                String err = record.getParseError() != null
                        ? record.getParseError()
                        : "invalid_oid_17";
                strong.add(CODE_ATTESTATION_EXTENSION_INVALID);
                items.add(new EvidenceItem(
                        CODE_ATTESTATION_EXTENSION_INVALID,
                        EvidenceItem.SourceLayer.JAVA,
                        "OID:1.3.6.1.4.1.11129.2.1.17",
                        err,
                        FAMILY_TEE_TAMPER,
                        EvidenceItem.Rank.STRONG));
            } else {
                if (!record.isChallengeMatched()) {
                    strong.add(CODE_CHALLENGE_MISMATCH);
                    items.add(new EvidenceItem(
                            CODE_CHALLENGE_MISMATCH,
                            EvidenceItem.SourceLayer.HARDWARE,
                            EnumSet.of(
                                    EvidenceItem.SourceLayer.HARDWARE,
                                    EvidenceItem.SourceLayer.JAVA),
                            "OID:1.3.6.1.4.1.11129.2.1.17:challenge",
                            "ephemeral_challenge_mismatch",
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                }
                if (record.isLeafShadowAttempted()) {
                    strong.add(CODE_LEAF_EXTENSION_SHADOW);
                    items.add(new EvidenceItem(
                            CODE_LEAF_EXTENSION_SHADOW,
                            EvidenceItem.SourceLayer.JAVA,
                            "OID:1.3.6.1.4.1.11129.2.1.17:chain",
                            "multiple_oid_17_extensions=" + record.getAttestationExtensionCount(),
                            FAMILY_TEE_TAMPER,
                            EvidenceItem.Rank.STRONG));
                }
            }
        }

        RkpExtensionParser.RkpParseResult rkp = snap.getRkp();
        if (rkp != null && rkp.isPresent() && !rkp.isValid()) {
            String rkpErr = !rkp.getIssues().isEmpty()
                    ? String.join(",", rkp.getIssues())
                    : "invalid_rkp_cbor";
            strong.add(CODE_RKP_EXTENSION_INVALID);
            items.add(new EvidenceItem(
                    CODE_RKP_EXTENSION_INVALID,
                    EvidenceItem.SourceLayer.JAVA,
                    "OID:1.3.6.1.4.1.11129.2.1.30",
                    rkpErr,
                    FAMILY_TEE_TAMPER,
                    EvidenceItem.Rank.STRONG));
        }
    }

    private static byte[] extractLeafDer(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty() || chain.get(0) == null) {
            return null;
        }
        try {
            return chain.get(0).getEncoded();
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            return null;
        }
    }

    private static final class DefaultTeeEnvironment implements TeeEnvironment {
        private final Context context;
        private final SignalSnapshot signals;

        DefaultTeeEnvironment(Context context, SignalSnapshot signals) {
            this.context = context;
            this.signals = signals;
        }

        @Override
        public AttestationCapability.AttestationSnapshot collectAttestation() {
            if (signals != null) {
                SignalResult<AttestationCapability.AttestationSnapshot> res =
                        signals.getAttestationSnapshot(true);
                return res != null && res.isSuccess() ? res.getValue() : null;
            }
            return new AttestationCapability().collect();
        }

        @Override
        public TeeNativeProbe.ProbeResult runNativeProbe(byte[] leafCertDer) {
            return TeeNativeProbe.run(signals, leafCertDer, true);
        }

        @Override
        public GrantDomainSplitProbe.ProbeResult runGrantDomainSplitProbe(
                boolean isolatedProbeEnabled) {
            return GrantDomainSplitProbe.run(signals, isolatedProbeEnabled);
        }

        @Override
        public Keystore2DeepProbe.ProbeResult runKeystore2DeepProbe(
                AttestationCapability.AttestationSnapshot snapshot) {
            return Keystore2DeepProbe.run(context, snapshot);
        }

        @Override
        public VintfHalAndErrorPathProbe.ProbeResult runVintfAndErrorPathProbe(
                AttestationCapability.AttestationSnapshot snapshot) {
            return VintfHalAndErrorPathProbe.run(snapshot);
        }
    }
}
