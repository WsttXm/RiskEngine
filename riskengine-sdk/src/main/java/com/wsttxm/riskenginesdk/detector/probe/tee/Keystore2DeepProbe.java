package com.wsttxm.riskenginesdk.detector.probe.tee;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.attestation.AttestationExtensionParser;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.process.Keystore2ParcelClient;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Keystore2 &amp; StrongBox deep forensics probe (API 31+ / 35+).
 *
 * <p>Implements 4 orthogonal TrickyStore / TEE Simulator / soft-StrongBox sub-checks:
 * <ol>
 *   <li><b>API 31+ {@code generateKey} Reply Parcel {@code TAG_USER_ID}</b>: inspects the raw
 *       {@code KeyMetadata} reply parcel from {@code IKeystoreSecurityLevel.generateKey} to verify
 *       that stock Rust {@code keystore2} appended {@code TAG_USER_ID (0x300001F5)} at
 *       {@code SECURITY_LEVEL_SOFTWARE (0)} as the final authorization.</li>
 *   <li><b>API 35+ Post-Processing Split-Path Parity</b>: compares the {@code RkpdProvisioned}
 *       arm (subject to {@code KeystorePostProcessor}) against the {@code PURPOSE_ATTEST_KEY}
 *       {@code UserGenerated} arm (bypassing post-processing) for both {@code RootOfTrust}
 *       parity and paired median/MAD latency delta.</li>
 *   <li><b>Overwrite-Readback Anti-Cache Trap</b>: gates on marker-certificate observability,
 *       overwrites an attested key entry via {@code KeyStore.setKeyEntry}, and performs dual
 *       post-update readbacks (plus delete/regenerate serial freshness) to expose stale cached
 *       attestation chains in TEE Simulator / TEES-RS.</li>
 *   <li><b>StrongBox Hardware Constraints</b>: validates {@code KeyInfo} vs attested security
 *       level consistency, RSA-4096 / {@code secp521r1} rejection layer attribution, and
 *       {@code <2ms} signing / {@code <20ms} keygen software-emulation tripwires.</li>
 * </ol></p>
 *
 * <p>All temporary keys are unconditionally deleted in {@code finally}. Hidden-API restrictions,
 * RKP offline states, or missing hardware features map cleanly to unavailable/skipped with zero
 * false positives.</p>
 */
public final class Keystore2DeepProbe {

    public static final String FAMILY_TEE_TAMPER = TeeNativeProbe.FAMILY_TEE_TAMPER;

    public static final String CODE_GENERATE_KEY_PARCEL_SPOOF = "tee_generate_key_parcel_spoof";
    public static final String CODE_GENERATE_KEY_CREATION_LEVEL = "tee_generate_key_creation_level";
    public static final String CODE_POST_PROCESSING_ROT_DIVERGENCE = "tee_post_processing_rot_divergence";
    public static final String CODE_POST_PROCESSING_LATENCY = "tee_post_processing_latency";
    public static final String CODE_OVERWRITE_STALE_CHAIN = "tee_overwrite_stale_chain";
    public static final String CODE_LIFECYCLE_STALE_SERIAL = "tee_lifecycle_stale_serial";
    public static final String CODE_STRONGBOX_LEVEL_MISMATCH = "tee_strongbox_level_mismatch";
    public static final String CODE_SOFT_STRONGBOX = "tee_soft_strongbox";

    public static final int TAG_USER_ID = 0x300001F5;
    public static final int TAG_CREATION_DATETIME = 0x600002BD;
    public static final int SECURITY_LEVEL_SOFTWARE = 0;
    public static final int SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int SECURITY_LEVEL_STRONGBOX = 2;
    public static final int SECURITY_LEVEL_KEYSTORE = 100;

    public static final int POST_PROCESSING_MIN_PAIRED_SAMPLES = 8;
    public static final double POST_PROCESSING_DELTA_FLOOR_MS = 120.0;
    public static final double POST_PROCESSING_DISPERSION_MULTIPLIER = 3.0;
    public static final double POST_PROCESSING_SUSPECT_DELTA_FLOOR_MS = 60.0;
    public static final double POST_PROCESSING_SUSPECT_DISPERSION_MULTIPLIER = 2.0;

    public static final int STRONGBOX_SIGNING_TRIPWIRE_MICROS = 2_000;
    public static final int STRONGBOX_KEYGEN_TRIPWIRE_MILLIS = 20;

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String OID_RKP_PROVISIONING_INFO = "1.3.6.1.4.1.11129.2.1.30";

    private static final int DEFAULT_POST_PROCESSING_PAIRS = 8;
    private static final int MAX_AUTHORIZATION_COUNT = 256;
    private static final int NON_NULL_MARKER = 1;
    private static final int NULL_LENGTH = -1;

    // Self-contained minimal valid X.509v3 EC P-256 marker certificate (CN=RiskEngineMarker)
    // used exclusively for local setCertificateEntry/setKeyEntry overwrite-observability gating.
    private static final String MARKER_CERT_BASE64 =
            "MIIBbDCCARKgAwIBAgIUQ7QMO9VIRGJLjgzadISrLkJ2i5UwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQ"
            + "Umlza0VuZ2luZU1hcmtlcjAgFw0yNjExMjQwNTA4MDhaGA8yMTI2MTAzMTA1MDgwOFowGzEZMBcGA1UE"
            + "AwwQUmlza0VuZ2luZU1hcmtlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIncuA9ey5iTa+3zhwQ4"
            + "uZWHahQpcTydd6ocvI5V3GlydsiP0GjcjCoO0uTZifoGWbv9i0i8bFy34uU1UFOk9ymjMjAwMB0GA1Ud"
            + "DgQWBBSVhAoISdg9hyDjAy5x/8kkS8gV5zAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUC"
            + "IBPq9HE1URz3kF6eZe5+KFj8m4degZIi7k3nrtpX74IcAiEAqxZe7ReFqInWD3oCG9CQ95V+yf6Nh6Em"
            + "TMFybnFEwaY=";

    /** Layer attribution for StrongBox key-parameter rejection checks. */
    public enum StrongBoxAcceptance {
        ACCEPTED,
        REFUSED_BY_FRAMEWORK,
        REFUSED_BY_KEYSTORE,
        INCONCLUSIVE
    }

    /** Anomaly classification for {@code generateKey} reply parcels. */
    public enum ReplyParcelAnomaly {
        NONE,
        USER_ID_NOT_APPENDED_BY_KEYSTORE,
        CREATION_DATETIME_OUTSIDE_KEYSTORE
    }

    /** Anomaly classification for API 35+ post-processing split-path comparison. */
    public enum PostProcessingAnomaly {
        NONE,
        ROOT_OF_TRUST_DIVERGENCE,
        TIMING_DETECTED,
        TIMING_SUSPECT,
        RKP_UNAVAILABLE,
        RKP_FALLBACK_INCONCLUSIVE,
        UNMEASURABLE
    }

    /** Single parsed {@code Authorization} entry from a Keystore2 {@code KeyMetadata} parcel. */
    public static final class ReplyAuthorization {
        private final int securityLevel;
        private final int tag;
        private final int valueTag;
        private final Long scalarValue;
        private final Integer blobLength;

        public ReplyAuthorization(
                int securityLevel, int tag, int valueTag, Long scalarValue, Integer blobLength) {
            this.securityLevel = securityLevel;
            this.tag = tag;
            this.valueTag = valueTag;
            this.scalarValue = scalarValue;
            this.blobLength = blobLength;
        }

        public int getSecurityLevel() {
            return securityLevel;
        }

        public int getTag() {
            return tag;
        }

        public int getValueTag() {
            return valueTag;
        }

        public Long getScalarValue() {
            return scalarValue;
        }

        public Integer getBlobLength() {
            return blobLength;
        }

        public String describe() {
            return String.format(Locale.ROOT, "0x%08X@%d", tag, securityLevel);
        }
    }

    /** Parsed result of a raw {@code IKeystoreSecurityLevel.generateKey} reply parcel. */
    public static final class ReplyParcelParseResult {
        private final boolean parseSucceeded;
        private final int keySecurityLevel;
        private final List<ReplyAuthorization> authorizations;
        private final Integer certificateLength;
        private final Integer certificateChainLength;
        private final Long modificationTimeMs;
        private final ReplyParcelAnomaly anomaly;
        private final String detail;

        ReplyParcelParseResult(
                boolean parseSucceeded,
                int keySecurityLevel,
                List<ReplyAuthorization> authorizations,
                Integer certificateLength,
                Integer certificateChainLength,
                Long modificationTimeMs,
                ReplyParcelAnomaly anomaly,
                String detail) {
            this.parseSucceeded = parseSucceeded;
            this.keySecurityLevel = keySecurityLevel;
            this.authorizations = authorizations == null
                    ? Collections.<ReplyAuthorization>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(authorizations));
            this.certificateLength = certificateLength;
            this.certificateChainLength = certificateChainLength;
            this.modificationTimeMs = modificationTimeMs;
            this.anomaly = anomaly == null ? ReplyParcelAnomaly.NONE : anomaly;
            this.detail = detail == null ? "" : detail;
        }

        public boolean isParseSucceeded() {
            return parseSucceeded;
        }

        public int getKeySecurityLevel() {
            return keySecurityLevel;
        }

        public List<ReplyAuthorization> getAuthorizations() {
            return authorizations;
        }

        public Integer getCertificateLength() {
            return certificateLength;
        }

        public Integer getCertificateChainLength() {
            return certificateChainLength;
        }

        public Long getModificationTimeMs() {
            return modificationTimeMs;
        }

        public ReplyParcelAnomaly getAnomaly() {
            return anomaly;
        }

        public String getDetail() {
            return detail;
        }
    }

    /** Single timed attestation sample for API 35+ post-processing comparison. */
    public static final class PostProcessingPathSample {
        private final double elapsedMillis;
        private final AttestationRecord.RootOfTrust rootOfTrust;
        private final Boolean rkpProvisioningInfoPresent;
        private final String failureSummary;

        public PostProcessingPathSample(
                double elapsedMillis,
                AttestationRecord.RootOfTrust rootOfTrust,
                Boolean rkpProvisioningInfoPresent,
                String failureSummary) {
            this.elapsedMillis = elapsedMillis;
            this.rootOfTrust = rootOfTrust;
            this.rkpProvisioningInfoPresent = rkpProvisioningInfoPresent;
            this.failureSummary = failureSummary;
        }

        public static PostProcessingPathSample success(
                double elapsedMillis,
                AttestationRecord.RootOfTrust rootOfTrust,
                Boolean rkpProvisioningInfoPresent) {
            return new PostProcessingPathSample(
                    elapsedMillis, rootOfTrust, rkpProvisioningInfoPresent, null);
        }

        public static PostProcessingPathSample failure(String summary) {
            return new PostProcessingPathSample(
                    0.0, null, null, summary == null ? "failed" : summary);
        }

        public double getElapsedMillis() {
            return elapsedMillis;
        }

        public AttestationRecord.RootOfTrust getRootOfTrust() {
            return rootOfTrust;
        }

        public Boolean getRkpProvisioningInfoPresent() {
            return rkpProvisioningInfoPresent;
        }

        public String getFailureSummary() {
            return failureSummary;
        }

        public boolean isSuccess() {
            return failureSummary == null;
        }
    }

    /** Evaluated result of API 35+ post-processing split-path comparison. */
    public static final class PostProcessingResult {
        private final boolean measurementAvailable;
        private final PostProcessingAnomaly anomaly;
        private final int pairedSampleCount;
        private final Double medianRkpMillis;
        private final Double medianAttestKeyMillis;
        private final Double deltaMillis;
        private final Double dispersionMillis;
        private final List<String> divergentFields;
        private final String detail;

        PostProcessingResult(
                boolean measurementAvailable,
                PostProcessingAnomaly anomaly,
                int pairedSampleCount,
                Double medianRkpMillis,
                Double medianAttestKeyMillis,
                Double deltaMillis,
                Double dispersionMillis,
                List<String> divergentFields,
                String detail) {
            this.measurementAvailable = measurementAvailable;
            this.anomaly = anomaly == null ? PostProcessingAnomaly.UNMEASURABLE : anomaly;
            this.pairedSampleCount = pairedSampleCount;
            this.medianRkpMillis = medianRkpMillis;
            this.medianAttestKeyMillis = medianAttestKeyMillis;
            this.deltaMillis = deltaMillis;
            this.dispersionMillis = dispersionMillis;
            this.divergentFields = divergentFields == null
                    ? Collections.<String>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(divergentFields));
            this.detail = detail == null ? "" : detail;
        }

        public boolean isMeasurementAvailable() {
            return measurementAvailable;
        }

        public PostProcessingAnomaly getAnomaly() {
            return anomaly;
        }

        public int getPairedSampleCount() {
            return pairedSampleCount;
        }

        public Double getMedianRkpMillis() {
            return medianRkpMillis;
        }

        public Double getMedianAttestKeyMillis() {
            return medianAttestKeyMillis;
        }

        public Double getDeltaMillis() {
            return deltaMillis;
        }

        public Double getDispersionMillis() {
            return dispersionMillis;
        }

        public List<String> getDivergentFields() {
            return divergentFields;
        }

        public String getDetail() {
            return detail;
        }
    }

    /** Post-overwrite readback snapshot for the anti-cache persistence trap. */
    public static final class PostUpdateSnapshot {
        private final List<byte[]> fullChainDer;
        private final boolean leafMatchesMarker;

        public PostUpdateSnapshot(List<byte[]> fullChainDer, boolean leafMatchesMarker) {
            List<byte[]> copy = new ArrayList<>();
            if (fullChainDer != null) {
                for (byte[] item : fullChainDer) {
                    if (item != null && item.length > 0) {
                        copy.add(Arrays.copyOf(item, item.length));
                    }
                }
            }
            this.fullChainDer = Collections.unmodifiableList(copy);
            this.leafMatchesMarker = leafMatchesMarker;
        }

        public List<byte[]> getFullChainDer() {
            return fullChainDer;
        }

        public boolean isLeafMatchesMarker() {
            return leafMatchesMarker;
        }
    }

    /** Observation collected for StrongBox constraint checks. */
    public static final class StrongBoxObservation {
        private final boolean advertised;
        private final Boolean keyInfoConfirmedStrongBox;
        private final AttestationRecord.SecurityLevel attestedLevel;
        private final Integer keygenMillis;
        private final Integer medianSigningMicros;
        private final StrongBoxAcceptance rsa4096Acceptance;
        private final StrongBoxAcceptance secp521r1Acceptance;
        private final String unavailableDetail;

        public StrongBoxObservation(
                boolean advertised,
                Boolean keyInfoConfirmedStrongBox,
                AttestationRecord.SecurityLevel attestedLevel,
                Integer keygenMillis,
                Integer medianSigningMicros,
                StrongBoxAcceptance rsa4096Acceptance,
                StrongBoxAcceptance secp521r1Acceptance,
                String unavailableDetail) {
            this.advertised = advertised;
            this.keyInfoConfirmedStrongBox = keyInfoConfirmedStrongBox;
            this.attestedLevel = attestedLevel == null
                    ? AttestationRecord.SecurityLevel.UNKNOWN
                    : attestedLevel;
            this.keygenMillis = keygenMillis;
            this.medianSigningMicros = medianSigningMicros;
            this.rsa4096Acceptance = rsa4096Acceptance == null
                    ? StrongBoxAcceptance.INCONCLUSIVE
                    : rsa4096Acceptance;
            this.secp521r1Acceptance = secp521r1Acceptance == null
                    ? StrongBoxAcceptance.INCONCLUSIVE
                    : secp521r1Acceptance;
            this.unavailableDetail = unavailableDetail;
        }

        public boolean isAdvertised() {
            return advertised;
        }

        public Boolean getKeyInfoConfirmedStrongBox() {
            return keyInfoConfirmedStrongBox;
        }

        public boolean isKeyInfoConfirmedStrongBox() {
            return Boolean.TRUE.equals(keyInfoConfirmedStrongBox);
        }

        public AttestationRecord.SecurityLevel getAttestedLevel() {
            return attestedLevel;
        }

        public Integer getKeygenMillis() {
            return keygenMillis;
        }

        public Integer getMedianSigningMicros() {
            return medianSigningMicros;
        }

        public StrongBoxAcceptance getRsa4096Acceptance() {
            return rsa4096Acceptance;
        }

        public StrongBoxAcceptance getSecp521r1Acceptance() {
            return secp521r1Acceptance;
        }

        public String getUnavailableDetail() {
            return unavailableDetail;
        }
    }

    /** Injectable seam covering all 4 sub-checks for deterministic pure-JVM unit testing. */
    public interface Keystore2DeepAdapter {
        int getSdkInt();

        /** Captures raw marshalled reply parcel of {@code generateKey} on API 31+; null if unavailable. */
        byte[] captureGenerateKeyReplyParcel(String alias) throws Exception;

        /** Executes warmup + paired RKP vs PURPOSE_ATTEST_KEY samples on API 35+; null if unavailable. */
        PostProcessingSessionData collectPostProcessingSamples(String aliasPrefix, int pairCount)
                throws Exception;

        /** Executes support-gated overwrite-readback + lifecycle serial check; null if unavailable. */
        OverwriteSessionData collectOverwriteAndLifecycle(
                String supportAlias, String attackAlias, String lifecycleAlias) throws Exception;

        /** Collects StrongBox behavioral constraints if StrongBox is advertised; null if unavailable. */
        StrongBoxObservation collectStrongBoxObservation(String aliasPrefix) throws Exception;

        /** Best-effort alias deletion invoked unconditionally in {@code finally}. */
        void deleteAlias(String alias);
    }

    /** Raw paired samples returned by {@link Keystore2DeepAdapter#collectPostProcessingSamples}. */
    public static final class PostProcessingSessionData {
        private final PostProcessingPathSample warmupSample;
        private final boolean attestKeyProvisioned;
        private final List<PostProcessingPathSample> rkpSamples;
        private final List<PostProcessingPathSample> attestKeySamples;

        public PostProcessingSessionData(
                PostProcessingPathSample warmupSample,
                boolean attestKeyProvisioned,
                List<PostProcessingPathSample> rkpSamples,
                List<PostProcessingPathSample> attestKeySamples) {
            this.warmupSample = warmupSample;
            this.attestKeyProvisioned = attestKeyProvisioned;
            this.rkpSamples = rkpSamples == null
                    ? Collections.<PostProcessingPathSample>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(rkpSamples));
            this.attestKeySamples = attestKeySamples == null
                    ? Collections.<PostProcessingPathSample>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(attestKeySamples));
        }

        public PostProcessingPathSample getWarmupSample() {
            return warmupSample;
        }

        public boolean isAttestKeyProvisioned() {
            return attestKeyProvisioned;
        }

        public List<PostProcessingPathSample> getRkpSamples() {
            return rkpSamples;
        }

        public List<PostProcessingPathSample> getAttestKeySamples() {
            return attestKeySamples;
        }
    }

    /** Raw observations returned by {@link Keystore2DeepAdapter#collectOverwriteAndLifecycle}. */
    public static final class OverwriteSessionData {
        private final boolean supportGateClean;
        private final List<byte[]> priorAttestedChainDer;
        private final boolean updateSucceeded;
        private final List<PostUpdateSnapshot> postUpdateSnapshots;
        private final String firstLifecycleSerialHex;
        private final String secondLifecycleSerialHex;
        private final String firstLifecycleSpkiSha256;
        private final String secondLifecycleSpkiSha256;
        private final boolean deleteRemovedAlias;

        public OverwriteSessionData(
                boolean supportGateClean,
                List<byte[]> priorAttestedChainDer,
                boolean updateSucceeded,
                List<PostUpdateSnapshot> postUpdateSnapshots,
                String firstLifecycleSerialHex,
                String secondLifecycleSerialHex,
                boolean deleteRemovedAlias) {
            this(
                    supportGateClean,
                    priorAttestedChainDer,
                    updateSucceeded,
                    postUpdateSnapshots,
                    firstLifecycleSerialHex,
                    secondLifecycleSerialHex,
                    null,
                    null,
                    deleteRemovedAlias);
        }

        public OverwriteSessionData(
                boolean supportGateClean,
                List<byte[]> priorAttestedChainDer,
                boolean updateSucceeded,
                List<PostUpdateSnapshot> postUpdateSnapshots,
                String firstLifecycleSerialHex,
                String secondLifecycleSerialHex,
                String firstLifecycleSpkiSha256,
                String secondLifecycleSpkiSha256,
                boolean deleteRemovedAlias) {
            this.supportGateClean = supportGateClean;
            List<byte[]> priorCopy = new ArrayList<>();
            if (priorAttestedChainDer != null) {
                for (byte[] cert : priorAttestedChainDer) {
                    if (cert != null && cert.length > 0) {
                        priorCopy.add(Arrays.copyOf(cert, cert.length));
                    }
                }
            }
            this.priorAttestedChainDer = Collections.unmodifiableList(priorCopy);
            this.updateSucceeded = updateSucceeded;
            this.postUpdateSnapshots = postUpdateSnapshots == null
                    ? Collections.<PostUpdateSnapshot>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(postUpdateSnapshots));
            this.firstLifecycleSerialHex = firstLifecycleSerialHex;
            this.secondLifecycleSerialHex = secondLifecycleSerialHex;
            this.firstLifecycleSpkiSha256 = firstLifecycleSpkiSha256;
            this.secondLifecycleSpkiSha256 = secondLifecycleSpkiSha256;
            this.deleteRemovedAlias = deleteRemovedAlias;
        }

        public boolean isSupportGateClean() {
            return supportGateClean;
        }

        public List<byte[]> getPriorAttestedChainDer() {
            return priorAttestedChainDer;
        }

        public boolean isUpdateSucceeded() {
            return updateSucceeded;
        }

        public List<PostUpdateSnapshot> getPostUpdateSnapshots() {
            return postUpdateSnapshots;
        }

        public String getFirstLifecycleSerialHex() {
            return firstLifecycleSerialHex;
        }

        public String getSecondLifecycleSerialHex() {
            return secondLifecycleSerialHex;
        }

        public String getFirstLifecycleSpkiSha256() {
            return firstLifecycleSpkiSha256;
        }

        public String getSecondLifecycleSpkiSha256() {
            return secondLifecycleSpkiSha256;
        }

        public boolean isDeleteRemovedAlias() {
            return deleteRemovedAlias;
        }
    }

    /** Aggregate probe output compatible with {@code TeeIntegrityDetector}. */
    public static final class ProbeResult {
        private final boolean usable;
        private final String failureReason;
        private final Set<String> strongTokens;
        private final Set<String> mediumTokens;
        private final List<EvidenceItem> evidenceItems;
        private final ReplyParcelParseResult replyParcelResult;
        private final PostProcessingResult postProcessingResult;

        ProbeResult(
                boolean usable,
                String failureReason,
                Set<String> strongTokens,
                Set<String> mediumTokens,
                List<EvidenceItem> evidenceItems,
                ReplyParcelParseResult replyParcelResult,
                PostProcessingResult postProcessingResult) {
            this.usable = usable;
            this.failureReason = failureReason;
            this.strongTokens = Collections.unmodifiableSet(strongTokens);
            this.mediumTokens = Collections.unmodifiableSet(mediumTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.replyParcelResult = replyParcelResult;
            this.postProcessingResult = postProcessingResult;
        }

        public boolean isUsable() {
            return usable;
        }

        public String getFailureReason() {
            return failureReason;
        }

        public Set<String> getStrongTokens() {
            return strongTokens;
        }

        public Set<String> getMediumTokens() {
            return mediumTokens;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public ReplyParcelParseResult getReplyParcelResult() {
            return replyParcelResult;
        }

        public PostProcessingResult getPostProcessingResult() {
            return postProcessingResult;
        }

        public boolean hasFindings() {
            return !strongTokens.isEmpty() || !mediumTokens.isEmpty() || !evidenceItems.isEmpty();
        }
    }

    private Keystore2DeepProbe() {
    }

    public static ProbeResult run(
            Context context, AttestationCapability.AttestationSnapshot attestationSnapshot) {
        return run(new AndroidKeystore2DeepAdapter(context, attestationSnapshot));
    }

    public static ProbeResult run(Keystore2DeepAdapter adapter) {
        if (adapter == null) {
            return new ProbeResult(
                    false,
                    "deep_adapter_null",
                    Collections.<String>emptySet(),
                    Collections.<String>emptySet(),
                    Collections.<EvidenceItem>emptyList(),
                    null,
                    null);
        }

        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();
        boolean anyUsable = false;
        String lastFailure = null;
        ReplyParcelParseResult parsedParcel = null;
        PostProcessingResult postResult = null;

        int sdkInt = adapter.getSdkInt();
        String nonce = UUID.randomUUID().toString().replace("-", "").substring(0, 12);

        // 1. API 31+ generateKey Reply Parcel TAG_USER_ID (0x300001F5, SOFTWARE)
        if (sdkInt >= 31) {
            String parcelAlias = "riskengine_ks2_parcel_" + nonce;
            try {
                byte[] rawReply = adapter.captureGenerateKeyReplyParcel(parcelAlias);
                if (rawReply != null && rawReply.length > 0) {
                    parsedParcel = parseGenerateKeyReplyParcel(rawReply);
                    if (parsedParcel.isParseSucceeded()) {
                        anyUsable = true;
                        if (parsedParcel.getAnomaly()
                                == ReplyParcelAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE) {
                            strong.add(CODE_GENERATE_KEY_PARCEL_SPOOF);
                            items.add(new EvidenceItem(
                                    CODE_GENERATE_KEY_PARCEL_SPOOF,
                                    EvidenceItem.SourceLayer.HARDWARE,
                                    EnumSet.of(
                                            EvidenceItem.SourceLayer.HARDWARE,
                                            EvidenceItem.SourceLayer.JAVA),
                                    "keystore2:IKeystoreSecurityLevel.generateKey",
                                    parsedParcel.getDetail(),
                                    FAMILY_TEE_TAMPER,
                                    EvidenceItem.Rank.STRONG));
                        } else if (parsedParcel.getAnomaly()
                                == ReplyParcelAnomaly.CREATION_DATETIME_OUTSIDE_KEYSTORE) {
                            medium.add(CODE_GENERATE_KEY_CREATION_LEVEL);
                            items.add(new EvidenceItem(
                                    CODE_GENERATE_KEY_CREATION_LEVEL,
                                    EvidenceItem.SourceLayer.HARDWARE,
                                    "keystore2:IKeystoreSecurityLevel.generateKey",
                                    parsedParcel.getDetail(),
                                    FAMILY_TEE_TAMPER,
                                    EvidenceItem.Rank.MEDIUM));
                        }
                    } else {
                        lastFailure = parsedParcel.getDetail();
                    }
                } else if (lastFailure == null) {
                    lastFailure = "generate_key_reply_unavailable";
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                lastFailure = "generate_key_reply_err:" + e.getClass().getSimpleName();
            } finally {
                safeDelete(adapter, parcelAlias);
            }
        }

        // 2. API 35+ Post-Processing RkpdProvisioned vs PURPOSE_ATTEST_KEY parity
        if (sdkInt >= 35) {
            String ppPrefix = "riskengine_ks2_pp_" + nonce;
            try {
                PostProcessingSessionData ppData =
                        adapter.collectPostProcessingSamples(ppPrefix, DEFAULT_POST_PROCESSING_PAIRS);
                if (ppData != null) {
                    postResult = evaluatePostProcessing(ppData);
                    if (postResult.isMeasurementAvailable()
                            || postResult.getAnomaly()
                                    == PostProcessingAnomaly.ROOT_OF_TRUST_DIVERGENCE) {
                        anyUsable = true;
                        if (postResult.getAnomaly()
                                == PostProcessingAnomaly.ROOT_OF_TRUST_DIVERGENCE) {
                            strong.add(CODE_POST_PROCESSING_ROT_DIVERGENCE);
                            items.add(new EvidenceItem(
                                    CODE_POST_PROCESSING_ROT_DIVERGENCE,
                                    EvidenceItem.SourceLayer.HARDWARE,
                                    EnumSet.of(
                                            EvidenceItem.SourceLayer.HARDWARE,
                                            EvidenceItem.SourceLayer.JAVA),
                                    "keystore2:RkpdProvisioned_vs_UserGenerated",
                                    postResult.getDetail(),
                                    FAMILY_TEE_TAMPER,
                                    EvidenceItem.Rank.STRONG));
                        } else if (postResult.getAnomaly()
                                == PostProcessingAnomaly.TIMING_DETECTED) {
                            medium.add(CODE_POST_PROCESSING_LATENCY);
                            items.add(new EvidenceItem(
                                    CODE_POST_PROCESSING_LATENCY,
                                    EvidenceItem.SourceLayer.HARDWARE,
                                    "keystore2:KeystorePostProcessor",
                                    postResult.getDetail(),
                                    FAMILY_TEE_TAMPER,
                                    EvidenceItem.Rank.MEDIUM));
                        }
                    } else if (lastFailure == null) {
                        lastFailure = postResult.getDetail();
                    }
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                if (lastFailure == null) {
                    lastFailure = "post_processing_err:" + e.getClass().getSimpleName();
                }
            } finally {
                safeDelete(adapter, ppPrefix);
            }
        }

        // 3. Overwrite-readback anti-cache trap & key-lifecycle serial freshness
        String supportAlias = "riskengine_ks2_sup_" + nonce;
        String attackAlias = "riskengine_ks2_ovw_" + nonce;
        String lifecycleAlias = "riskengine_ks2_lc_" + nonce;
        try {
            OverwriteSessionData ovw =
                    adapter.collectOverwriteAndLifecycle(supportAlias, attackAlias, lifecycleAlias);
            if (ovw != null) {
                Boolean staleChain = evaluateOverwriteStaleChain(ovw);
                if (staleChain != null) {
                    anyUsable = true;
                    if (staleChain) {
                        strong.add(CODE_OVERWRITE_STALE_CHAIN);
                        items.add(new EvidenceItem(
                                CODE_OVERWRITE_STALE_CHAIN,
                                EvidenceItem.SourceLayer.HARDWARE,
                                EnumSet.of(
                                        EvidenceItem.SourceLayer.HARDWARE,
                                        EvidenceItem.SourceLayer.JAVA),
                                "keystore2:updateSubcomponent_readback",
                                "retained_prior_attestation_after_overwrite",
                                FAMILY_TEE_TAMPER,
                                EvidenceItem.Rank.STRONG));
                    }
                }
                boolean hasSerialPair = ovw.getFirstLifecycleSerialHex() != null
                        && ovw.getSecondLifecycleSerialHex() != null;
                boolean hasSpkiPair = ovw.getFirstLifecycleSpkiSha256() != null
                        && ovw.getSecondLifecycleSpkiSha256() != null;
                if (hasSerialPair || hasSpkiPair) {
                    anyUsable = true;
                    boolean nonDefaultSerialReused = hasSerialPair
                            && !"1".equals(ovw.getFirstLifecycleSerialHex())
                            && ovw.getFirstLifecycleSerialHex()
                                    .equalsIgnoreCase(ovw.getSecondLifecycleSerialHex());
                    boolean spkiReused = hasSpkiPair
                            && ovw.getFirstLifecycleSpkiSha256()
                                    .equalsIgnoreCase(ovw.getSecondLifecycleSpkiSha256());
                    if (!ovw.isDeleteRemovedAlias() || spkiReused || nonDefaultSerialReused) {
                        medium.add(CODE_LIFECYCLE_STALE_SERIAL);
                        items.add(new EvidenceItem(
                                CODE_LIFECYCLE_STALE_SERIAL,
                                EvidenceItem.SourceLayer.JAVA,
                                "AndroidKeyStore:delete_regenerate",
                                "deleteRemoved=" + ovw.isDeleteRemovedAlias()
                                        + ",spkiReused=" + spkiReused
                                        + ",serialReused=" + nonDefaultSerialReused,
                                FAMILY_TEE_TAMPER,
                                EvidenceItem.Rank.MEDIUM));
                    }
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            if (lastFailure == null) {
                lastFailure = "overwrite_probe_err:" + e.getClass().getSimpleName();
            }
        } finally {
            safeDelete(adapter, supportAlias);
            safeDelete(adapter, attackAlias);
            safeDelete(adapter, lifecycleAlias);
        }

        // 4. StrongBox hardware constraints & timing tripwires
        String sbPrefix = "riskengine_sb_" + nonce;
        try {
            StrongBoxObservation sb = adapter.collectStrongBoxObservation(sbPrefix);
            if (sb != null) {
                if (!sb.isAdvertised()) {
                    anyUsable = true;
                } else {
                    boolean evaluated = evaluateStrongBoxObservation(sb, strong, medium, items);
                    if (evaluated) {
                        anyUsable = true;
                    } else if (lastFailure == null && sb.getUnavailableDetail() != null) {
                        lastFailure = sb.getUnavailableDetail();
                    }
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            if (lastFailure == null) {
                lastFailure = "strongbox_probe_err:" + e.getClass().getSimpleName();
            }
        } finally {
            safeDelete(adapter, sbPrefix);
        }

        return new ProbeResult(
                anyUsable,
                anyUsable ? null : (lastFailure == null ? "keystore2_deep_unavailable" : lastFailure),
                strong,
                medium,
                items,
                parsedParcel,
                postResult);
    }

    /**
     * Parses a marshalled {@code IKeystoreSecurityLevel.generateKey} reply parcel and verifies the
     * trailing {@code TAG_USER_ID (0x300001F5)} at {@code SECURITY_LEVEL_SOFTWARE (0)}.
     */
    public static ReplyParcelParseResult parseGenerateKeyReplyParcel(byte[] rawReply) {
        if (rawReply == null || rawReply.length < 4) {
            return new ReplyParcelParseResult(
                    false, -1, null, null, null, null, ReplyParcelAnomaly.NONE, "empty_reply_parcel");
        }
        try {
            LittleEndianParcelReader reader = new LittleEndianParcelReader(rawReply);
            int exceptionCode = reader.readInt();
            if (exceptionCode != 0) {
                return new ReplyParcelParseResult(
                        false,
                        -1,
                        null,
                        null,
                        null,
                        null,
                        ReplyParcelAnomaly.NONE,
                        "unexpected_exception_code=" + exceptionCode);
            }
            reader.expectNonNull("key_metadata");
            int metadataEnd = reader.readParcelableEnd();
            if (metadataEnd > rawReply.length) {
                throw new IllegalArgumentException("key_metadata_end_out_of_bounds=" + metadataEnd);
            }
            reader.expectNonNull("key_descriptor");
            int descriptorEnd = reader.readParcelableEnd();
            reader.skipTo(descriptorEnd, "key_descriptor");
            int keySecurityLevel = reader.readInt();
            int authCount = reader.readInt();
            if (authCount < 0 || authCount > MAX_AUTHORIZATION_COUNT) {
                throw new IllegalArgumentException("authorization_count_out_of_range=" + authCount);
            }
            List<ReplyAuthorization> authorizations = new ArrayList<>(authCount);
            for (int i = 0; i < authCount; i++) {
                authorizations.add(readAuthorization(reader));
            }

            Integer certLen = null;
            Integer chainLen = null;
            Long modTimeMs = null;
            try {
                certLen = reader.skipNullableByteArray("certificate");
                chainLen = reader.skipNullableByteArray("certificate_chain");
                modTimeMs = reader.readLong();
            } catch (RuntimeException ignored) {
                // Tail fields beyond authorizations are optional for the TAG_USER_ID check
            }

            ReplyParcelAnomaly anomaly = classifyReplyAuthorizations(authorizations);
            String lastDesc = authorizations.isEmpty()
                    ? "none"
                    : authorizations.get(authorizations.size() - 1).describe();
            String detail = "keySecurityLevel=" + keySecurityLevel
                    + ";authCount=" + authCount
                    + ";lastAuth=" + lastDesc
                    + ";anomaly=" + anomaly.name();
            return new ReplyParcelParseResult(
                    true,
                    keySecurityLevel,
                    authorizations,
                    certLen,
                    chainLen,
                    modTimeMs,
                    anomaly,
                    detail);
        } catch (RuntimeException e) {
            return new ReplyParcelParseResult(
                    false,
                    -1,
                    null,
                    null,
                    null,
                    null,
                    ReplyParcelAnomaly.NONE,
                    "parse_failed:" + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
        }
    }

    /** Classifies StrongBox key-generation failure by rejecting layer (Framework vs Keystore/HAL). */
    public static StrongBoxAcceptance classifyStrongBoxAcceptance(Throwable failure) {
        if (failure == null) {
            return StrongBoxAcceptance.ACCEPTED;
        }
        if (failure instanceof InvalidAlgorithmParameterException) {
            return StrongBoxAcceptance.REFUSED_BY_FRAMEWORK;
        }
        if (failure instanceof ProviderException) {
            return StrongBoxAcceptance.REFUSED_BY_KEYSTORE;
        }
        return StrongBoxAcceptance.INCONCLUSIVE;
    }

    /** Evaluates API 35+ post-processing split-path data into a deterministic classification. */
    public static PostProcessingResult evaluatePostProcessing(PostProcessingSessionData data) {
        if (data == null) {
            return new PostProcessingResult(
                    false,
                    PostProcessingAnomaly.UNMEASURABLE,
                    0,
                    null,
                    null,
                    null,
                    null,
                    null,
                    "session_data_null");
        }
        PostProcessingPathSample warmup = data.getWarmupSample();
        if (warmup != null && !warmup.isSuccess() && isRkpdRelatedFailure(warmup.getFailureSummary())) {
            return new PostProcessingResult(
                    false,
                    PostProcessingAnomaly.RKP_UNAVAILABLE,
                    0,
                    null,
                    null,
                    null,
                    null,
                    null,
                    "rkp_only_hard_failure:" + warmup.getFailureSummary());
        }
        if (!data.isAttestKeyProvisioned()) {
            return new PostProcessingResult(
                    false,
                    PostProcessingAnomaly.UNMEASURABLE,
                    0,
                    null,
                    null,
                    null,
                    null,
                    null,
                    "purpose_attest_key_unavailable");
        }

        Boolean rkpObserved = warmup != null && warmup.isSuccess()
                ? warmup.getRkpProvisioningInfoPresent()
                : null;
        AttestationRecord.RootOfTrust rkpRot = null;
        AttestationRecord.RootOfTrust attestKeyRot = null;
        List<Double> rkpLatencies = new ArrayList<>();
        List<Double> attestKeyLatencies = new ArrayList<>();

        int pairLimit = Math.min(data.getRkpSamples().size(), data.getAttestKeySamples().size());
        for (int i = 0; i < pairLimit; i++) {
            PostProcessingPathSample rkp = data.getRkpSamples().get(i);
            PostProcessingPathSample ak = data.getAttestKeySamples().get(i);
            if (rkp != null && ak != null && rkp.isSuccess() && ak.isSuccess()) {
                rkpLatencies.add(rkp.getElapsedMillis());
                attestKeyLatencies.add(ak.getElapsedMillis());
                if (rkpRot == null && rkp.getRootOfTrust() != null) {
                    rkpRot = rkp.getRootOfTrust();
                }
                if (attestKeyRot == null && ak.getRootOfTrust() != null) {
                    attestKeyRot = ak.getRootOfTrust();
                }
                if (rkpObserved == null && rkp.getRkpProvisioningInfoPresent() != null) {
                    rkpObserved = rkp.getRkpProvisioningInfoPresent();
                }
            }
        }

        List<String> divergence = diffRootOfTrust(rkpRot, attestKeyRot);
        int pairedCount = Math.min(rkpLatencies.size(), attestKeyLatencies.size());
        Double medRkp = medianOf(rkpLatencies);
        Double medAk = medianOf(attestKeyLatencies);
        Double deltaMs = (medRkp != null && medAk != null) ? (medRkp - medAk) : null;
        Double madMs = pairedDiffMad(rkpLatencies, attestKeyLatencies);

        PostProcessingAnomaly anomaly = classifyPostProcessingAnomaly(
                pairedCount, deltaMs, divergence, madMs, rkpObserved);
        String detail = String.format(
                Locale.ROOT,
                "kind=%s,pairs=%d,medRkp=%s,medAttestKey=%s,delta=%s,mad=%s,divergence=%s",
                anomaly.name(),
                pairedCount,
                formatDouble(medRkp),
                formatDouble(medAk),
                formatDouble(deltaMs),
                formatDouble(madMs),
                divergence);
        return new PostProcessingResult(
                pairedCount > 0,
                anomaly,
                pairedCount,
                medRkp,
                medAk,
                deltaMs,
                madMs,
                divergence,
                detail);
    }

    /**
     * Returns {@code Boolean.TRUE} when prior attested certificates persist after overwrite,
     * {@code Boolean.FALSE} when marker certificate cleanly replaced the chain, or {@code null}
     * when observability preconditions were not met.
     */
    public static Boolean evaluateOverwriteStaleChain(OverwriteSessionData data) {
        if (data == null
                || !data.isSupportGateClean()
                || !data.isUpdateSucceeded()
                || data.getPriorAttestedChainDer().isEmpty()
                || data.getPostUpdateSnapshots().isEmpty()) {
            return null;
        }
        Set<String> priorHashes = new LinkedHashSet<>();
        for (byte[] der : data.getPriorAttestedChainDer()) {
            priorHashes.add(sha256Hex(der));
        }
        PostUpdateSnapshot finalSnap =
                data.getPostUpdateSnapshots().get(data.getPostUpdateSnapshots().size() - 1);
        for (byte[] postDer : finalSnap.getFullChainDer()) {
            if (priorHashes.contains(sha256Hex(postDer))) {
                return Boolean.TRUE;
            }
        }
        return finalSnap.isLeafMatchesMarker() ? Boolean.FALSE : null;
    }

    private static boolean evaluateStrongBoxObservation(
            StrongBoxObservation sb,
            Set<String> strong,
            Set<String> medium,
            List<EvidenceItem> items) {
        boolean anySignal = sb.getKeyInfoConfirmedStrongBox() != null
                || sb.getAttestedLevel() != AttestationRecord.SecurityLevel.UNKNOWN
                || sb.getRsa4096Acceptance() != StrongBoxAcceptance.INCONCLUSIVE
                || sb.getSecp521r1Acceptance() != StrongBoxAcceptance.INCONCLUSIVE;
        if (!anySignal) {
            return false;
        }

        AttestationRecord.SecurityLevel attested = sb.getAttestedLevel();
        Boolean keyInfoStrongBox = sb.getKeyInfoConfirmedStrongBox();
        if (Boolean.TRUE.equals(keyInfoStrongBox)
                && attested != AttestationRecord.SecurityLevel.UNKNOWN
                && attested != AttestationRecord.SecurityLevel.STRONGBOX) {
            strong.add(CODE_STRONGBOX_LEVEL_MISMATCH);
            items.add(new EvidenceItem(
                    CODE_STRONGBOX_LEVEL_MISMATCH,
                    EvidenceItem.SourceLayer.HARDWARE,
                    EnumSet.of(EvidenceItem.SourceLayer.HARDWARE, EvidenceItem.SourceLayer.JAVA),
                    "StrongBox:KeyInfo_vs_Attestation",
                    "keyInfo=STRONGBOX,attested=" + attested.name(),
                    FAMILY_TEE_TAMPER,
                    EvidenceItem.Rank.STRONG));
        } else if (Boolean.FALSE.equals(keyInfoStrongBox)
                && attested == AttestationRecord.SecurityLevel.STRONGBOX) {
            strong.add(CODE_STRONGBOX_LEVEL_MISMATCH);
            items.add(new EvidenceItem(
                    CODE_STRONGBOX_LEVEL_MISMATCH,
                    EvidenceItem.SourceLayer.HARDWARE,
                    EnumSet.of(EvidenceItem.SourceLayer.HARDWARE, EvidenceItem.SourceLayer.JAVA),
                    "StrongBox:KeyInfo_vs_Attestation",
                    "keyInfo=NOT_STRONGBOX,attested=STRONGBOX",
                    FAMILY_TEE_TAMPER,
                    EvidenceItem.Rank.STRONG));
        }

        List<String> softIndicators = new ArrayList<>();
        if (sb.getRsa4096Acceptance() == StrongBoxAcceptance.ACCEPTED) {
            softIndicators.add("rsa4096=ACCEPTED");
        }
        if (sb.getSecp521r1Acceptance() == StrongBoxAcceptance.ACCEPTED) {
            softIndicators.add("secp521r1=ACCEPTED");
        }
        if (sb.isKeyInfoConfirmedStrongBox()) {
            Integer signUs = sb.getMedianSigningMicros();
            if (signUs != null && signUs >= 0 && signUs < STRONGBOX_SIGNING_TRIPWIRE_MICROS) {
                softIndicators.add("signUs=" + signUs + "<" + STRONGBOX_SIGNING_TRIPWIRE_MICROS);
            }
            Integer keygenMs = sb.getKeygenMillis();
            if (keygenMs != null && keygenMs >= 0 && keygenMs < STRONGBOX_KEYGEN_TRIPWIRE_MILLIS) {
                softIndicators.add("keygenMs=" + keygenMs + "<" + STRONGBOX_KEYGEN_TRIPWIRE_MILLIS);
            }
        }
        if (!softIndicators.isEmpty()) {
            String joined = joinStrings(softIndicators, ";");
            medium.add(CODE_SOFT_STRONGBOX);
            items.add(new EvidenceItem(
                    CODE_SOFT_STRONGBOX,
                    EvidenceItem.SourceLayer.HARDWARE,
                    "StrongBox:constraints",
                    joined
                            + ";rsa4096=" + sb.getRsa4096Acceptance().name()
                            + ";p521=" + sb.getSecp521r1Acceptance().name(),
                    FAMILY_TEE_TAMPER,
                    EvidenceItem.Rank.MEDIUM));
        }
        return true;
    }

    private static ReplyAuthorization readAuthorization(LittleEndianParcelReader reader) {
        reader.expectNonNull("authorization");
        int authEnd = reader.readParcelableEnd();
        int securityLevel = reader.readInt();
        reader.expectNonNull("key_parameter");
        int paramEnd = reader.readParcelableEnd();
        if (paramEnd > authEnd) {
            throw new IllegalArgumentException("key_parameter_overruns_authorization");
        }
        int tag = reader.readInt();
        reader.expectNonNull("key_parameter_value");
        int valueTag = reader.readInt();
        Long scalar = null;
        Integer blobLen = null;
        if (valueTag >= 0 && valueTag <= 11) {
            scalar = (long) reader.readInt();
        } else if (valueTag == 12 || valueTag == 13) {
            scalar = reader.readLong();
        } else if (valueTag == 14) {
            blobLen = reader.skipByteArray("key_parameter_blob");
        }
        reader.skipTo(paramEnd, "key_parameter");
        reader.skipTo(authEnd, "authorization");
        return new ReplyAuthorization(securityLevel, tag, valueTag, scalar, blobLen);
    }

    private static ReplyParcelAnomaly classifyReplyAuthorizations(List<ReplyAuthorization> auths) {
        if (auths == null || auths.isEmpty()) {
            return ReplyParcelAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE;
        }
        ReplyAuthorization last = auths.get(auths.size() - 1);
        if (last.getTag() != TAG_USER_ID || last.getSecurityLevel() != SECURITY_LEVEL_SOFTWARE) {
            return ReplyParcelAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE;
        }
        for (ReplyAuthorization auth : auths) {
            if (auth.getTag() == TAG_CREATION_DATETIME
                    && auth.getSecurityLevel() != SECURITY_LEVEL_KEYSTORE) {
                return ReplyParcelAnomaly.CREATION_DATETIME_OUTSIDE_KEYSTORE;
            }
        }
        return ReplyParcelAnomaly.NONE;
    }

    private static PostProcessingAnomaly classifyPostProcessingAnomaly(
            int pairedSampleCount,
            Double deltaMillis,
            List<String> divergence,
            Double dispersionMillis,
            Boolean rkpChainObserved) {
        if (divergence != null && !divergence.isEmpty()) {
            return PostProcessingAnomaly.ROOT_OF_TRUST_DIVERGENCE;
        }
        if (pairedSampleCount < POST_PROCESSING_MIN_PAIRED_SAMPLES || deltaMillis == null) {
            return PostProcessingAnomaly.UNMEASURABLE;
        }
        boolean significantStrong = dispersionMillis == null
                || dispersionMillis <= 0.0
                || deltaMillis >= dispersionMillis * POST_PROCESSING_DISPERSION_MULTIPLIER;
        if (deltaMillis >= POST_PROCESSING_DELTA_FLOOR_MS && significantStrong) {
            return PostProcessingAnomaly.TIMING_DETECTED;
        }
        boolean significantSuspect = dispersionMillis == null
                || dispersionMillis <= 0.0
                || deltaMillis >= dispersionMillis * POST_PROCESSING_SUSPECT_DISPERSION_MULTIPLIER;
        if (Boolean.FALSE.equals(rkpChainObserved)) {
            return PostProcessingAnomaly.RKP_FALLBACK_INCONCLUSIVE;
        }
        if (deltaMillis >= POST_PROCESSING_SUSPECT_DELTA_FLOOR_MS && significantSuspect) {
            return PostProcessingAnomaly.TIMING_SUSPECT;
        }
        return PostProcessingAnomaly.NONE;
    }

    private static List<String> diffRootOfTrust(
            AttestationRecord.RootOfTrust rkpRot,
            AttestationRecord.RootOfTrust attestKeyRot) {
        if (rkpRot == null || attestKeyRot == null) {
            return Collections.emptyList();
        }
        List<String> diffs = new ArrayList<>();
        if (rkpRot.isDeviceLocked() != attestKeyRot.isDeviceLocked()) {
            diffs.add("deviceLocked:" + rkpRot.isDeviceLocked() + "!=" + attestKeyRot.isDeviceLocked());
        }
        if (rkpRot.getVerifiedBootState() != AttestationRecord.VerifiedBootState.UNKNOWN
                && attestKeyRot.getVerifiedBootState() != AttestationRecord.VerifiedBootState.UNKNOWN
                && rkpRot.getVerifiedBootState() != attestKeyRot.getVerifiedBootState()) {
            diffs.add("verifiedBootState:"
                    + rkpRot.getVerifiedBootState().name()
                    + "!="
                    + attestKeyRot.getVerifiedBootState().name());
        }
        return diffs;
    }

    static boolean isRkpdRelatedFailure(String summary) {
        if (summary == null) {
            return false;
        }
        String lower = summary.toLowerCase(Locale.ROOT);
        return lower.contains("out_of_keys")
                || lower.contains("outofkeys")
                || lower.contains("pending_internet_connectivity")
                || lower.contains("requires_system_upgrade")
                || lower.contains("remotely_provisioned")
                || lower.contains("rkpd")
                || lower.contains("rkp");
    }

    private static Double medianOf(List<Double> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int mid = sorted.size() / 2;
        if ((sorted.size() & 1) == 1) {
            return sorted.get(mid);
        }
        return (sorted.get(mid - 1) + sorted.get(mid)) / 2.0;
    }

    private static Double pairedDiffMad(List<Double> rkp, List<Double> ak) {
        int n = Math.min(rkp.size(), ak.size());
        if (n < POST_PROCESSING_MIN_PAIRED_SAMPLES) {
            return null;
        }
        List<Double> diffs = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            diffs.add(rkp.get(i) - ak.get(i));
        }
        List<Double> sortedDiffs = new ArrayList<>(diffs);
        Collections.sort(sortedDiffs);
        double median = sortedDiffs.get(sortedDiffs.size() / 2);
        List<Double> deviations = new ArrayList<>(n);
        for (double d : diffs) {
            deviations.add(Math.abs(d - median));
        }
        Collections.sort(deviations);
        return deviations.get(deviations.size() / 2);
    }

    private static String formatDouble(Double val) {
        return val == null ? "n/a" : String.format(Locale.ROOT, "%.2f", val);
    }

    private static String joinStrings(List<String> list, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) {
                sb.append(sep);
            }
            sb.append(list.get(i));
        }
        return sb.toString();
    }

    static String sha256Hex(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input == null ? new byte[0] : input);
            return AttestationRecord.toLowerHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static X509Certificate loadMarkerCertificate() throws Exception {
        byte[] der = Base64.getDecoder().decode(MARKER_CERT_BASE64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private static void safeDelete(Keystore2DeepAdapter adapter, String alias) {
        if (adapter == null || alias == null) {
            return;
        }
        try {
            adapter.deleteAlias(alias);
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Never throw out of finally
        }
    }

    /** Overflow-safe little-endian reader for marshalled stable-AIDL Binder reply parcels. */
    private static final class LittleEndianParcelReader {
        private final byte[] bytes;
        private int position;

        LittleEndianParcelReader(byte[] bytes) {
            this.bytes = bytes;
            this.position = 0;
        }

        int readInt() {
            if (position < 0 || position > bytes.length - 4) {
                throw new IllegalArgumentException("int_out_of_bounds@" + position);
            }
            int v = (bytes[position] & 0xFF)
                    | ((bytes[position + 1] & 0xFF) << 8)
                    | ((bytes[position + 2] & 0xFF) << 16)
                    | ((bytes[position + 3] & 0xFF) << 24);
            position += 4;
            return v;
        }

        long readLong() {
            if (position < 0 || position > bytes.length - 8) {
                throw new IllegalArgumentException("long_out_of_bounds@" + position);
            }
            long v = 0L;
            for (int i = 0; i < 8; i++) {
                v |= ((long) (bytes[position + i] & 0xFF)) << (i * 8);
            }
            position += 8;
            return v;
        }

        void expectNonNull(String label) {
            int marker = readInt();
            if (marker != NON_NULL_MARKER) {
                throw new IllegalArgumentException(label + "_marker=" + marker);
            }
        }

        int readParcelableEnd() {
            int start = position;
            int size = readInt();
            if (size < 4 || size > bytes.length - start) {
                throw new IllegalArgumentException("parcelable_size=" + size + "@" + start);
            }
            return start + size;
        }

        void skipTo(int end, String label) {
            if (end < position || end > bytes.length) {
                throw new IllegalArgumentException(label + "_end=" + end + "@" + position);
            }
            position = end;
        }

        int skipByteArray(String label) {
            int len = readInt();
            if (len < 0 || len > bytes.length - position) {
                throw new IllegalArgumentException(label + "_len=" + len);
            }
            int aligned = align4(position + len);
            skipTo(aligned, label);
            return len;
        }

        Integer skipNullableByteArray(String label) {
            int len = readInt();
            if (len == NULL_LENGTH) {
                return null;
            }
            if (len < 0 || len > bytes.length - position) {
                throw new IllegalArgumentException(label + "_len=" + len);
            }
            int aligned = align4(position + len);
            skipTo(aligned, label);
            return len;
        }

        private int align4(int offset) {
            if (offset < 0 || offset > Integer.MAX_VALUE - 3) {
                throw new IllegalArgumentException("align_overflow");
            }
            return (offset + 3) & ~3;
        }
    }

    /**
     * Production Android Keystore2 / AndroidKeyStore runtime implementation.
     * Communicates over VINTF-stable Binder wire transactions via {@link Keystore2ParcelClient}
     * (zero blocked hidden-API reflection) and cleans up every provisioned alias/descriptor in
     * {@code finally}.
     */
    private static final class AndroidKeystore2DeepAdapter implements Keystore2DeepAdapter {
        private final Context appContext;
        private final AttestationCapability.AttestationSnapshot priorSnapshot;
        private final AttestationExtensionParser extensionParser = new AttestationExtensionParser();
        private final SecureRandom secureRandom = new SecureRandom();
        private final Set<String> touchedAliases =
                Collections.synchronizedSet(new LinkedHashSet<String>());

        AndroidKeystore2DeepAdapter(
                Context context, AttestationCapability.AttestationSnapshot priorSnapshot) {
            this.appContext = context != null && context.getApplicationContext() != null
                    ? context.getApplicationContext()
                    : context;
            this.priorSnapshot = priorSnapshot;
        }

        @Override
        public int getSdkInt() {
            return Build.VERSION.SDK_INT;
        }

        @Override
        public byte[] captureGenerateKeyReplyParcel(String alias) throws Exception {
            touchedAliases.add(alias);
            IBinder serviceBinder = Keystore2ParcelClient.lookupServiceBinder();
            if (serviceBinder == null) {
                return null;
            }
            IBinder secLevelBinder = Keystore2ParcelClient.getSecurityLevel(
                    serviceBinder, SECURITY_LEVEL_TRUSTED_ENVIRONMENT);
            if (secLevelBinder == null) {
                return null;
            }

            Keystore2ParcelClient.KeyDescriptor descriptor =
                    Keystore2ParcelClient.KeyDescriptor.app(alias);
            try {
                byte[] challenge = new byte[32];
                secureRandom.nextBytes(challenge);
                List<Keystore2ParcelClient.KeyParam> params = buildSigningKeyParams(challenge);
                Keystore2ParcelClient.GenerateKeyReply reply = Keystore2ParcelClient.generateKey(
                        secLevelBinder, descriptor, null, params, 0, new byte[0]);
                return reply != null ? reply.rawReplyBytes : null;
            } finally {
                deleteViaKeystore2(serviceBinder, descriptor);
                deleteAliasFromJavaKeyStore(alias);
            }
        }

        @Override
        public PostProcessingSessionData collectPostProcessingSamples(
                String aliasPrefix, int pairCount) throws Exception {
            IBinder serviceBinder = Keystore2ParcelClient.lookupServiceBinder();
            if (serviceBinder == null) {
                return null;
            }
            IBinder secLevelBinder = Keystore2ParcelClient.getSecurityLevel(
                    serviceBinder, SECURITY_LEVEL_TRUSTED_ENVIRONMENT);
            if (secLevelBinder == null) {
                return null;
            }

            List<Keystore2ParcelClient.KeyDescriptor> descriptorsToDelete = new ArrayList<>();
            List<String> aliasesToDelete = new ArrayList<>();
            try {
                String warmupAlias = aliasPrefix + "_warmup";
                trackAlias(warmupAlias, aliasesToDelete);
                PostProcessingPathSample warmup = sampleTimedGenerateKey(
                        serviceBinder, secLevelBinder, warmupAlias, null, descriptorsToDelete);
                if (!warmup.isSuccess() && isRkpdRelatedFailure(warmup.getFailureSummary())) {
                    return new PostProcessingSessionData(
                            warmup, false, Collections.<PostProcessingPathSample>emptyList(),
                            Collections.<PostProcessingPathSample>emptyList());
                }

                String akAlias = aliasPrefix + "_ak";
                trackAlias(akAlias, aliasesToDelete);
                Keystore2ParcelClient.KeyDescriptor attestKeyDesc =
                        provisionAttestKey(secLevelBinder, akAlias, descriptorsToDelete);
                if (attestKeyDesc == null) {
                    return new PostProcessingSessionData(
                            warmup, false, Collections.<PostProcessingPathSample>emptyList(),
                            Collections.<PostProcessingPathSample>emptyList());
                }

                List<PostProcessingPathSample> rkpSamples = new ArrayList<>(pairCount);
                List<PostProcessingPathSample> akSamples = new ArrayList<>(pairCount);
                for (int i = 0; i < pairCount; i++) {
                    String rkpAlias = aliasPrefix + "_rkp_" + i;
                    String usrAlias = aliasPrefix + "_usr_" + i;
                    trackAlias(rkpAlias, aliasesToDelete);
                    trackAlias(usrAlias, aliasesToDelete);
                    // Alternate order across rounds to eliminate warm-up / scheduling bias (§8.1)
                    if ((i & 1) == 0) {
                        rkpSamples.add(sampleTimedGenerateKey(
                                serviceBinder, secLevelBinder, rkpAlias, null, descriptorsToDelete));
                        akSamples.add(sampleTimedGenerateKey(
                                serviceBinder, secLevelBinder, usrAlias, attestKeyDesc, descriptorsToDelete));
                    } else {
                        PostProcessingPathSample akSample = sampleTimedGenerateKey(
                                serviceBinder, secLevelBinder, usrAlias, attestKeyDesc, descriptorsToDelete);
                        PostProcessingPathSample rkpSample = sampleTimedGenerateKey(
                                serviceBinder, secLevelBinder, rkpAlias, null, descriptorsToDelete);
                        rkpSamples.add(rkpSample);
                        akSamples.add(akSample);
                    }
                }
                return new PostProcessingSessionData(warmup, true, rkpSamples, akSamples);
            } finally {
                for (Keystore2ParcelClient.KeyDescriptor desc : descriptorsToDelete) {
                    deleteViaKeystore2(serviceBinder, desc);
                }
                for (String a : aliasesToDelete) {
                    deleteAliasFromJavaKeyStore(a);
                }
            }
        }

        @Override
        public OverwriteSessionData collectOverwriteAndLifecycle(
                String supportAlias, String attackAlias, String lifecycleAlias) throws Exception {
            touchedAliases.add(supportAlias);
            touchedAliases.add(attackAlias);
            touchedAliases.add(lifecycleAlias);

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            X509Certificate marker = loadMarkerCertificate();
            byte[] markerDer = marker.getEncoded();

            String firstSerial = null;
            String secondSerial = null;
            String firstSpki = null;
            String secondSpki = null;
            boolean deleteRemoved = true;
            try {
                // Pass distinct non-default serials (AOSP defaults to BigInteger.ONE when unset)
                generateJavaEcKey(
                        lifecycleAlias, null, false, BigInteger.valueOf(0x52451001L));
                Certificate c1 = ks.getCertificate(lifecycleAlias);
                if (c1 instanceof X509Certificate) {
                    firstSerial = ((X509Certificate) c1).getSerialNumber().toString(16);
                    if (c1.getPublicKey() != null && c1.getPublicKey().getEncoded() != null) {
                        firstSpki = sha256Hex(c1.getPublicKey().getEncoded());
                    }
                }
                ks.deleteEntry(lifecycleAlias);
                deleteRemoved = !ks.containsAlias(lifecycleAlias);
                generateJavaEcKey(
                        lifecycleAlias, null, false, BigInteger.valueOf(0x52451002L));
                Certificate c2 = ks.getCertificate(lifecycleAlias);
                if (c2 instanceof X509Certificate) {
                    secondSerial = ((X509Certificate) c2).getSerialNumber().toString(16);
                    if (c2.getPublicKey() != null && c2.getPublicKey().getEncoded() != null) {
                        secondSpki = sha256Hex(c2.getPublicKey().getEncoded());
                    }
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Lifecycle sub-check optional if signing keygen unavailable
            } finally {
                deleteAliasFromJavaKeyStore(lifecycleAlias);
            }

            boolean supportClean = false;
            List<byte[]> priorChain = Collections.emptyList();
            boolean updateSucceeded = false;
            List<PostUpdateSnapshot> snapshots = new ArrayList<>();
            try {
                ks.setCertificateEntry(supportAlias, marker);
                PostUpdateSnapshot supSnap = readPostUpdateSnapshot(ks, supportAlias, markerDer);
                supportClean = supSnap != null && supSnap.isLeafMatchesMarker();
                if (supportClean) {
                    byte[] challenge = new byte[32];
                    secureRandom.nextBytes(challenge);
                    generateJavaEcKey(attackAlias, challenge, false, null);
                    Certificate[] rawPrior = ks.getCertificateChain(attackAlias);
                    if (rawPrior != null && rawPrior.length > 0) {
                        List<byte[]> encoded = new ArrayList<>(rawPrior.length);
                        for (Certificate c : rawPrior) {
                            encoded.add(c.getEncoded());
                        }
                        priorChain = encoded;
                        Key existingKey = ks.getKey(attackAlias, null);
                        if (existingKey != null) {
                            ks.setKeyEntry(attackAlias, existingKey, null, new Certificate[]{marker});
                            updateSucceeded = true;
                            PostUpdateSnapshot s1 = readPostUpdateSnapshot(ks, attackAlias, markerDer);
                            PostUpdateSnapshot s2 = readPostUpdateSnapshot(ks, attackAlias, markerDer);
                            if (s1 != null) {
                                snapshots.add(s1);
                            }
                            if (s2 != null) {
                                snapshots.add(s2);
                            }
                        }
                    }
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Degrade cleanly if overwrite subcomponent unsupported
            } finally {
                deleteAliasFromJavaKeyStore(supportAlias);
                deleteAliasFromJavaKeyStore(attackAlias);
            }

            return new OverwriteSessionData(
                    supportClean,
                    priorChain,
                    updateSucceeded,
                    snapshots,
                    firstSerial,
                    secondSerial,
                    firstSpki,
                    secondSpki,
                    deleteRemoved);
        }

        @Override
        public StrongBoxObservation collectStrongBoxObservation(String aliasPrefix) throws Exception {
            if (appContext == null || appContext.getPackageManager() == null) {
                return null;
            }
            boolean advertised = appContext.getPackageManager()
                    .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
            if (!advertised) {
                return new StrongBoxObservation(
                        false,
                        null,
                        AttestationRecord.SecurityLevel.UNKNOWN,
                        null,
                        null,
                        StrongBoxAcceptance.INCONCLUSIVE,
                        StrongBoxAcceptance.INCONCLUSIVE,
                        null);
            }

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);

            String infoAlias = aliasPrefix + "_info";
            touchedAliases.add(infoAlias);
            Boolean keyInfoStrongBox = null;
            Integer keygenMs = null;
            Integer signUs = null;
            String unavail = null;
            try {
                long t0 = System.nanoTime();
                generateJavaEcKey(infoAlias, null, true, null);
                keygenMs = (int) Math.max(0L, (System.nanoTime() - t0) / 1_000_000L);
                Key key = ks.getKey(infoAlias, null);
                if (key instanceof PrivateKey) {
                    KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm(), ANDROID_KEYSTORE);
                    KeyInfo ki = kf.getKeySpec(key, KeyInfo.class);
                    if (Build.VERSION.SDK_INT >= 31) {
                        keyInfoStrongBox = ki.getSecurityLevel()
                                == KeyProperties.SECURITY_LEVEL_STRONGBOX;
                    } else {
                        keyInfoStrongBox = isInsideSecureHardwareLegacy(ki);
                    }
                    signUs = measureMedianSigningMicros((PrivateKey) key);
                }
            } catch (StrongBoxUnavailableException e) {
                unavail = "StrongBoxUnavailableException";
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                unavail = e.getClass().getSimpleName();
            } finally {
                deleteAliasFromJavaKeyStore(infoAlias);
            }

            AttestationRecord.SecurityLevel attestedLevel = AttestationRecord.SecurityLevel.UNKNOWN;
            if (priorSnapshot != null
                    && priorSnapshot.isAvailable()
                    && priorSnapshot.isUsedStrongBox()
                    && priorSnapshot.getRecord() != null) {
                attestedLevel = priorSnapshot.getRecord().getAttestationSecurityLevel();
            } else {
                String attAlias = aliasPrefix + "_att";
                touchedAliases.add(attAlias);
                try {
                    byte[] ch = new byte[32];
                    secureRandom.nextBytes(ch);
                    generateJavaEcKey(attAlias, ch, true, null);
                    Certificate[] raw = ks.getCertificateChain(attAlias);
                    if (raw != null && raw.length > 0) {
                        List<X509Certificate> x509s = new ArrayList<>(raw.length);
                        for (Certificate c : raw) {
                            if (c instanceof X509Certificate) {
                                x509s.add((X509Certificate) c);
                            }
                        }
                        AttestationRecord rec = extensionParser.parse(x509s, ch);
                        if (rec.isValid()) {
                            attestedLevel = rec.getAttestationSecurityLevel();
                        }
                    }
                } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                    // Leave UNKNOWN when dedicated StrongBox attestation fails
                } finally {
                    deleteAliasFromJavaKeyStore(attAlias);
                }
            }

            StrongBoxAcceptance rsa4096 = probeStrongBoxRsa4096(aliasPrefix + "_rsa4096");
            StrongBoxAcceptance p521 = probeStrongBoxP521(aliasPrefix + "_p521");

            return new StrongBoxObservation(
                    true,
                    keyInfoStrongBox,
                    attestedLevel,
                    keygenMs,
                    signUs,
                    rsa4096,
                    p521,
                    unavail);
        }

        @Override
        public void deleteAlias(String prefixOrAlias) {
            deleteAliasFromJavaKeyStore(prefixOrAlias);
            List<String> snapshot;
            synchronized (touchedAliases) {
                snapshot = new ArrayList<>(touchedAliases);
            }
            for (String candidate : snapshot) {
                if (candidate != null && candidate.startsWith(prefixOrAlias)) {
                    deleteAliasFromJavaKeyStore(candidate);
                    touchedAliases.remove(candidate);
                }
            }
        }

        private void trackAlias(String alias, List<String> localList) {
            touchedAliases.add(alias);
            localList.add(alias);
        }

        private StrongBoxAcceptance probeStrongBoxRsa4096(String alias) {
            touchedAliases.add(alias);
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setKeySize(4096)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setIsStrongBoxBacked(true)
                        .build();
                kpg.initialize(spec);
                kpg.generateKeyPair();
                return StrongBoxAcceptance.ACCEPTED;
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return classifyStrongBoxAcceptance(e);
            } finally {
                deleteAliasFromJavaKeyStore(alias);
            }
        }

        private StrongBoxAcceptance probeStrongBoxP521(String alias) {
            touchedAliases.add(alias);
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp521r1"))
                        .setDigests(KeyProperties.DIGEST_SHA512)
                        .setIsStrongBoxBacked(true)
                        .build();
                kpg.initialize(spec);
                kpg.generateKeyPair();
                return StrongBoxAcceptance.ACCEPTED;
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return classifyStrongBoxAcceptance(e);
            } finally {
                deleteAliasFromJavaKeyStore(alias);
            }
        }

        private Integer measureMedianSigningMicros(PrivateKey privateKey) {
            try {
                List<Integer> samples = new ArrayList<>(8);
                for (int i = 0; i < 8; i++) {
                    Signature sig = Signature.getInstance("SHA256withECDSA");
                    byte[] msg = ("riskengine_sb_" + i).getBytes(StandardCharsets.UTF_8);
                    long t0 = System.nanoTime();
                    sig.initSign(privateKey);
                    sig.update(msg);
                    sig.sign();
                    samples.add((int) Math.max(0L, (System.nanoTime() - t0) / 1_000L));
                }
                Collections.sort(samples);
                return samples.get(samples.size() / 2);
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                return null;
            }
        }

        private void generateJavaEcKey(
                String alias, byte[] challenge, boolean strongBox, BigInteger serialNumber)
                throws Exception {
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setIsStrongBoxBacked(strongBox);
            if (serialNumber != null) {
                b.setCertificateSerialNumber(serialNumber);
            }
            if (challenge != null) {
                b.setAttestationChallenge(challenge);
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            kpg.initialize(b.build());
            kpg.generateKeyPair();
        }

        private PostUpdateSnapshot readPostUpdateSnapshot(
                KeyStore ks, String alias, byte[] markerDer) {
            try {
                IBinder binder = Keystore2ParcelClient.lookupServiceBinder();
                if (binder != null) {
                    Keystore2ParcelClient.KeyEntryResponse resp = Keystore2ParcelClient.getKeyEntry(
                            binder, Keystore2ParcelClient.KeyDescriptor.app(alias));
                    if (resp != null && resp.metadata != null) {
                        byte[] leaf = resp.metadata.certificate;
                        byte[] chainBlob = resp.metadata.certificateChain;
                        List<byte[]> full = new ArrayList<>();
                        if (leaf != null && leaf.length > 0) {
                            full.add(leaf);
                        }
                        if (chainBlob != null && chainBlob.length > 0) {
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            Collection<? extends Certificate> certs = cf.generateCertificates(
                                    new ByteArrayInputStream(chainBlob));
                            for (Certificate c : certs) {
                                full.add(c.getEncoded());
                            }
                        }
                        boolean matches = (leaf != null && Arrays.equals(leaf, markerDer))
                                || (!full.isEmpty() && Arrays.equals(full.get(0), markerDer));
                        return new PostUpdateSnapshot(full, matches);
                    }
                }
                Certificate[] jChain = ks.getCertificateChain(alias);
                if (jChain == null || jChain.length == 0) {
                    Certificate single = ks.getCertificate(alias);
                    if (single == null) {
                        return null;
                    }
                    jChain = new Certificate[]{single};
                }
                List<byte[]> full = new ArrayList<>(jChain.length);
                for (Certificate c : jChain) {
                    full.add(c.getEncoded());
                }
                boolean matches = !full.isEmpty() && Arrays.equals(full.get(0), markerDer);
                return new PostUpdateSnapshot(full, matches);
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                return null;
            }
        }

        private Keystore2ParcelClient.KeyDescriptor provisionAttestKey(
                IBinder secLevelBinder,
                String alias,
                List<Keystore2ParcelClient.KeyDescriptor> descriptorsToDelete) {
            Keystore2ParcelClient.KeyDescriptor reqDesc =
                    Keystore2ParcelClient.KeyDescriptor.app(alias);
            descriptorsToDelete.add(reqDesc);
            int[][] digestAttempts = new int[][]{{4}, {0}, {}};
            for (int[] digests : digestAttempts) {
                try {
                    List<Keystore2ParcelClient.KeyParam> params = new ArrayList<>();
                    params.add(Keystore2ParcelClient.KeyParam.ofInt(
                            0x10000002, Keystore2ParcelClient.VAL_ALGORITHM, 3));
                    params.add(Keystore2ParcelClient.KeyParam.ofInt(
                            0x30000003, Keystore2ParcelClient.VAL_INTEGER, 256));
                    params.add(Keystore2ParcelClient.KeyParam.ofInt(
                            0x1000000A, Keystore2ParcelClient.VAL_EC_CURVE, 1));
                    params.add(Keystore2ParcelClient.KeyParam.ofInt(
                            0x20000001, Keystore2ParcelClient.VAL_KEY_PURPOSE, 7));
                    if (digests.length > 0) {
                        params.add(Keystore2ParcelClient.KeyParam.ofInt(
                                0x20000005, Keystore2ParcelClient.VAL_DIGEST, digests[0]));
                    }
                    params.add(Keystore2ParcelClient.KeyParam.ofBool(0x700001F7, true));
                    Keystore2ParcelClient.GenerateKeyReply reply = Keystore2ParcelClient.generateKey(
                            secLevelBinder, reqDesc, null, params, 0, new byte[0]);
                    Keystore2ParcelClient.KeyDescriptor retKey =
                            reply != null && reply.metadata != null ? reply.metadata.key : null;
                    if (retKey != null) {
                        descriptorsToDelete.add(retKey);
                        return retKey;
                    }
                    return reqDesc;
                } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                    // Try next parameter combination
                }
            }
            return null;
        }

        private PostProcessingPathSample sampleTimedGenerateKey(
                IBinder serviceBinder,
                IBinder secLevelBinder,
                String alias,
                Keystore2ParcelClient.KeyDescriptor attestKeyDescriptor,
                List<Keystore2ParcelClient.KeyDescriptor> descriptorsToDelete) {
            try {
                Keystore2ParcelClient.KeyDescriptor reqDesc =
                        Keystore2ParcelClient.KeyDescriptor.app(alias);
                descriptorsToDelete.add(reqDesc);
                byte[] challenge = new byte[32];
                secureRandom.nextBytes(challenge);
                List<Keystore2ParcelClient.KeyParam> params = buildSigningKeyParams(challenge);

                long t0 = System.nanoTime();
                Keystore2ParcelClient.GenerateKeyReply reply = Keystore2ParcelClient.generateKey(
                        secLevelBinder, reqDesc, attestKeyDescriptor, params, 0, new byte[0]);
                double elapsedMs = (System.nanoTime() - t0) / 1_000_000.0;

                Keystore2ParcelClient.KeyMetadata meta = reply != null ? reply.metadata : null;
                Keystore2ParcelClient.KeyDescriptor retKey = meta != null ? meta.key : null;
                if (retKey != null) {
                    descriptorsToDelete.add(retKey);
                }
                Keystore2ParcelClient.KeyDescriptor lookupDesc = retKey != null ? retKey : reqDesc;

                Keystore2ParcelClient.KeyEntryResponse entryResp =
                        Keystore2ParcelClient.getKeyEntry(serviceBinder, lookupDesc);
                Keystore2ParcelClient.KeyMetadata entryMeta =
                        entryResp != null && entryResp.metadata != null ? entryResp.metadata : meta;
                byte[] leafBlob = entryMeta != null ? entryMeta.certificate : null;
                byte[] chainBlob = entryMeta != null ? entryMeta.certificateChain : null;

                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                List<X509Certificate> chain = new ArrayList<>();
                if (leafBlob != null && leafBlob.length > 0) {
                    Certificate c = cf.generateCertificate(new ByteArrayInputStream(leafBlob));
                    if (c instanceof X509Certificate) {
                        chain.add((X509Certificate) c);
                    }
                }
                if (chainBlob != null && chainBlob.length > 0) {
                    for (Certificate c : cf.generateCertificates(new ByteArrayInputStream(chainBlob))) {
                        if (c instanceof X509Certificate) {
                            chain.add((X509Certificate) c);
                        }
                    }
                }
                boolean rkpInfoPresent = false;
                for (X509Certificate cert : chain) {
                    if (cert.getExtensionValue(OID_RKP_PROVISIONING_INFO) != null) {
                        rkpInfoPresent = true;
                        break;
                    }
                }
                AttestationRecord.RootOfTrust rot = null;
                if (!chain.isEmpty()) {
                    // Parse full chain root-first so RKP/hardware RootOfTrust on leaf/intermediate is extracted accurately
                    AttestationRecord rec = extensionParser.parse(chain, challenge);
                    rot = rec.getRootOfTrust();
                }
                return PostProcessingPathSample.success(elapsedMs, rot, rkpInfoPresent);
            } catch (Exception | LinkageError | OutOfMemoryError t) {
                String msg = t.getClass().getSimpleName()
                        + (t.getMessage() != null ? ":" + t.getMessage() : "");
                return PostProcessingPathSample.failure(msg);
            }
        }

        private List<Keystore2ParcelClient.KeyParam> buildSigningKeyParams(byte[] challenge) {
            List<Keystore2ParcelClient.KeyParam> params = new ArrayList<>(7);
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x10000002, Keystore2ParcelClient.VAL_ALGORITHM, 3));
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x30000003, Keystore2ParcelClient.VAL_INTEGER, 256));
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x1000000A, Keystore2ParcelClient.VAL_EC_CURVE, 1));
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x20000001, Keystore2ParcelClient.VAL_KEY_PURPOSE, 2));
            params.add(Keystore2ParcelClient.KeyParam.ofInt(
                    0x20000005, Keystore2ParcelClient.VAL_DIGEST, 4));
            params.add(Keystore2ParcelClient.KeyParam.ofBool(0x700001F7, true));
            if (challenge != null) {
                params.add(Keystore2ParcelClient.KeyParam.ofBlob(0x900002C4, challenge));
            }
            return params;
        }
    }

    @SuppressWarnings("deprecation")
    private static boolean isInsideSecureHardwareLegacy(KeyInfo ki) {
        return ki.isInsideSecureHardware();
    }

    static void deleteViaKeystore2(
            IBinder serviceBinder, Keystore2ParcelClient.KeyDescriptor descriptor) {
        if (serviceBinder == null || descriptor == null) {
            return;
        }
        try {
            Keystore2ParcelClient.deleteKey(serviceBinder, descriptor);
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Best-effort cleanup
        }
    }

    static void deleteAliasFromJavaKeyStore(String alias) {
        if (alias == null || alias.isEmpty()) {
            return;
        }
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias);
            }
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Best-effort cleanup
        }
    }
}
