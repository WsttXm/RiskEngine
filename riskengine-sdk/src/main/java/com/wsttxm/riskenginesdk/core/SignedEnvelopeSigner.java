package com.wsttxm.riskenginesdk.core;

import android.content.Context;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import com.wsttxm.riskenginesdk.EnvelopeMode;
import com.wsttxm.riskenginesdk.attestation.AttestationExtensionParser;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskDimension;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;
import com.wsttxm.riskenginesdk.util.RiskReportJsonSerializer;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Dual-mode hardware envelope signer ({@link EnvelopeMode#PERSISTENT_KEY} &amp;
 * {@link EnvelopeMode#FRESH_ATTESTATION}) with strict {@code SOFTWARE_FALLBACK} labeling.
 *
 * <p>Key invariants:
 * <ul>
 *   <li>{@link EnvelopeMode#PERSISTENT_KEY} provisions {@code riskengine_envelope_sign_key} once
 *       (on-SoC hardware TEE &rarr; StrongBox fallback) and caches its {@link PrivateKey} + PEM/DER
 *       certificate chain so subsequent calls perform ONLY {@code SHA256withECDSA} signing
 *       ({@code <10ms} P95).</li>
 *   <li>{@link EnvelopeMode#FRESH_ATTESTATION} generates an ephemeral EC P-256 key with
 *       {@code setAttestationChallenge(serverChallenge)} and unconditionally deletes the alias in
 *       {@code finally}.</li>
 *   <li>Whenever hardware Keystore is unavailable or reports {@code SOFTWARE} backing, emits
 *       {@link SignedRiskEnvelope.AttestationMode#SOFTWARE_FALLBACK} with
 *       {@link AttestationRecord.SecurityLevel#SOFTWARE} — NEVER spoofing hardware backing.</li>
 * </ul></p>
 */
public final class SignedEnvelopeSigner {

    public static final String PERSISTENT_KEY_ALIAS = "riskengine_envelope_sign_key";
    public static final int MIN_CHALLENGE_BYTES = 16;
    public static final int MAX_CHALLENGE_BYTES = 128;

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String EPHEMERAL_ALIAS_PREFIX = "riskengine_ephem_env_";
    private static final int PERSISTENT_INIT_CHALLENGE_BYTES = 32;

    /** Monotonic clock abstraction for deterministic unit/golden-vector testing. */
    public interface MonotonicClock {
        long monotonicMillis();
    }

    /** Material returned by {@link EnvelopeKeyBackend} for signing. */
    public static final class SigningKeyHandle {
        private final PrivateKey privateKey;
        private final List<X509Certificate> certificateChain;
        private final AttestationRecord.SecurityLevel securityLevel;

        public SigningKeyHandle(
                PrivateKey privateKey,
                List<X509Certificate> certificateChain,
                AttestationRecord.SecurityLevel securityLevel) {
            this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
            this.certificateChain = certificateChain == null
                    ? Collections.<X509Certificate>emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(certificateChain));
            this.securityLevel = securityLevel == null
                    ? AttestationRecord.SecurityLevel.SOFTWARE
                    : securityLevel;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public List<X509Certificate> getCertificateChain() {
            return certificateChain;
        }

        public AttestationRecord.SecurityLevel getSecurityLevel() {
            return securityLevel;
        }
    }

    /** Pluggable key backend enabling deterministic pure-JVM unit tests. */
    public interface EnvelopeKeyBackend {
        SigningKeyHandle loadExistingKey(String alias) throws Exception;

        SigningKeyHandle generateSigningKey(
                String alias, byte[] attestationChallenge, boolean strongBox) throws Exception;

        byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes) throws Exception;

        void deleteAlias(String alias);
    }

    private static final class CachedPersistentMaterial {
        final PrivateKey privateKey;
        final AttestationRecord.SecurityLevel securityLevel;
        final List<String> certChainPem;
        final List<byte[]> certChainDer;

        CachedPersistentMaterial(
                PrivateKey privateKey,
                AttestationRecord.SecurityLevel securityLevel,
                List<String> certChainPem,
                List<byte[]> certChainDer) {
            this.privateKey = privateKey;
            this.securityLevel = securityLevel;
            this.certChainPem = certChainPem;
            this.certChainDer = certChainDer;
        }
    }

    public static final MonotonicClock DEFAULT_MONOTONIC_CLOCK = new MonotonicClock() {
        @Override
        public long monotonicMillis() {
            try {
                long elapsed = SystemClock.elapsedRealtime();
                if (elapsed > 0L) {
                    return elapsed;
                }
            } catch (RuntimeException | LinkageError | OutOfMemoryError ignored) {
            }
            return Math.max(0L, TimeUnit.NANOSECONDS.toMillis(System.nanoTime()));
        }
    };

    private final EnvelopeKeyBackend backend;
    private final MonotonicClock monotonicClock;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Object persistentLock = new Object();

    private volatile CachedPersistentMaterial cachedPersistent;
    private volatile boolean strongBoxKnownUnsupported;
    private volatile CachedPersistentMaterial softwareFallbackMaterial;

    public SignedEnvelopeSigner() {
        this(new AndroidKeyStoreEnvelopeBackend(), DEFAULT_MONOTONIC_CLOCK);
    }

    public SignedEnvelopeSigner(EnvelopeKeyBackend backend, MonotonicClock monotonicClock) {
        this.backend = backend == null ? new AndroidKeyStoreEnvelopeBackend() : backend;
        this.monotonicClock = monotonicClock == null ? DEFAULT_MONOTONIC_CLOCK : monotonicClock;
    }

    public static void validateChallenge(byte[] serverChallenge) {
        if (serverChallenge == null) {
            throw new IllegalArgumentException("serverChallenge must not be null");
        }
        if (serverChallenge.length < MIN_CHALLENGE_BYTES
                || serverChallenge.length > MAX_CHALLENGE_BYTES) {
            throw new IllegalArgumentException(
                    "serverChallenge length must be between "
                            + MIN_CHALLENGE_BYTES
                            + " and "
                            + MAX_CHALLENGE_BYTES
                            + " bytes (got "
                            + serverChallenge.length
                            + ")");
        }
    }

    /** Background warm-up hook invoked asynchronously after {@code RiskEngine.init()}. */
    public void warmUpPersistentKeyIfPossible() {
        try {
            getOrCreatePersistentMaterial();
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Best-effort warm-up; signing falls back safely if hardware keystore is absent
        }
    }

    /**
     * Builds the canonical RFC §4.8.3 payload for {@code report} + {@code serverChallenge} and
     * signs it under {@code mode}.
     */
    public SignedRiskEnvelope sign(
            Context context,
            RiskReport report,
            byte[] serverChallenge,
            EnvelopeMode mode) {
        Objects.requireNonNull(report, "report must not be null");
        Objects.requireNonNull(mode, "mode must not be null");
        validateChallenge(serverChallenge);

        byte[] challengeCopy = Arrays.copyOf(serverChallenge, serverChallenge.length);
        String pkg = resolvePackageName(context);
        long monoMs = monotonicClock.monotonicMillis();
        String challengeB64Url = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(challengeCopy);

        JSONObject reportJsonObj = RiskReportJsonSerializer.toJsonObject(report, null);
        String reportSha256 = CanonicalJsonWriter.sha256HexOfCanonicalJson(reportJsonObj);
        List<String> hardTriggers = report.getHardTriggers();

        Map<String, Object> payloadMap = buildPayloadMap(
                pkg,
                report,
                monoMs,
                challengeB64Url,
                hardTriggers,
                reportSha256);
        String canonicalPayloadJson = CanonicalJsonWriter.toCanonicalJson(payloadMap);
        byte[] canonicalPayloadBytes = canonicalPayloadJson.getBytes(StandardCharsets.UTF_8);

        long signStartNanos = System.nanoTime();
        if (mode == EnvelopeMode.PERSISTENT_KEY) {
            return signWithPersistentKey(
                    report,
                    mode,
                    canonicalPayloadJson,
                    canonicalPayloadBytes,
                    challengeB64Url,
                    reportSha256,
                    monoMs,
                    hardTriggers,
                    signStartNanos);
        }
        return signWithFreshAttestation(
                report,
                mode,
                challengeCopy,
                canonicalPayloadJson,
                canonicalPayloadBytes,
                challengeB64Url,
                reportSha256,
                monoMs,
                hardTriggers,
                signStartNanos);
    }

    /** Constructs the exact 17-field RFC §4.8.3 protocol v=2 canonical payload map. */
    public static Map<String, Object> buildPayloadMap(
            String packageName,
            RiskReport report,
            long monotonicMs,
            String challengeBase64Url,
            List<String> hardTriggers,
            String reportSha256) {
        FingerprintId fpId = report.getFingerprintId();
        String fpComposite = fpId != null && fpId.getCompositeId() != null
                ? fpId.getCompositeId()
                : "";
        String fpHardware = fpId != null && fpId.getHardwareId() != null
                ? fpId.getHardwareId()
                : "";

        Map<String, Integer> dimensions = new LinkedHashMap<>(RiskDimension.values().length);
        for (RiskDimension dim : RiskDimension.values()) {
            dimensions.put(dim.name(), report.getDimensionScore(dim));
        }

        Map<String, Object> m = new LinkedHashMap<>(20);
        m.put("v", SignedRiskEnvelope.PROTOCOL_VERSION);
        m.put("pkg", packageName == null ? "" : packageName);
        m.put("sdk", report.getSdkVersion() == null ? "" : report.getSdkVersion());
        m.put("scene", report.getCollectScene().name());
        m.put("ts", report.getTimestampMs());
        m.put("monoMs", monotonicMs);
        m.put("challenge", challengeBase64Url == null ? "" : challengeBase64Url);
        m.put("riskLevel", report.getOverallRiskLevel().name());
        m.put("score", report.getRiskScore());
        m.put("action", report.getRecommendedAction().name());
        m.put("confidence", report.getConfidencePercent());
        m.put("dimensions", dimensions);
        m.put("hardTriggers", hardTriggers == null
                ? Collections.<String>emptyList()
                : hardTriggers);
        m.put("coverage", report.getCoveragePercent());
        m.put("fpComposite", fpComposite);
        m.put("fpHardware", fpHardware);
        m.put("reportSha256", reportSha256 == null ? "" : reportSha256);
        return m;
    }

    /** Returns the authoritative hard-trigger list directly from {@link RiskReport}. */
    public static List<String> extractHardTriggers(RiskReport report) {
        return report == null ? Collections.emptyList() : report.getHardTriggers();
    }

    private SignedRiskEnvelope signWithPersistentKey(
            RiskReport report,
            EnvelopeMode requestedMode,
            String canonicalPayloadJson,
            byte[] canonicalPayloadBytes,
            String challengeB64Url,
            String reportSha256,
            long monoMs,
            List<String> hardTriggers,
            long signStartNanos) {
        try {
            CachedPersistentMaterial material = getOrCreatePersistentMaterial();
            byte[] sigBytes;
            try {
                sigBytes = backend.signEcdsaSha256(material.privateKey, canonicalPayloadBytes);
            } catch (InvalidKeyException | ProviderException invalidated) {
                // CAS-evict only if no peer thread has already rotated the persistent key
                evictPersistentMaterial(material);
                material = getOrCreatePersistentMaterial();
                sigBytes = backend.signEcdsaSha256(material.privateKey, canonicalPayloadBytes);
            }
            long latencyMs = Math.max(0L, (System.nanoTime() - signStartNanos) / 1_000_000L);
            boolean hwBacked = material.securityLevel.isHardwareBacked()
                    && !material.certChainPem.isEmpty();
            SignedRiskEnvelope.AttestationMode effectiveMode = hwBacked
                    ? SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY
                    : SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK;
            AttestationRecord.SecurityLevel effectiveLevel = hwBacked
                    ? material.securityLevel
                    : AttestationRecord.SecurityLevel.SOFTWARE;
            return new SignedRiskEnvelope(
                    report,
                    requestedMode,
                    effectiveMode,
                    effectiveLevel,
                    canonicalPayloadJson,
                    sigBytes,
                    Base64.getEncoder().encodeToString(sigBytes),
                    material.certChainPem,
                    material.certChainDer,
                    challengeB64Url,
                    reportSha256,
                    monoMs,
                    hardTriggers,
                    latencyMs);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return signWithSoftwareFallback(
                    report,
                    requestedMode,
                    canonicalPayloadJson,
                    canonicalPayloadBytes,
                    challengeB64Url,
                    reportSha256,
                    monoMs,
                    hardTriggers,
                    signStartNanos);
        }
    }

    private SignedRiskEnvelope signWithFreshAttestation(
            RiskReport report,
            EnvelopeMode requestedMode,
            byte[] challengeBytes,
            String canonicalPayloadJson,
            byte[] canonicalPayloadBytes,
            String challengeB64Url,
            String reportSha256,
            long monoMs,
            List<String> hardTriggers,
            long signStartNanos) {
        String ephemAlias = EPHEMERAL_ALIAS_PREFIX
                + UUID.randomUUID().toString().replace("-", "");
        try {
            SigningKeyHandle handle = generateWithHardwareFallback(ephemAlias, challengeBytes);
            if (handle == null || handle.getCertificateChain().isEmpty()) {
                throw new IllegalStateException("Ephemeral signing key missing certificate chain");
            }
            byte[] sigBytes = backend.signEcdsaSha256(
                    handle.getPrivateKey(), canonicalPayloadBytes);
            List<String> pemChain = toPemList(handle.getCertificateChain());
            List<byte[]> derChain = toDerList(handle.getCertificateChain());
            long latencyMs = Math.max(0L, (System.nanoTime() - signStartNanos) / 1_000_000L);

            boolean hwBacked = handle.getSecurityLevel().isHardwareBacked() && !pemChain.isEmpty();
            SignedRiskEnvelope.AttestationMode effectiveMode = hwBacked
                    ? SignedRiskEnvelope.AttestationMode.FRESH_ATTESTATION
                    : SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK;
            AttestationRecord.SecurityLevel effectiveLevel = hwBacked
                    ? handle.getSecurityLevel()
                    : AttestationRecord.SecurityLevel.SOFTWARE;

            return new SignedRiskEnvelope(
                    report,
                    requestedMode,
                    effectiveMode,
                    effectiveLevel,
                    canonicalPayloadJson,
                    sigBytes,
                    Base64.getEncoder().encodeToString(sigBytes),
                    pemChain,
                    derChain,
                    challengeB64Url,
                    reportSha256,
                    monoMs,
                    hardTriggers,
                    latencyMs);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return signWithSoftwareFallback(
                    report,
                    requestedMode,
                    canonicalPayloadJson,
                    canonicalPayloadBytes,
                    challengeB64Url,
                    reportSha256,
                    monoMs,
                    hardTriggers,
                    signStartNanos);
        } finally {
            safeDeleteAlias(ephemAlias);
        }
    }

    private SignedRiskEnvelope signWithSoftwareFallback(
            RiskReport report,
            EnvelopeMode requestedMode,
            String canonicalPayloadJson,
            byte[] canonicalPayloadBytes,
            String challengeB64Url,
            String reportSha256,
            long monoMs,
            List<String> hardTriggers,
            long signStartNanos) {
        try {
            CachedPersistentMaterial sw = getOrCreateSoftwareFallbackMaterial();
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(sw.privateKey);
            sig.update(canonicalPayloadBytes);
            byte[] sigBytes = sig.sign();
            long latencyMs = Math.max(0L, (System.nanoTime() - signStartNanos) / 1_000_000L);
            return new SignedRiskEnvelope(
                    report,
                    requestedMode,
                    SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK,
                    AttestationRecord.SecurityLevel.SOFTWARE,
                    canonicalPayloadJson,
                    sigBytes,
                    Base64.getEncoder().encodeToString(sigBytes),
                    sw.certChainPem,
                    sw.certChainDer,
                    challengeB64Url,
                    reportSha256,
                    monoMs,
                    hardTriggers,
                    latencyMs);
        } catch (Exception e) {
            throw new IllegalStateException("Envelope software fallback signing failed", e);
        }
    }

    private CachedPersistentMaterial getOrCreatePersistentMaterial() throws Exception {
        CachedPersistentMaterial fast = cachedPersistent;
        if (fast != null) {
            return fast;
        }
        synchronized (persistentLock) {
            fast = cachedPersistent;
            if (fast != null) {
                return fast;
            }
            SigningKeyHandle handle = null;
            try {
                handle = backend.loadExistingKey(PERSISTENT_KEY_ALIAS);
            } catch (Exception | LinkageError ignored) {
                safeDeleteAlias(PERSISTENT_KEY_ALIAS);
            }
            if (handle == null || handle.getCertificateChain().isEmpty()) {
                byte[] initChallenge = new byte[PERSISTENT_INIT_CHALLENGE_BYTES];
                secureRandom.nextBytes(initChallenge);
                handle = generatePersistentWithTeeFirst(PERSISTENT_KEY_ALIAS, initChallenge);
            }
            if (handle == null || handle.getCertificateChain().isEmpty()) {
                throw new IllegalStateException("Persistent signing key missing certificate chain");
            }
            List<String> pem = toPemList(handle.getCertificateChain());
            List<byte[]> der = toDerList(handle.getCertificateChain());
            CachedPersistentMaterial created = new CachedPersistentMaterial(
                    handle.getPrivateKey(),
                    handle.getSecurityLevel(),
                    pem,
                    der);
            cachedPersistent = created;
            return created;
        }
    }

    private void evictPersistentMaterial(CachedPersistentMaterial expected) {
        synchronized (persistentLock) {
            if (cachedPersistent == expected) {
                cachedPersistent = null;
                safeDeleteAlias(PERSISTENT_KEY_ALIAS);
            }
        }
    }

    /**
     * Provisions the latency-sensitive {@link EnvelopeMode#PERSISTENT_KEY} key preferring on-SoC
     * hardware TEE ({@code <10ms} P95 ECDSA signing on Pixel/Snapdragon/MediaTek vs 35&ndash;50ms
     * discrete StrongBox chip bus latency), falling back to StrongBox only if TEE generation fails.
     */
    private SigningKeyHandle generatePersistentWithTeeFirst(String alias, byte[] challenge)
            throws Exception {
        try {
            return backend.generateSigningKey(alias, challenge, false);
        } catch (Exception | LinkageError teeErr) {
            safeDeleteAlias(alias);
            if (!strongBoxKnownUnsupported) {
                try {
                    return backend.generateSigningKey(alias, challenge, true);
                } catch (Exception | LinkageError sbErr) {
                    if (isStrongBoxUnavailable(sbErr)) {
                        strongBoxKnownUnsupported = true;
                    }
                    safeDeleteAlias(alias);
                    throw sbErr;
                }
            }
            throw teeErr;
        }
    }

    private SigningKeyHandle generateWithHardwareFallback(String alias, byte[] challenge)
            throws Exception {
        if (!strongBoxKnownUnsupported) {
            try {
                return backend.generateSigningKey(alias, challenge, true);
            } catch (Exception | LinkageError sbErr) {
                if (isStrongBoxUnavailable(sbErr)) {
                    strongBoxKnownUnsupported = true;
                }
                safeDeleteAlias(alias);
            }
        }
        return backend.generateSigningKey(alias, challenge, false);
    }

    static boolean isStrongBoxUnavailable(Throwable error) {
        Throwable cur = error;
        int depth = 0;
        while (cur != null && depth++ < 8) {
            try {
                if (cur instanceof StrongBoxUnavailableException) {
                    return true;
                }
            } catch (LinkageError ignored) {
                // Pure JVM without Android framework class; fall back to class-name check
            }
            String name = cur.getClass().getName();
            if ("android.security.keystore.StrongBoxUnavailableException".equals(name)) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    private CachedPersistentMaterial getOrCreateSoftwareFallbackMaterial() throws Exception {
        CachedPersistentMaterial fast = softwareFallbackMaterial;
        if (fast != null) {
            return fast;
        }
        synchronized (persistentLock) {
            fast = softwareFallbackMaterial;
            if (fast != null) {
                return fast;
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), secureRandom);
            KeyPair kp = kpg.generateKeyPair();
            X509Certificate selfSigned = generateSoftwareSelfSignedCert(kp);
            List<X509Certificate> chain = Collections.singletonList(selfSigned);
            CachedPersistentMaterial created = new CachedPersistentMaterial(
                    kp.getPrivate(),
                    AttestationRecord.SecurityLevel.SOFTWARE,
                    toPemList(chain),
                    toDerList(chain));
            softwareFallbackMaterial = created;
            return created;
        }
    }

    private void safeDeleteAlias(String alias) {
        try {
            backend.deleteAlias(alias);
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Never throw out of finally
        }
    }

    public static String toPemCertificate(byte[] derBytes) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(derBytes);
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----";
    }

    private static List<String> toPemList(List<X509Certificate> certs)
            throws CertificateEncodingException {
        List<String> out = new ArrayList<>(certs.size());
        for (X509Certificate cert : certs) {
            out.add(toPemCertificate(cert.getEncoded()));
        }
        return Collections.unmodifiableList(out);
    }

    private static List<byte[]> toDerList(List<X509Certificate> certs)
            throws CertificateEncodingException {
        List<byte[]> out = new ArrayList<>(certs.size());
        for (X509Certificate cert : certs) {
            out.add(cert.getEncoded());
        }
        return Collections.unmodifiableList(out);
    }

    private static String resolvePackageName(Context context) {
        if (context == null) {
            return "";
        }
        try {
            String pkg = context.getPackageName();
            return pkg == null ? "" : pkg;
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            return "";
        }
    }

    /** Generates a minimal standard X.509v3 self-signed certificate for software fallback only. */
    private static X509Certificate generateSoftwareSelfSignedCert(KeyPair kp) throws Exception {
        Date now = new Date();
        Date notBefore = new Date(now.getTime() - 60_000L);
        Date notAfter = new Date(now.getTime() + 86_400_000L * 365);

        byte[] version = derExplicit(0, derTlv(0x02, BigInteger.valueOf(2).toByteArray()));
        BigInteger positiveSerial = BigInteger.valueOf(now.getTime() & Long.MAX_VALUE)
                .add(BigInteger.ONE);
        byte[] serial = derTlv(0x02, positiveSerial.toByteArray());
        byte[] sigAlg = derSeq(derOid(new int[]{1, 2, 840, 10045, 4, 3, 2})); // ecdsa-with-SHA256
        byte[] dn = derName("RiskEngine Software Fallback");
        byte[] validity = derSeq(derTime(notBefore), derTime(notAfter));
        byte[] spki = kp.getPublic().getEncoded();

        byte[] tbs = derSeq(version, serial, sigAlg, dn, validity, dn, spki);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(kp.getPrivate());
        sig.update(tbs);
        byte[] sigDer = sig.sign();
        byte[] bitString = new byte[sigDer.length + 1];
        bitString[0] = 0x00;
        System.arraycopy(sigDer, 0, bitString, 1, sigDer.length);
        byte[] certDer = derSeq(tbs, sigAlg, derTlv(0x03, bitString));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static byte[] derName(String cn) {
        byte[] utf8 = derTlv(0x0C, cn.getBytes(StandardCharsets.UTF_8));
        byte[] atv = derSeq(derOid(new int[]{2, 5, 4, 3}), utf8);
        return derSeq(derTlv(0x31, atv));
    }

    private static byte[] derTime(Date d) {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.ROOT);
        cal.setTime(d);
        int year = cal.get(Calendar.YEAR);
        if (year >= 1950 && year <= 2049) {
            SimpleDateFormat fmt = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.ROOT);
            fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            return derTlv(0x17, fmt.format(d).getBytes(StandardCharsets.US_ASCII));
        }
        SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.ROOT);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        return derTlv(0x18, fmt.format(d).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] derExplicit(int tagNo, byte[] inner) {
        return derTlv(0xA0 | tagNo, inner);
    }

    private static byte[] derSeq(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            if (p != null && p.length > 0) {
                out.write(p, 0, p.length);
            }
        }
        return derTlv(0x30, out.toByteArray());
    }

    private static byte[] derOid(int[] arcs) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            int v = arcs[i];
            if (v < 128) {
                out.write(v);
            } else {
                byte[] tmp = new byte[5];
                int pos = 5;
                tmp[--pos] = (byte) (v & 0x7F);
                v >>>= 7;
                while (v > 0) {
                    tmp[--pos] = (byte) ((v & 0x7F) | 0x80);
                    v >>>= 7;
                }
                out.write(tmp, pos, 5 - pos);
            }
        }
        return derTlv(0x06, out.toByteArray());
    }

    private static byte[] derTlv(int tag, byte[] val) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = val.length;
        if (len < 128) {
            out.write(len);
        } else if (len < 256) {
            out.write(0x81);
            out.write(len);
        } else if (len < 65536) {
            out.write(0x82);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        } else if (len < 16777216) {
            out.write(0x83);
            out.write((len >>> 16) & 0xFF);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        } else {
            out.write(0x84);
            out.write((len >>> 24) & 0xFF);
            out.write((len >>> 16) & 0xFF);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.write(val, 0, len);
        return out.toByteArray();
    }

    /** Production {@code AndroidKeyStore} implementation of {@link EnvelopeKeyBackend}. */
    private static final class AndroidKeyStoreEnvelopeBackend implements EnvelopeKeyBackend {
        private final AttestationExtensionParser extensionParser = new AttestationExtensionParser();

        @Override
        public SigningKeyHandle loadExistingKey(String alias) throws Exception {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (!ks.containsAlias(alias)) {
                return null;
            }
            Key key = ks.getKey(alias, null);
            if (!(key instanceof PrivateKey)) {
                return null;
            }
            List<X509Certificate> chain = readX509Chain(ks, alias);
            if (chain.isEmpty()) {
                return null;
            }
            AttestationRecord.SecurityLevel level =
                    resolveAttestedSecurityLevel(extensionParser, chain, null);
            return new SigningKeyHandle((PrivateKey) key, chain, level);
        }

        @Override
        public SigningKeyHandle generateSigningKey(
                String alias, byte[] attestationChallenge, boolean strongBox) throws Exception {
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setIsStrongBoxBacked(strongBox);
            if (attestationChallenge != null && attestationChallenge.length > 0) {
                b.setAttestationChallenge(attestationChallenge);
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            kpg.initialize(b.build());
            kpg.generateKeyPair();

            try {
                KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
                ks.load(null);
                Key key = ks.getKey(alias, null);
                if (!(key instanceof PrivateKey)) {
                    throw new IllegalStateException("Generated alias missing PrivateKey");
                }
                List<X509Certificate> chain = readX509Chain(ks, alias);
                if (chain.isEmpty()) {
                    throw new IllegalStateException("Generated alias missing certificate chain");
                }
                AttestationRecord.SecurityLevel level = resolveAttestedSecurityLevel(
                        extensionParser, chain, attestationChallenge);
                return new SigningKeyHandle((PrivateKey) key, chain, level);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                deleteAlias(alias);
                throw e;
            }
        }

        @Override
        public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes) throws Exception {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(privateKey);
            sig.update(payloadBytes);
            return sig.sign();
        }

        @Override
        public void deleteAlias(String alias) {
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

        private List<X509Certificate> readX509Chain(KeyStore ks, String alias) throws Exception {
            Certificate[] raw = ks.getCertificateChain(alias);
            if (raw == null || raw.length == 0) {
                return Collections.emptyList();
            }
            List<X509Certificate> out = new ArrayList<>(raw.length);
            for (Certificate c : raw) {
                if (c instanceof X509Certificate) {
                    out.add((X509Certificate) c);
                }
            }
            return out;
        }
    }

    /**
     * Resolves hardware attestation security level strictly from root-first OID {@code .17} on an
     * attestation certificate chain of length {@code >= 2}. Never falls back to {@code KeyInfo}
     * when OID {@code .17} is absent/malformed or when a non-empty {@code expectedChallenge} fails
     * to match, preventing unattested or replayed chains from claiming hardware endorsement.
     */
    public static AttestationRecord.SecurityLevel resolveAttestedSecurityLevel(
            AttestationExtensionParser parser,
            List<X509Certificate> chain,
            byte[] expectedChallenge) {
        if (parser == null || chain == null || chain.size() < 2) {
            return AttestationRecord.SecurityLevel.SOFTWARE;
        }
        try {
            byte[] ch = expectedChallenge == null ? new byte[0] : expectedChallenge;
            AttestationRecord rec = parser.parse(chain, ch);
            if (!rec.isValid()) {
                return AttestationRecord.SecurityLevel.SOFTWARE;
            }
            if (expectedChallenge != null && expectedChallenge.length > 0
                    && !rec.isChallengeMatched()) {
                return AttestationRecord.SecurityLevel.SOFTWARE;
            }
            AttestationRecord.SecurityLevel att = rec.getAttestationSecurityLevel();
            AttestationRecord.SecurityLevel km = rec.getKeymasterSecurityLevel();
            if (att == AttestationRecord.SecurityLevel.STRONGBOX
                    && km == AttestationRecord.SecurityLevel.STRONGBOX) {
                return AttestationRecord.SecurityLevel.STRONGBOX;
            }
            if (att.isHardwareBacked() && km.isHardwareBacked()) {
                return AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT;
            }
            return AttestationRecord.SecurityLevel.SOFTWARE;
        } catch (Exception | LinkageError ignored) {
            return AttestationRecord.SecurityLevel.SOFTWARE;
        }
    }
}
