package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.content.ContextWrapper;

import com.wsttxm.riskenginesdk.attestation.AttestationExtensionParser;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.attestation.CertificateTrustAnalyzer;
import com.wsttxm.riskenginesdk.attestation.GoogleAttestationRootStore;
import com.wsttxm.riskenginesdk.core.CanonicalJsonWriter;
import com.wsttxm.riskenginesdk.core.SignedEnvelopeSigner;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Independent Java 6-step offline server verifier reference implementation + cross-language
 * golden-vector parity tests against {@code scripts/verify_risk_envelope.py}.
 */
public class EnvelopeOfflineVerifierTest {

    private static final String APP_PKG = "com.host.app";
    private static final String APP_SIG_HEX =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /** Standardized RFC §4.8.3 verification result (1:1 parity with Python verifier). */
    static final class VerificationResult {
        final boolean ok;
        final String decision; // ALLOW | STEP_UP | REJECT
        final String reasonCode;
        final int stepFailed;
        final String message;

        VerificationResult(boolean ok, String decision, String reasonCode, int stepFailed, String message) {
            this.ok = ok;
            this.decision = decision;
            this.reasonCode = reasonCode;
            this.stepFailed = stepFailed;
            this.message = message;
        }
    }

    static final class VerifierPolicy {
        final Set<String> trustedRootSpkiSha256;
        final Set<String> revokedSerials;
        final String expectedPackage;
        final Set<String> expectedAppSigSha256;
        final boolean requireHardware;
        final long maxAgeMs;
        final long maxFutureSkewMs;
        final int minCoverage;
        final int minConfidence;
        final int rejectScoreThreshold;

        VerifierPolicy(
                Set<String> trustedRootSpkiSha256,
                Set<String> revokedSerials,
                String expectedPackage,
                Set<String> expectedAppSigSha256,
                boolean requireHardware) {
            this.trustedRootSpkiSha256 = trustedRootSpkiSha256;
            this.revokedSerials = revokedSerials;
            this.expectedPackage = expectedPackage;
            this.expectedAppSigSha256 = expectedAppSigSha256;
            this.requireHardware = requireHardware;
            this.maxAgeMs = 5 * 60 * 1000L;
            this.maxFutureSkewMs = 60 * 1000L;
            this.minCoverage = 80;
            this.minConfidence = 70;
            this.rejectScoreThreshold = 60;
        }
    }

    /** Independent offline 6-step Java reference verifier (zero cloud/HTTP dependencies). */
    static final class OfflineEnvelopeVerifier {
        private static final Set<String> VALID_ACTIONS = Collections.unmodifiableSet(
                new HashSet<>(Arrays.asList("ALLOW", "CHALLENGE", "RESTRICT", "BLOCK", "REVIEW")));
        private static final List<String> REQUIRED_DIMENSIONS = Arrays.asList(
                "TAMPERING", "PRIVILEGE", "ENVIRONMENT", "FRAUD_CONTEXT");
        private final AttestationExtensionParser extParser = new AttestationExtensionParser();

        private static boolean isValidBoundedInt(Object raw, int min, int max) {
            if (!(raw instanceof Integer || raw instanceof Long)) {
                return false;
            }
            long v = ((Number) raw).longValue();
            return v >= min && v <= max;
        }

        VerificationResult verify(
                String envelopeOrReportJson,
                byte[] expectedChallenge,
                VerifierPolicy policy,
                Set<String> consumedNonces,
                long evalEpochMs) {
            try {
                JSONObject rootObj = new JSONObject(envelopeOrReportJson);
                JSONObject envelope;
                JSONObject outerReport = null;
                if (rootObj.has("signedEnvelope")) {
                    envelope = rootObj.optJSONObject("signedEnvelope");
                    outerReport = new JSONObject(envelopeOrReportJson);
                    outerReport.remove("signedEnvelope");
                } else {
                    envelope = rootObj;
                }
                if (envelope == null) {
                    return reject(0, "ENVELOPE_MALFORMED", "Missing signedEnvelope");
                }
                JSONObject payload = envelope.optJSONObject("payload");
                String sigB64 = envelope.optString("signatureBase64", "");
                JSONArray chainArr = envelope.optJSONArray("certChainPem");
                String attMode = envelope.optString("attestationMode", "");
                String keySec = envelope.optString("keySecurityLevel", "");
                if (payload == null || sigB64.isEmpty() || chainArr == null || attMode.isEmpty()) {
                    return reject(0, "ENVELOPE_MALFORMED", "Missing required envelope fields");
                }

                Object protoRaw = payload.opt("v");
                if (!(protoRaw instanceof Integer || protoRaw instanceof Long)) {
                    return reject(0, "ENVELOPE_MALFORMED", "Missing or non-integer payload.v");
                }
                int protoVer = ((Number) protoRaw).intValue();
                if (protoVer != SignedRiskEnvelope.PROTOCOL_VERSION) {
                    return reject(0, "UNSUPPORTED_PROTOCOL_VERSION",
                            "Unsupported envelope protocol version v=" + protoVer);
                }
                if (!isValidBoundedInt(payload.opt("score"), 0, 100)) {
                    return reject(0, "ENVELOPE_MALFORMED", "payload.score must be an integer in 0..100");
                }
                String action = payload.optString("action", "");
                if (!VALID_ACTIONS.contains(action)) {
                    return reject(0, "ENVELOPE_MALFORMED", "Invalid or missing payload.action");
                }
                if (!isValidBoundedInt(payload.opt("confidence"), 0, 100)) {
                    return reject(0, "ENVELOPE_MALFORMED", "payload.confidence must be an integer in 0..100");
                }
                JSONObject dimensions = payload.optJSONObject("dimensions");
                if (dimensions == null || dimensions.length() != REQUIRED_DIMENSIONS.size()) {
                    return reject(0, "ENVELOPE_MALFORMED", "Invalid payload.dimensions");
                }
                for (String dimKey : REQUIRED_DIMENSIONS) {
                    if (!dimensions.has(dimKey) || !isValidBoundedInt(dimensions.opt(dimKey), 0, 100)) {
                        return reject(0, "ENVELOPE_MALFORMED", "Invalid payload.dimensions." + dimKey);
                    }
                }

                if (policy.requireHardware
                        && ("SOFTWARE_FALLBACK".equals(attMode) || "SOFTWARE".equals(keySec))) {
                    return reject(0, "SOFTWARE_FALLBACK_REJECTED", "Hardware attestation required");
                }

                if (outerReport != null) {
                    String expectedSha = CanonicalJsonWriter.sha256HexOfCanonicalJson(outerReport);
                    if (!expectedSha.equals(payload.optString("reportSha256", ""))) {
                        return reject(0, "REPORT_SHA256_MISMATCH", "Outer report SHA-256 mismatch");
                    }
                }

                // Step 1 & 2: Chain signatures, constraints, validity, Google root SPKI & CRL
                if (chainArr.length() < 2) {
                    return reject(1, "CERT_CHAIN_TOO_SHORT", "Chain length < 2");
                }
                List<X509Certificate> chain = new ArrayList<>(chainArr.length());
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                for (int i = 0; i < chainArr.length(); i++) {
                    byte[] der = decodePem(chainArr.getString(i));
                    chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
                }

                GoogleAttestationRootStore rootStore = GoogleAttestationRootStore.withAdditions(
                        policy.trustedRootSpkiSha256,
                        policy.revokedSerials);
                CertificateTrustAnalyzer analyzer = new CertificateTrustAnalyzer(rootStore);
                CertificateTrustAnalyzer.TrustResult trust =
                        analyzer.inspect(chain, new Date(evalEpochMs));

                if (!trust.isChainSignatureValid()) {
                    return reject(1, "CERT_SIGNATURE_INVALID", trust.getSignatureError());
                }
                if (!trust.isIssuerChainValid()) {
                    for (String issue : trust.getIssuerMismatches()) {
                        if (issue.contains("not_ca")
                                || issue.contains("pathlen")
                                || issue.contains("key_cert_sign")) {
                            return reject(1, "CERT_CA_CONSTRAINT_INVALID", issue);
                        }
                    }
                    return reject(1, "CERT_ISSUER_MISMATCH", trust.getIssuerMismatches().toString());
                }
                if (!trust.isValidityWindowValid()) {
                    return reject(1, "CERT_VALIDITY_EXPIRED", trust.getValidityIssues().toString());
                }
                if (!trust.isGoogleRootMatched()) {
                    return reject(1, "ROOT_ANCHOR_UNTRUSTED", "Root SPKI not trusted");
                }
                if (trust.isAnyCertRevoked()) {
                    return reject(2, "CERT_SERIAL_REVOKED", trust.getRevokedSerials().toString());
                }

                // Step 3: Root-first OID .17, TEE/StrongBox, RootOfTrust, attestationApplicationId
                AttestationRecord rec = extParser.parse(chain, expectedChallenge);
                if (!rec.isValid()) {
                    String err = rec.getParseError() == null ? "" : rec.getParseError();
                    if (err.contains("not found")) {
                        return reject(3, "ATTESTATION_EXTENSION_MISSING", err);
                    }
                    return reject(3, "ATTESTATION_EXTENSION_INVALID", err);
                }
                if (!rec.getAttestationSecurityLevel().isHardwareBacked()
                        || !rec.getKeymasterSecurityLevel().isHardwareBacked()) {
                    return reject(3, "ATTESTATION_SECURITY_LEVEL_INVALID", "Non-hardware level");
                }
                AttestationRecord.RootOfTrust rot = rec.getRootOfTrust();
                if (rot == null || !rot.isHardwareEnforced()) {
                    return reject(3, "ROOT_OF_TRUST_MISSING", "Missing hardware RootOfTrust");
                }
                if (!rot.isDeviceLocked()) {
                    return reject(3, "ROOT_OF_TRUST_UNLOCKED", "Bootloader unlocked");
                }
                if (rot.getVerifiedBootState() != AttestationRecord.VerifiedBootState.VERIFIED) {
                    return reject(3, "ROOT_OF_TRUST_BOOT_UNVERIFIED", "VerifiedBootState != VERIFIED");
                }
                if (policy.expectedPackage != null && !policy.expectedPackage.isEmpty()) {
                    AttestationRecord.AttestationApplicationId appId = rec.getAttestationApplicationId();
                    boolean pkgInAtt = appId != null
                            && appId.getPackageNames().contains(policy.expectedPackage);
                    if (!policy.expectedPackage.equals(payload.optString("pkg", "")) || !pkgInAtt) {
                        return reject(3, "APP_ID_PACKAGE_MISMATCH", "Package name mismatch");
                    }
                }
                if (policy.expectedAppSigSha256 != null && !policy.expectedAppSigSha256.isEmpty()) {
                    AttestationRecord.AttestationApplicationId appId = rec.getAttestationApplicationId();
                    boolean matched = false;
                    if (appId != null) {
                        for (String digest : appId.getSignatureDigestsSha256()) {
                            if (policy.expectedAppSigSha256.contains(digest.toLowerCase(Locale.US))) {
                                matched = true;
                                break;
                            }
                        }
                    }
                    if (!matched) {
                        return reject(3, "APP_ID_SIGNATURE_MISMATCH", "App signing cert mismatch");
                    }
                }

                // Step 4: Challenge, freshness & replay nonce check
                String expectedB64Url = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(expectedChallenge);
                if (!expectedB64Url.equals(payload.optString("challenge", ""))) {
                    return reject(4, "CHALLENGE_MISMATCH", "payload.challenge mismatch");
                }
                if ("FRESH_ATTESTATION".equals(attMode) && !rec.isChallengeMatched()) {
                    return reject(4, "ATTESTATION_CHALLENGE_MISMATCH", "Cert challenge mismatch");
                }
                if (!payload.has("ts")) {
                    return reject(4, "ENVELOPE_EXPIRED", "Missing payload.ts");
                }
                long ts = payload.getLong("ts");
                if (ts < evalEpochMs - policy.maxAgeMs || ts > evalEpochMs + policy.maxFutureSkewMs) {
                    return reject(4, "ENVELOPE_EXPIRED", "Timestamp outside window");
                }
                if (consumedNonces != null && !consumedNonces.add(expectedB64Url)) {
                    return reject(4, "NONCE_REPLAYED", "Challenge nonce already consumed");
                }

                // Step 5: SHA256withECDSA over canonical payload bytes
                byte[] sigBytes = Base64.getDecoder().decode(sigB64);
                byte[] canonicalBytes = CanonicalJsonWriter.toCanonicalUtf8Bytes(payload);
                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(chain.get(0).getPublicKey());
                verifier.update(canonicalBytes);
                if (!verifier.verify(sigBytes)) {
                    return reject(5, "SIGNATURE_INVALID", "ECDSA signature mismatch");
                }

                // Step 6: Business risk policy decision (protocol v=2, 0-100 scale)
                JSONArray hardTriggers = payload.optJSONArray("hardTriggers");
                if (hardTriggers != null && hardTriggers.length() > 0) {
                    return reject(6, "POLICY_HARD_TRIGGER", "Hard triggers present");
                }
                String riskLevel = payload.optString("riskLevel", "UNKNOWN");
                int score = payload.getInt("score");
                int confidence = payload.getInt("confidence");
                int coverage = payload.optInt("coverage", 0);
                if ("HIGH".equals(riskLevel)
                        || "DEADLY".equals(riskLevel)
                        || "RESTRICT".equals(action)
                        || "BLOCK".equals(action)
                        || score >= policy.rejectScoreThreshold) {
                    return reject(6, "POLICY_HIGH_RISK", "Risk exceeds threshold");
                }
                if ("MEDIUM".equals(riskLevel)
                        || "UNKNOWN".equals(riskLevel)
                        || "CHALLENGE".equals(action)
                        || "REVIEW".equals(action)
                        || confidence < policy.minConfidence
                        || coverage < policy.minCoverage) {
                    return new VerificationResult(
                            true, "STEP_UP", "POLICY_STEP_UP", 0, "Step-up auth required");
                }
                return new VerificationResult(true, "ALLOW", "OK", 0, "Verified");
            } catch (Exception e) {
                return reject(0, "ENVELOPE_MALFORMED", e.getMessage());
            }
        }

        private static VerificationResult reject(int step, String code, String msg) {
            return new VerificationResult(false, "REJECT", code, step, msg == null ? code : msg);
        }

        private static byte[] decodePem(String pem) {
            String stripped = pem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");
            return Base64.getDecoder().decode(stripped);
        }
    }

    // ------------------------------------------------------------------
    // Cross-Language Golden-Vector Tests (Java <-> Python 1:1 Parity)
    // ------------------------------------------------------------------

    @Test
    public void crossLanguageGoldenVectorsPassAndMatchAllTargetedRejections() throws Exception {
        byte[] challenge = fixedChallenge(32, 0x2A);
        long nowMs = System.currentTimeMillis();
        Context ctx = fakeContext(APP_PKG);
        OfflineEnvelopeVerifier javaVerifier = new OfflineEnvelopeVerifier();

        // 1. Valid FRESH_ATTESTATION full report JSON -> ALLOW / OK in both Java & Python
        FixtureChain freshChain = buildChain(
                challenge, BigInteger.valueOf(5001L), true, 0,
                AttestationRecord.SecurityLevel.STRONGBOX, false);
        RiskReport safeReport = sampleSafeReport();
        nowMs = safeReport.getTimestampMs();
        SignedRiskEnvelope freshEnv = signWithChain(
                ctx, safeReport, challenge, EnvelopeMode.FRESH_ATTESTATION, freshChain);
        String freshJson = freshEnv.toReportJson();
        VerifierPolicy basePolicy = new VerifierPolicy(
                Collections.singleton(freshChain.rootSpkiSha256),
                Collections.<String>emptySet(),
                APP_PKG,
                Collections.singleton(APP_SIG_HEX),
                true);

        Set<String> javaNonces = new HashSet<>();
        VerificationResult javaAllow = javaVerifier.verify(
                freshJson, challenge, basePolicy, javaNonces, nowMs);
        VerificationResult pyAllow = invokePythonVerifier(
                freshJson, challenge, freshChain.rootSpkiSha256, null, nowMs, true);
        assertParity("ALLOW", "OK", javaAllow, pyAllow);

        // 2. Replayed nonce -> REJECT / NONCE_REPLAYED (Java in-memory store; Python tested in unittest)
        VerificationResult javaReplay = javaVerifier.verify(
                freshJson, challenge, basePolicy, javaNonces, nowMs);
        assertEquals("REJECT", javaReplay.decision);
        assertEquals("NONCE_REPLAYED", javaReplay.reasonCode);
        assertEquals(4, javaReplay.stepFailed);

        // 3. Valid PERSISTENT_KEY mode -> ALLOW / OK in both Java & Python
        FixtureChain persistentChain = buildChain(
                fixedChallenge(32, 0x77), BigInteger.valueOf(5002L), true, 0,
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, false);
        SignedRiskEnvelope persistentEnv = signWithChain(
                ctx, safeReport, challenge, EnvelopeMode.PERSISTENT_KEY, persistentChain);
        String persistentJson = persistentEnv.toReportJson();
        VerifierPolicy persistentPolicy = new VerifierPolicy(
                Collections.singleton(persistentChain.rootSpkiSha256),
                Collections.<String>emptySet(),
                APP_PKG,
                Collections.singleton(APP_SIG_HEX),
                true);
        assertParity(
                "ALLOW",
                "OK",
                javaVerifier.verify(persistentJson, challenge, persistentPolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(persistentJson, challenge, persistentChain.rootSpkiSha256, null, nowMs, false));

        // 4. Tampered payload -> REJECT / SIGNATURE_INVALID (Step 5) in both Java & Python
        JSONObject tamperedObj = new JSONObject(freshJson);
        tamperedObj.getJSONObject("signedEnvelope").getJSONObject("payload").put("score", 9);
        // Strip outer report so REPORT_SHA256 check doesn't mask Step 5 signature tampering
        String tamperedStandalone = tamperedObj.getJSONObject("signedEnvelope").toString();
        assertParity(
                "REJECT",
                "SIGNATURE_INVALID",
                javaVerifier.verify(tamperedStandalone, challenge, basePolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(tamperedStandalone, challenge, freshChain.rootSpkiSha256, null, nowMs, false));

        // 5. Revoked certificate serial -> REJECT / CERT_SERIAL_REVOKED (Step 2) in both Java & Python
        String revokedSerialHex = BigInteger.valueOf(5001L).toString(16);
        VerifierPolicy revokedPolicy = new VerifierPolicy(
                Collections.singleton(freshChain.rootSpkiSha256),
                Collections.singleton(revokedSerialHex),
                APP_PKG,
                Collections.singleton(APP_SIG_HEX),
                true);
        assertParity(
                "REJECT",
                "CERT_SERIAL_REVOKED",
                javaVerifier.verify(freshJson, challenge, revokedPolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(freshJson, challenge, freshChain.rootSpkiSha256, revokedSerialHex, nowMs, false));

        // 6. Unlocked RootOfTrust -> REJECT / ROOT_OF_TRUST_UNLOCKED (Step 3) in both Java & Python
        FixtureChain unlockedChain = buildChain(
                challenge, BigInteger.valueOf(5003L), false, 2,
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, false);
        SignedRiskEnvelope unlockedEnv = signWithChain(
                ctx, safeReport, challenge, EnvelopeMode.FRESH_ATTESTATION, unlockedChain);
        String unlockedJson = unlockedEnv.toReportJson();
        VerifierPolicy unlockedPolicy = new VerifierPolicy(
                Collections.singleton(unlockedChain.rootSpkiSha256),
                Collections.<String>emptySet(),
                APP_PKG,
                Collections.singleton(APP_SIG_HEX),
                true);
        assertParity(
                "REJECT",
                "ROOT_OF_TRUST_UNLOCKED",
                javaVerifier.verify(unlockedJson, challenge, unlockedPolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(unlockedJson, challenge, unlockedChain.rootSpkiSha256, null, nowMs, false));

        // 7. Wrong server challenge -> REJECT / CHALLENGE_MISMATCH (Step 4) in both Java & Python
        byte[] wrongChallenge = fixedChallenge(32, 0xFF);
        assertParity(
                "REJECT",
                "CHALLENGE_MISMATCH",
                javaVerifier.verify(freshJson, wrongChallenge, basePolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(freshJson, wrongChallenge, freshChain.rootSpkiSha256, null, nowMs, false));

        // 8. SOFTWARE_FALLBACK -> REJECT / SOFTWARE_FALLBACK_REJECTED (Step 0) in both Java & Python
        SignedEnvelopeSigner fallbackSigner = new SignedEnvelopeSigner(
                new SignedEnvelopeSigner.EnvelopeKeyBackend() {
                    @Override public SignedEnvelopeSigner.SigningKeyHandle loadExistingKey(String alias) {
                        return null;
                    }
                    @Override public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                            String alias, byte[] attestationChallenge, boolean strongBox) {
                        throw new RuntimeException("No hardware keystore");
                    }
                    @Override public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes) {
                        throw new RuntimeException("No hardware keystore");
                    }
                    @Override public void deleteAlias(String alias) {}
                },
                () -> 8429103L);
        SignedRiskEnvelope swEnv = fallbackSigner.sign(
                ctx, safeReport, challenge, EnvelopeMode.FRESH_ATTESTATION);
        String swJson = swEnv.toReportJson();
        assertParity(
                "REJECT",
                "SOFTWARE_FALLBACK_REJECTED",
                javaVerifier.verify(swJson, challenge, basePolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(swJson, challenge, freshChain.rootSpkiSha256, null, nowMs, false));

        // 9. Hard trigger in valid signed envelope -> REJECT / POLICY_HARD_TRIGGER (Step 6) in both
        RiskReport htReport = sampleHardTriggerReport();
        SignedRiskEnvelope htEnv = signWithChain(
                ctx, htReport, challenge, EnvelopeMode.FRESH_ATTESTATION, freshChain);
        String htJson = htEnv.toReportJson();
        assertParity(
                "REJECT",
                "POLICY_HARD_TRIGGER",
                javaVerifier.verify(htJson, challenge, basePolicy, new HashSet<String>(), htReport.getTimestampMs()),
                invokePythonVerifier(htJson, challenge, freshChain.rootSpkiSha256, null, htReport.getTimestampMs(), false));

        // 10. Root-first leaf extension shadowing -> REJECT / ROOT_OF_TRUST_UNLOCKED (Step 3) in both
        FixtureChain shadowChain = buildChain(
                challenge, BigInteger.valueOf(5004L), true, 0,
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, true);
        SignedRiskEnvelope shadowEnv = signWithChain(
                ctx, safeReport, challenge, EnvelopeMode.FRESH_ATTESTATION, shadowChain);
        String shadowJson = shadowEnv.toReportJson();
        VerifierPolicy shadowPolicy = new VerifierPolicy(
                Collections.singleton(shadowChain.rootSpkiSha256),
                Collections.<String>emptySet(),
                APP_PKG,
                Collections.singleton(APP_SIG_HEX),
                true);
        assertParity(
                "REJECT",
                "ROOT_OF_TRUST_UNLOCKED",
                javaVerifier.verify(shadowJson, challenge, shadowPolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(shadowJson, challenge, shadowChain.rootSpkiSha256, null, nowMs, false));

        // 11. Legacy v=1 payload -> REJECT / UNSUPPORTED_PROTOCOL_VERSION (Step 0) in both
        JSONObject legacyObj = new JSONObject(freshJson).getJSONObject("signedEnvelope");
        legacyObj.getJSONObject("payload").put("v", 1);
        String legacyStandalone = legacyObj.toString();
        assertParity(
                "REJECT",
                "UNSUPPORTED_PROTOCOL_VERSION",
                javaVerifier.verify(legacyStandalone, challenge, basePolicy, new HashSet<String>(), nowMs),
                invokePythonVerifier(legacyStandalone, challenge, freshChain.rootSpkiSha256, null, nowMs, false));

        // 12. Normalized MEDIUM risk (0-100 score, CHALLENGE) -> STEP_UP / POLICY_STEP_UP in both
        RiskReport medReport = sampleMediumReport();
        SignedRiskEnvelope medEnv = signWithChain(
                ctx, medReport, challenge, EnvelopeMode.FRESH_ATTESTATION, freshChain);
        String medJson = medEnv.toReportJson();
        assertParity(
                "STEP_UP",
                "POLICY_STEP_UP",
                javaVerifier.verify(medJson, challenge, basePolicy, new HashSet<String>(), medReport.getTimestampMs()),
                invokePythonVerifier(medJson, challenge, freshChain.rootSpkiSha256, null, medReport.getTimestampMs(), false));

        // 13. Normalized HIGH risk (0-100 score >= 60, BLOCK in PAYMENT) -> REJECT / POLICY_HIGH_RISK in both
        RiskReport highReport = sampleHighReport();
        SignedRiskEnvelope highEnv = signWithChain(
                ctx, highReport, challenge, EnvelopeMode.FRESH_ATTESTATION, freshChain);
        String highJson = highEnv.toReportJson();
        assertParity(
                "REJECT",
                "POLICY_HIGH_RISK",
                javaVerifier.verify(highJson, challenge, basePolicy, new HashSet<String>(), highReport.getTimestampMs()),
                invokePythonVerifier(highJson, challenge, freshChain.rootSpkiSha256, null, highReport.getTimestampMs(), false));

        // 14. Low Assessment Confidence (UNKNOWN / REVIEW) -> STEP_UP / POLICY_STEP_UP in both
        RiskReport unknownReport = sampleLowConfidenceReport();
        SignedRiskEnvelope unknownEnv = signWithChain(
                ctx, unknownReport, challenge, EnvelopeMode.FRESH_ATTESTATION, freshChain);
        String unknownJson = unknownEnv.toReportJson();
        assertParity(
                "STEP_UP",
                "POLICY_STEP_UP",
                javaVerifier.verify(unknownJson, challenge, basePolicy, new HashSet<String>(), unknownReport.getTimestampMs()),
                invokePythonVerifier(unknownJson, challenge, freshChain.rootSpkiSha256, null, unknownReport.getTimestampMs(), false));
    }

    private static void assertParity(
            String expectedDecision,
            String expectedCode,
            VerificationResult javaRes,
            VerificationResult pyRes) {
        assertEquals("Java decision (" + javaRes.message + ")", expectedDecision, javaRes.decision);
        assertEquals("Java reasonCode (" + javaRes.message + ")", expectedCode, javaRes.reasonCode);
        assertEquals("Python decision (" + pyRes.message + ")", expectedDecision, pyRes.decision);
        assertEquals("Python reasonCode (" + pyRes.message + ")", expectedCode, pyRes.reasonCode);
        assertEquals(javaRes.decision, pyRes.decision);
        assertEquals(javaRes.reasonCode, pyRes.reasonCode);
    }

    private static VerificationResult invokePythonVerifier(
            String jsonInput,
            byte[] challenge,
            String trustedRootSpki,
            String revokedSerial,
            long evalEpochMs,
            boolean requireFresh) throws Exception {
        File repoRoot = resolveRepoRoot();
        File script = new File(repoRoot, "scripts/verify_risk_envelope.py");
        assertTrue("Expected script at " + script.getAbsolutePath(), script.isFile());

        String challengeB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
        List<String> cmd = new ArrayList<>();
        cmd.add("python3");
        cmd.add(script.getAbsolutePath());
        cmd.add("--envelope");
        cmd.add("-");
        cmd.add("--challenge");
        cmd.add(challengeB64Url);
        cmd.add("--expected-package");
        cmd.add(APP_PKG);
        cmd.add("--expected-app-sig");
        cmd.add(APP_SIG_HEX);
        cmd.add("--trusted-root-spki");
        cmd.add(trustedRootSpki);
        cmd.add("--eval-epoch-ms");
        cmd.add(Long.toString(evalEpochMs));
        if (revokedSerial != null) {
            cmd.add("--revoked-serial");
            cmd.add(revokedSerial);
        }
        if (requireFresh) {
            cmd.add("--require-fresh");
        }

        Process proc = new ProcessBuilder(cmd).redirectErrorStream(false).start();
        try (OutputStream os = proc.getOutputStream()) {
            os.write(jsonInput.getBytes(StandardCharsets.UTF_8));
        }
        String stdout = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        String stderr = new String(proc.getErrorStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        int rc = proc.waitFor();
        assertFalse("Python verifier produced empty stdout (stderr=" + stderr + ")", stdout.isEmpty());
        JSONObject obj = new JSONObject(stdout);
        boolean ok = obj.getBoolean("ok");
        String decision = obj.getString("decision");
        if ("REJECT".equals(decision)) {
            assertEquals("Expected rc=1 on REJECT", 1, rc);
        } else {
            assertEquals("Expected rc=0 on ALLOW/STEP_UP (stderr=" + stderr + ")", 0, rc);
        }
        return new VerificationResult(
                ok,
                decision,
                obj.getString("reasonCode"),
                obj.getInt("stepFailed"),
                obj.optString("message", ""));
    }

    private static File resolveRepoRoot() {
        File dir = new File(System.getProperty("user.dir")).getAbsoluteFile();
        while (dir != null) {
            if (new File(dir, "scripts/verify_risk_envelope.py").isFile()) {
                return dir;
            }
            dir = dir.getParentFile();
        }
        throw new IllegalStateException("Could not locate repo root from " + System.getProperty("user.dir"));
    }

    // ------------------------------------------------------------------
    // Test Certificate Chain & SignedRiskEnvelope Builders
    // ------------------------------------------------------------------

    private static final class FixtureChain {
        final PrivateKey leafPrivateKey;
        final List<X509Certificate> chain;
        final AttestationRecord.SecurityLevel level;
        final String rootSpkiSha256;

        FixtureChain(
                PrivateKey leafPrivateKey,
                List<X509Certificate> chain,
                AttestationRecord.SecurityLevel level,
                String rootSpkiSha256) {
            this.leafPrivateKey = leafPrivateKey;
            this.chain = chain;
            this.level = level;
            this.rootSpkiSha256 = rootSpkiSha256;
        }
    }

    private static SignedRiskEnvelope signWithChain(
            Context ctx,
            RiskReport report,
            byte[] challenge,
            EnvelopeMode mode,
            final FixtureChain fixture) {
        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(
                new SignedEnvelopeSigner.EnvelopeKeyBackend() {
                    @Override public SignedEnvelopeSigner.SigningKeyHandle loadExistingKey(String alias) {
                        return new SignedEnvelopeSigner.SigningKeyHandle(
                                fixture.leafPrivateKey, fixture.chain, fixture.level);
                    }
                    @Override public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                            String alias, byte[] attestationChallenge, boolean strongBox) {
                        return new SignedEnvelopeSigner.SigningKeyHandle(
                                fixture.leafPrivateKey, fixture.chain, fixture.level);
                    }
                    @Override public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes)
                            throws Exception {
                        Signature s = Signature.getInstance("SHA256withECDSA");
                        s.initSign(privateKey);
                        s.update(payloadBytes);
                        return s.sign();
                    }
                    @Override public void deleteAlias(String alias) {}
                },
                () -> 8429103L);
        return signer.sign(ctx, report, challenge, mode);
    }

    private static FixtureChain buildChain(
            byte[] attChallenge,
            BigInteger leafSerial,
            boolean deviceLocked,
            int verifiedBootState,
            AttestationRecord.SecurityLevel level,
            boolean addUnlockedIntermediateAttestation) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair rootKp = kpg.generateKeyPair();
        KeyPair interKp = kpg.generateKeyPair();
        KeyPair leafKp = kpg.generateKeyPair();

        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L * 30L);
        Date notAfter = new Date(System.currentTimeMillis() + 86_400_000L * 365L);

        X509Certificate root = buildCert(
                BigInteger.ONE, "Test Google Root", "Test Google Root",
                rootKp.getPublic(), rootKp.getPrivate(), notBefore, notAfter,
                true, 1, true, null);
        byte[] interAtt = addUnlockedIntermediateAttestation
                ? buildAttestationExtensionInner(
                        attChallenge, level.getCode(), false, 2, APP_PKG, APP_SIG_HEX)
                : null;
        X509Certificate inter = buildCert(
                BigInteger.valueOf(2L), "Test Google Root", "Test KeyMint Intermediate",
                interKp.getPublic(), rootKp.getPrivate(), notBefore, notAfter,
                true, 0, true, interAtt);
        byte[] leafAtt = buildAttestationExtensionInner(
                attChallenge, level.getCode(), deviceLocked, verifiedBootState, APP_PKG, APP_SIG_HEX);
        X509Certificate leaf = buildCert(
                leafSerial, "Test KeyMint Intermediate", "Android Keystore Key",
                leafKp.getPublic(), interKp.getPrivate(), notBefore, notAfter,
                false, -1, false, leafAtt);

        String rootSpki = GoogleAttestationRootStore.sha256SpkiHex(root);
        return new FixtureChain(
                leafKp.getPrivate(),
                Arrays.asList(leaf, inter, root),
                level,
                rootSpki);
    }

    private static X509Certificate buildCert(
            BigInteger serial,
            String issuerCn,
            String subjectCn,
            PublicKey subjectPub,
            PrivateKey issuerPriv,
            Date notBefore,
            Date notAfter,
            boolean isCa,
            int pathLen,
            boolean keyCertSign,
            byte[] attestationInner) throws Exception {
        List<byte[]> exts = new ArrayList<>();
        ByteArrayOutputStream bcInner = new ByteArrayOutputStream();
        if (isCa) {
            bcInner.write(new byte[]{0x01, 0x01, (byte) 0xFF});
            if (pathLen >= 0) {
                bcInner.write(derInt(BigInteger.valueOf(pathLen)));
            }
        }
        exts.add(derSeq(
                derOid(new int[]{2, 5, 29, 19}),
                new byte[]{0x01, 0x01, (byte) 0xFF},
                derOctets(derSeq(bcInner.toByteArray()))));
        if (keyCertSign) {
            exts.add(derSeq(
                    derOid(new int[]{2, 5, 29, 15}),
                    new byte[]{0x01, 0x01, (byte) 0xFF},
                    derOctets(derBitString(new byte[]{0x04}, 2))));
        }
        if (attestationInner != null) {
            exts.add(derSeq(
                    derOid(new int[]{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}),
                    derOctets(attestationInner)));
        }

        byte[] sigAlg = derSeq(derOid(new int[]{1, 2, 840, 10045, 4, 3, 2}));
        byte[] tbs = derSeq(
                derCtx(0, derInt(BigInteger.valueOf(2))),
                derInt(serial),
                sigAlg,
                derDn(issuerCn),
                derSeq(derUtcTime(notBefore), derUtcTime(notAfter)),
                derDn(subjectCn),
                subjectPub.getEncoded(),
                derCtx(3, derSeq(exts.toArray(new byte[0][]))));

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(issuerPriv);
        signer.update(tbs);
        byte[] sig = signer.sign();

        byte[] certDer = derSeq(tbs, sigAlg, derBitString(sig, 0));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static byte[] buildAttestationExtensionInner(
            byte[] challenge,
            int secLevel,
            boolean deviceLocked,
            int verifiedBootState,
            String pkgName,
            String appSigHex) {
        byte[] rot = derSeq(
                derOctets(new byte[32]),
                new byte[]{0x01, 0x01, deviceLocked ? (byte) 0xFF : 0x00},
                derEnum(verifiedBootState),
                derOctets(new byte[32]));
        byte[] appId = derSeq(
                derSet(derSeq(derOctets(pkgName.getBytes(StandardCharsets.UTF_8)), derInt(BigInteger.valueOf(100)))),
                derSet(derOctets(hexToBytes(appSigHex))));
        byte[] swList = derSeq(derCtx(709, derOctets(appId)));
        byte[] hwList = derSeq(derCtx(704, rot));
        return derSeq(
                derInt(BigInteger.valueOf(300)),
                derEnum(secLevel),
                derInt(BigInteger.valueOf(300)),
                derEnum(secLevel),
                derOctets(challenge),
                derOctets(new byte[0]),
                swList,
                hwList);
    }

    private static byte[] derTlv(byte[] tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag, 0, tag.length);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            ByteArrayOutputStream lb = new ByteArrayOutputStream();
            int tmp = len;
            while (tmp > 0) {
                lb.write(tmp & 0xFF);
                tmp >>>= 8;
            }
            byte[] rev = lb.toByteArray();
            out.write(0x80 | rev.length);
            for (int i = rev.length - 1; i >= 0; i--) {
                out.write(rev[i]);
            }
        }
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    private static byte[] derSeq(byte[]... items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] item : items) {
            out.write(item, 0, item.length);
        }
        return derTlv(new byte[]{0x30}, out.toByteArray());
    }

    private static byte[] derSet(byte[]... items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] item : items) {
            out.write(item, 0, item.length);
        }
        return derTlv(new byte[]{0x31}, out.toByteArray());
    }

    private static byte[] derInt(BigInteger v) {
        return derTlv(new byte[]{0x02}, v.toByteArray());
    }

    private static byte[] derEnum(int v) {
        return derTlv(new byte[]{0x0A}, BigInteger.valueOf(v).toByteArray());
    }

    private static byte[] derOctets(byte[] data) {
        return derTlv(new byte[]{0x04}, data);
    }

    private static byte[] derBitString(byte[] data, int unused) {
        byte[] content = new byte[data.length + 1];
        content[0] = (byte) unused;
        System.arraycopy(data, 0, content, 1, data.length);
        return derTlv(new byte[]{0x03}, content);
    }

    private static byte[] derCtx(int tagNum, byte[] content) {
        if (tagNum < 31) {
            return derTlv(new byte[]{(byte) (0xA0 | tagNum)}, content);
        }
        ByteArrayOutputStream tag = new ByteArrayOutputStream();
        tag.write(0xBF);
        int[] chunks = new int[5];
        int count = 0;
        int v = tagNum;
        while (v > 0) {
            chunks[count++] = v & 0x7F;
            v >>>= 7;
        }
        for (int i = count - 1; i >= 0; i--) {
            tag.write(chunks[i] | (i > 0 ? 0x80 : 0));
        }
        return derTlv(tag.toByteArray(), content);
    }

    private static byte[] derOid(int[] arcs) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            int arc = arcs[i];
            if (arc == 0) {
                out.write(0);
            } else {
                int[] parts = new int[5];
                int n = 0;
                while (arc > 0) {
                    parts[n++] = arc & 0x7F;
                    arc >>>= 7;
                }
                for (int j = n - 1; j >= 0; j--) {
                    out.write(parts[j] | (j > 0 ? 0x80 : 0));
                }
            }
        }
        return derTlv(new byte[]{0x06}, out.toByteArray());
    }

    private static byte[] derDn(String cn) {
        byte[] utf8 = derTlv(new byte[]{0x0C}, cn.getBytes(StandardCharsets.UTF_8));
        return derSeq(derSet(derSeq(derOid(new int[]{2, 5, 4, 3}), utf8)));
    }

    private static byte[] derUtcTime(Date d) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        return derTlv(new byte[]{0x17}, fmt.format(d).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static Context fakeContext(final String pkgName) {
        return new ContextWrapper(null) {
            @Override public String getPackageName() { return pkgName; }
            @Override public Context getApplicationContext() { return this; }
        };
    }

    private static byte[] fixedChallenge(int len, int seed) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) ((seed + i * 17) & 0xFF);
        }
        return out;
    }

    private static RiskReport sampleSafeReport() {
        CollectorResult dev = new CollectorResult("device_info");
        dev.addValue("model", "Pixel");
        FingerprintId fpId = new FingerprintId(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "sys-test", "vol-test", 9, 13, 6, 11,
                Collections.singletonList("device_info.model"),
                Collections.singletonMap("cpu", "abcdef"));
        DeviceFingerprint fp = new DeviceFingerprint();
        fp.addResult(dev);
        DetectionResult clean = new DetectionResult(
                "root", RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                DetectionExecutionStatus.SAFE, 1, 1, 0,
                Collections.<String>emptyList(), Collections.<String>emptyList(), "clean");
        return new RiskReport(fp, Collections.singletonList(clean), CollectScene.PAYMENT, fpId);
    }

    private static RiskReport sampleHardTriggerReport() {
        EvidenceItem split = new EvidenceItem(
                "tee_grant_chain_split",
                EvidenceItem.SourceLayer.ISOLATED,
                "Domain.GRANT",
                "mismatch",
                "tee_tamper",
                EvidenceItem.Rank.STRONG);
        DetectionResult tee = new DetectionResult(
                "tee_integrity", RiskLevel.HIGH, DetectionStatus.DANGER, 9, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.<String>emptyList(),
                Collections.singletonList("tee_grant_chain_split"),
                Collections.singletonList(split),
                "Grant chain split");
        return new RiskReport(
                new DeviceFingerprint(), Collections.singletonList(tee), CollectScene.PAYMENT, null);
    }

    private static RiskReport sampleMediumReport() {
        DetectionResult emu = new DetectionResult(
                "emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING, 5, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.<String>emptyList(),
                Collections.singletonList("qemu_pipe"),
                "Emulator signal");
        return new RiskReport(
                new DeviceFingerprint(), Collections.singletonList(emu), CollectScene.STANDARD, null);
    }

    private static RiskReport sampleHighReport() {
        DetectionResult root = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.<String>emptyList(),
                Collections.singletonList("su_binary"),
                "Root binary detected");
        return new RiskReport(
                new DeviceFingerprint(), Collections.singletonList(root), CollectScene.PAYMENT, null);
    }

    private static RiskReport sampleLowConfidenceReport() {
        DetectionResult criticalTimeout = DetectionResult.timeout("hook_framework", "deadline")
                .withScanTier(ScanTier.CRITICAL);
        DetectionResult fastClean = new DetectionResult(
                "root", RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                DetectionExecutionStatus.SAFE, 1, 1, 0,
                Collections.<String>emptyList(), Collections.<String>emptyList(), "clean")
                .withScanTier(ScanTier.FAST);
        return new RiskReport(
                new DeviceFingerprint(), Arrays.asList(criticalTimeout, fastClean), CollectScene.PAYMENT, null);
    }
}
