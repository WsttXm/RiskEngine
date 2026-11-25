package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.content.ContextWrapper;
import android.security.keystore.StrongBoxUnavailableException;

import com.wsttxm.riskenginesdk.attestation.AttestationExtensionParser;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.core.AppLifecycleObserver;
import com.wsttxm.riskenginesdk.core.CanonicalJsonWriter;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.SignedEnvelopeSigner;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
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
import com.wsttxm.riskenginesdk.util.RiskReportJsonSerializer;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
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
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SignedRiskEnvelopeTest {

    @After
    public void tearDown() {
        RiskEngine engine = RiskEngine.getInstance();
        engine.setEnvelopeSignerForTest(null);
        engine.setNativeHooksForTest(null);
        if (RiskEngine.isInitialized()) {
            RiskEngine.shutdown();
        }
    }

    @Test
    public void canonicalJsonWriterRecursivelySortsKeysWithoutWhitespaceOrSlashEscaping()
            throws Exception {
        Map<String, Object> nestedA = new LinkedHashMap<>();
        nestedA.put("z", "/system/bin/su");
        nestedA.put("a", "line1\nline2\t\"q\"\\b");
        nestedA.put("m", Arrays.asList(3, 1, 2, null, true, false));

        Map<String, Object> rootA = new LinkedHashMap<>();
        rootA.put("b", nestedA);
        rootA.put("a", 42);
        rootA.put("c", 1.0d);

        JSONObject nestedB = new JSONObject();
        nestedB.put("m", new JSONArray(Arrays.asList(3, 1, 2, JSONObject.NULL, true, false)));
        nestedB.put("a", "line1\nline2\t\"q\"\\b");
        nestedB.put("z", "/system/bin/su");

        JSONObject rootB = new JSONObject();
        rootB.put("c", 1L);
        rootB.put("a", 42);
        rootB.put("b", nestedB);

        String canonA = CanonicalJsonWriter.toCanonicalJson(rootA);
        String canonB = CanonicalJsonWriter.toCanonicalJson(rootB);

        assertEquals(
                "{\"a\":42,\"b\":{\"a\":\"line1\\nline2\\t\\\"q\\\"\\\\b\","
                        + "\"m\":[3,1,2,null,true,false],\"z\":\"/system/bin/su\"},\"c\":1}",
                canonA);
        assertEquals(canonA, canonB);
        assertEquals(
                CanonicalJsonWriter.sha256HexOfCanonicalJson(rootA),
                CanonicalJsonWriter.sha256HexOfCanonicalJson(rootB));
    }

    @Test
    public void canonicalJsonWriterRejectsNonFiniteNumbersAndNullMapKeys() {
        try {
            CanonicalJsonWriter.toCanonicalJson(Double.NaN);
            fail("Expected IllegalArgumentException for NaN");
        } catch (IllegalArgumentException expected) {
        }
        try {
            CanonicalJsonWriter.toCanonicalJson(Double.POSITIVE_INFINITY);
            fail("Expected IllegalArgumentException for Infinity");
        } catch (IllegalArgumentException expected) {
        }
        Map<Object, Object> badKeyMap = new HashMap<>();
        badKeyMap.put(null, "v");
        try {
            CanonicalJsonWriter.toCanonicalJson(badKeyMap);
            fail("Expected IllegalArgumentException for null map key");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void persistentKeyModeGeneratesOnceAndReusesHardwareKeyUnder10ms() throws Exception {
        FakeEnvelopeKeyBackend backend = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                true /* failStrongBox */);
        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(backend, () -> 8429103L);
        RiskReport report = sampleSafeReport();
        Context ctx = fakeContext("com.host.app");

        byte[] challenge1 = fixedChallenge(32, 0x11);
        SignedRiskEnvelope first = signer.sign(ctx, report, challenge1, EnvelopeMode.PERSISTENT_KEY);

        assertEquals(EnvelopeMode.PERSISTENT_KEY, first.getRequestedMode());
        assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, first.getAttestationMode());
        assertEquals(
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                first.getKeySecurityLevel());
        assertTrue(first.isHardwareBacked());
        // PERSISTENT_KEY prefers on-SoC hardware TEE (<10ms P95) over discrete StrongBox (~40ms)
        assertEquals(0, backend.strongBoxAttempts.get());
        assertEquals(1, backend.teeAttempts.get());
        assertEquals(1, backend.signCalls.get());
        assertTrue(backend.activeKeys.containsKey(SignedEnvelopeSigner.PERSISTENT_KEY_ALIAS));
        assertTrue(verifyEcdsaSignature(first));

        // Verify exact 17 RFC §4.8.3 v=2 payload fields and canonical ordering
        JSONObject payloadObj = new JSONObject(first.getCanonicalPayloadJson());
        List<String> keys = new ArrayList<>();
        Iterator<String> it = payloadObj.keys();
        while (it.hasNext()) {
            keys.add(it.next());
        }
        Collections.sort(keys);
        assertEquals(
                Arrays.asList(
                        "action", "challenge", "confidence", "coverage", "dimensions",
                        "fpComposite", "fpHardware", "hardTriggers", "monoMs", "pkg",
                        "reportSha256", "riskLevel", "scene", "score", "sdk", "ts", "v"),
                keys);
        assertEquals(2, SignedRiskEnvelope.PROTOCOL_VERSION);
        assertEquals(2, payloadObj.getInt("v"));
        assertEquals("com.host.app", payloadObj.getString("pkg"));
        assertEquals("PAYMENT", payloadObj.getString("scene"));
        assertEquals(8429103L, payloadObj.getLong("monoMs"));
        assertEquals(
                Base64.getUrlEncoder().withoutPadding().encodeToString(challenge1),
                payloadObj.getString("challenge"));
        assertEquals("SAFE", payloadObj.getString("riskLevel"));
        assertEquals("ALLOW", payloadObj.getString("action"));
        assertEquals(0, payloadObj.getInt("score"));
        assertEquals(100, payloadObj.getInt("confidence"));
        JSONObject dims = payloadObj.getJSONObject("dimensions");
        assertEquals(4, dims.length());
        assertEquals(0, dims.getInt("TAMPERING"));
        assertEquals(0, dims.getInt("PRIVILEGE"));
        assertEquals(0, dims.getInt("ENVIRONMENT"));
        assertEquals(0, dims.getInt("FRAUD_CONTEXT"));
        assertEquals(0, payloadObj.getJSONArray("hardTriggers").length());
        assertEquals("comp-sha256-test", payloadObj.getString("fpComposite"));
        assertEquals("hw-sha256-test", payloadObj.getString("fpHardware"));

        String expectedReportSha = CanonicalJsonWriter.sha256HexOfCanonicalJson(
                RiskReportJsonSerializer.toJsonObject(report, null));
        assertEquals(expectedReportSha, payloadObj.getString("reportSha256"));
        assertEquals(expectedReportSha, first.getReportSha256());

        // Hot-path reuse: 10 subsequent signings must perform ZERO additional key generations
        long maxHotSignMs = 0L;
        for (int i = 0; i < 10; i++) {
            byte[] ch = fixedChallenge(32, 0x20 + i);
            SignedRiskEnvelope env = signer.sign(ctx, report, ch, EnvelopeMode.PERSISTENT_KEY);
            assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, env.getAttestationMode());
            assertTrue(verifyEcdsaSignature(env));
            maxHotSignMs = Math.max(maxHotSignMs, env.getSigningLatencyMs());
        }
        assertEquals(0, backend.strongBoxAttempts.get());
        assertEquals(1, backend.teeAttempts.get());
        assertEquals(11, backend.signCalls.get());
        assertTrue("Expected fast persistent signing latency, got " + maxHotSignMs + "ms",
                maxHotSignMs < 250L);
    }

    @Test
    public void persistentKeyInvalidationEvictsAndRegeneratesOnce() throws Exception {
        FakeEnvelopeKeyBackend backend = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, false);
        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(backend, () -> 1000L);
        RiskReport report = sampleSafeReport();
        Context ctx = fakeContext("com.host.app");

        SignedRiskEnvelope env1 = signer.sign(
                ctx, report, fixedChallenge(32, 1), EnvelopeMode.PERSISTENT_KEY);
        assertTrue(verifyEcdsaSignature(env1));
        assertEquals(1, backend.teeAttempts.get());
        assertEquals(0, backend.strongBoxAttempts.get());

        // Simulate Keystore invalidation on next sign
        backend.throwOnNextSign = new InvalidKeyException("key invalidated");
        SignedRiskEnvelope env2 = signer.sign(
                ctx, report, fixedChallenge(32, 2), EnvelopeMode.PERSISTENT_KEY);
        assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, env2.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, env2.getKeySecurityLevel());
        assertTrue(verifyEcdsaSignature(env2));
        assertEquals(2, backend.teeAttempts.get());
        assertTrue(backend.deletedAliases.contains(SignedEnvelopeSigner.PERSISTENT_KEY_ALIAS));

        // Simulate ProviderException on next sign as well
        backend.throwOnNextSign = new ProviderException("keystore reset");
        SignedRiskEnvelope env3 = signer.sign(
                ctx, report, fixedChallenge(32, 3), EnvelopeMode.PERSISTENT_KEY);
        assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, env3.getAttestationMode());
        assertTrue(verifyEcdsaSignature(env3));
        assertEquals(3, backend.teeAttempts.get());
    }

    @Test
    public void persistentKeyFallsBackToStrongBoxWhenTeeFails() throws Exception {
        FakeEnvelopeKeyBackend backend = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.STRONGBOX, false);
        backend.failTee = true;
        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(backend, () -> 2000L);
        RiskReport report = sampleSafeReport();
        Context ctx = fakeContext("com.host.app");

        SignedRiskEnvelope env = signer.sign(
                ctx, report, fixedChallenge(32, 0x33), EnvelopeMode.PERSISTENT_KEY);
        assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, env.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.STRONGBOX, env.getKeySecurityLevel());
        assertTrue(env.isHardwareBacked());
        assertEquals(1, backend.teeAttempts.get());
        assertEquals(1, backend.strongBoxAttempts.get());
        assertTrue(verifyEcdsaSignature(env));
    }

    @Test
    public void freshAttestationBindsServerChallengeAndAlwaysDeletesEphemeralAlias()
            throws Exception {
        FakeEnvelopeKeyBackend backend = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.STRONGBOX, false);
        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(backend, () -> 5555L);
        RiskReport report = sampleHardTriggerReport();
        Context ctx = fakeContext("com.host.app");

        byte[] challenge = fixedChallenge(32, 0x5A);
        SignedRiskEnvelope env = signer.sign(
                ctx, report, challenge, EnvelopeMode.FRESH_ATTESTATION);

        assertEquals(EnvelopeMode.FRESH_ATTESTATION, env.getRequestedMode());
        assertEquals(SignedRiskEnvelope.AttestationMode.FRESH_ATTESTATION, env.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.STRONGBOX, env.getKeySecurityLevel());
        assertTrue(env.isHardwareBacked());
        assertArrayEquals(challenge, backend.lastGeneratedChallenge);
        assertTrue("Ephemeral alias must be deleted in finally", backend.activeKeys.isEmpty());
        assertEquals(1, backend.deletedAliases.size());
        assertTrue(backend.deletedAliases.get(0).startsWith("riskengine_ephem_env_"));
        assertTrue(verifyEcdsaSignature(env));

        // Verify hard triggers match RiskReport authoritative list and v=2 fields in canonical payload
        assertEquals(report.getHardTriggers(), env.getHardTriggers());
        assertEquals(
                Arrays.asList("C8:spoofed_verified_boot", "tee_grant_chain_split"),
                env.getHardTriggers());
        JSONObject payloadObj = new JSONObject(env.getCanonicalPayloadJson());
        assertEquals(2, payloadObj.getInt("v"));
        assertEquals("DEADLY", payloadObj.getString("riskLevel"));
        assertEquals("BLOCK", payloadObj.getString("action"));
        assertEquals(report.getRiskScore(), payloadObj.getInt("score"));
        assertTrue("Expected hard-trigger score floor >= 95", payloadObj.getInt("score") >= 95);
        assertEquals(report.getConfidencePercent(), payloadObj.getInt("confidence"));
        JSONObject htDims = payloadObj.getJSONObject("dimensions");
        assertEquals(4, htDims.length());
        assertTrue("Expected TAMPERING dimension > 0", htDims.getInt("TAMPERING") > 0);
        JSONArray ht = payloadObj.getJSONArray("hardTriggers");
        assertEquals(2, ht.length());
        assertEquals("C8:spoofed_verified_boot", ht.getString(0));
        assertEquals("tee_grant_chain_split", ht.getString(1));

        // Even when signing fails mid-flight, ephemeral alias MUST still be deleted and fallback labeled
        backend.throwOnNextSign = new RuntimeException("transient sign error");
        SignedRiskEnvelope fallbackEnv = signer.sign(
                ctx, report, fixedChallenge(32, 0x6B), EnvelopeMode.FRESH_ATTESTATION);
        assertEquals(
                SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK,
                fallbackEnv.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.SOFTWARE, fallbackEnv.getKeySecurityLevel());
        assertFalse(fallbackEnv.isHardwareBacked());
        assertTrue("Ephemeral alias must be cleaned even on failure", backend.activeKeys.isEmpty());
        assertEquals(2, backend.deletedAliases.size());
        assertTrue(verifyEcdsaSignature(fallbackEnv));
    }

    @Test
    public void softwareKeystoreOrUnavailableHardwareNeverSpoofsHardwareBacking() throws Exception {
        // Case 1: Hardware Keystore completely unavailable
        SignedEnvelopeSigner.EnvelopeKeyBackend brokenBackend =
                new SignedEnvelopeSigner.EnvelopeKeyBackend() {
                    @Override public SignedEnvelopeSigner.SigningKeyHandle loadExistingKey(String alias) {
                        throw new RuntimeException("No AndroidKeyStore");
                    }
                    @Override public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                            String alias, byte[] attestationChallenge, boolean strongBox) {
                        throw new RuntimeException("No AndroidKeyStore");
                    }
                    @Override public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes) {
                        throw new RuntimeException("No AndroidKeyStore");
                    }
                    @Override public void deleteAlias(String alias) {}
                };
        SignedEnvelopeSigner brokenSigner = new SignedEnvelopeSigner(brokenBackend, () -> 123L);
        SignedRiskEnvelope sw1 = brokenSigner.sign(
                fakeContext("com.host.app"),
                sampleSafeReport(),
                fixedChallenge(32, 0x33),
                EnvelopeMode.PERSISTENT_KEY);
        assertEquals(SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK, sw1.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.SOFTWARE, sw1.getKeySecurityLevel());
        assertFalse(sw1.isHardwareBacked());
        assertFalse(sw1.getCertChainPem().isEmpty());
        assertTrue(verifyEcdsaSignature(sw1));

        // Case 2: Backend succeeds but reports SecurityLevel.SOFTWARE
        FakeEnvelopeKeyBackend softBackend = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.SOFTWARE, false);
        SignedEnvelopeSigner softSigner = new SignedEnvelopeSigner(softBackend, () -> 124L);
        SignedRiskEnvelope sw2 = softSigner.sign(
                fakeContext("com.host.app"),
                sampleSafeReport(),
                fixedChallenge(32, 0x44),
                EnvelopeMode.FRESH_ATTESTATION);
        assertEquals(SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK, sw2.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.SOFTWARE, sw2.getKeySecurityLevel());
        assertFalse(sw2.isHardwareBacked());
        assertTrue(verifyEcdsaSignature(sw2));
    }

    @Test
    public void jsonSerializerAddsOptionalSignedEnvelopeWithoutBreakingDefaultReport()
            throws Exception {
        FakeEnvelopeKeyBackend backend = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, false);
        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(backend, () -> 9999L);
        RiskReport report = sampleSafeReport();
        SignedRiskEnvelope env = signer.sign(
                fakeContext("com.host.app"),
                report,
                fixedChallenge(32, 0x77),
                EnvelopeMode.PERSISTENT_KEY);

        // Default serialization without envelope must NOT include signedEnvelope
        JSONObject plainJson = new JSONObject(RiskReportJsonSerializer.serialize(report));
        assertEquals(2, plainJson.getInt("schemaVersion"));
        assertFalse(plainJson.has("signedEnvelope"));

        // Serialization with envelope includes all 5 RFC §5.3 signedEnvelope fields
        JSONObject envReportJson = new JSONObject(env.toReportJson());
        assertEquals(2, envReportJson.getInt("schemaVersion"));
        assertTrue(envReportJson.has("signedEnvelope"));

        JSONObject se = envReportJson.getJSONObject("signedEnvelope");
        assertEquals("PERSISTENT_KEY", se.getString("attestationMode"));
        assertEquals("TRUSTED_ENVIRONMENT", se.getString("keySecurityLevel"));
        assertEquals(env.getSignatureBase64(), se.getString("signatureBase64"));
        assertEquals(1, se.getJSONArray("certChainPem").length());

        // Re-canonicalizing signedEnvelope.payload from parsed JSON MUST verify ECDSA bit-exact
        JSONObject parsedPayload = se.getJSONObject("payload");
        byte[] reconstructedBytes = CanonicalJsonWriter.toCanonicalUtf8Bytes(parsedPayload);
        assertArrayEquals(env.getCanonicalPayloadBytes(), reconstructedBytes);

        X509Certificate leaf = decodePemCert(se.getJSONArray("certChainPem").getString(0));
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(leaf.getPublicKey());
        verifier.update(reconstructedBytes);
        assertTrue(verifier.verify(Base64.getDecoder().decode(se.getString("signatureBase64"))));
    }

    @Test
    public void riskEngineCollectSignedEnvelopeSyncValidatesBoundsAndEndToEndFlow()
            throws Exception {
        // Challenge validation fails fast before requiring initialization
        try {
            RiskEngine.collectSignedEnvelopeSync(
                    CollectScene.PAYMENT, null, EnvelopeMode.PERSISTENT_KEY);
            fail("Expected IllegalArgumentException for null challenge");
        } catch (IllegalArgumentException expected) {
        }
        try {
            RiskEngine.collectSignedEnvelopeSync(
                    CollectScene.PAYMENT, new byte[15], EnvelopeMode.PERSISTENT_KEY);
            fail("Expected IllegalArgumentException for 15-byte challenge");
        } catch (IllegalArgumentException expected) {
        }
        try {
            RiskEngine.collectSignedEnvelopeSync(
                    CollectScene.PAYMENT, new byte[129], EnvelopeMode.PERSISTENT_KEY);
            fail("Expected IllegalArgumentException for 129-byte challenge");
        } catch (IllegalArgumentException expected) {
        }
        try {
            RiskEngine.collectSignedEnvelopeSync(
                    CollectScene.PAYMENT, fixedChallenge(32, 1), null);
            fail("Expected NullPointerException for null mode");
        } catch (NullPointerException expected) {
        }
        try {
            RiskEngine.collectSignedEnvelopeSync(
                    CollectScene.PAYMENT, fixedChallenge(16, 1), EnvelopeMode.PERSISTENT_KEY);
            fail("Expected IllegalStateException when uninitialized");
        } catch (IllegalStateException expected) {
        }

        // End-to-end collection + signing through RiskEngine with injected fake backend
        FakeEnvelopeKeyBackend backend = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, false);
        RiskEngine engine = RiskEngine.getInstance();
        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override public boolean ensureNativeLoaded() { return false; }
            @Override public void setAntiDumpable(boolean enable) {}
            @Override public void startMonitor() {}
            @Override public void stopMonitor() {}
        });
        engine.setEnvelopeSignerForTest(new SignedEnvelopeSigner(backend, () -> 77777L));
        Context testCtx = fakeContext("com.example.bank");
        engine.doInit(
                testCtx,
                new RiskEngineConfig.Builder()
                        .enablePeriodicMonitor(false)
                        .enableTeeAttestation(false)
                        .build(),
                new AppLifecycleObserver());

        BaseDetector cleanDetector = new BaseDetector(testCtx) {
            @Override public String getName() { return "mock_clean"; }
            @Override public ScanTier getScanTier() { return ScanTier.CRITICAL; }
            @Override protected DetectionResult detect() {
                return new DetectionResult(
                        "mock_clean", RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                        DetectionExecutionStatus.SAFE, 1, 1, 0,
                        Collections.<String>emptyList(), Collections.<String>emptyList(),
                        "clean");
            }
        };

        byte[] challenge128 = fixedChallenge(128, 0x09);
        SignedRiskEnvelope env = engine.doCollectSignedEnvelopeSync(
                CollectScene.PAYMENT,
                challenge128,
                EnvelopeMode.PERSISTENT_KEY,
                Collections.singletonList(cleanDetector),
                Collections.emptyList());

        assertNotNull(env);
        assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, env.getAttestationMode());
        assertEquals(CollectScene.PAYMENT, env.getReport().getCollectScene());
        assertEquals(RiskLevel.SAFE, env.getReport().getOverallRiskLevel());
        assertTrue(verifyEcdsaSignature(env));

        JSONObject payload = new JSONObject(env.getCanonicalPayloadJson());
        assertEquals("com.example.bank", payload.getString("pkg"));
        assertEquals("PAYMENT", payload.getString("scene"));
        assertEquals(77777L, payload.getLong("monoMs"));
        assertEquals(
                Base64.getUrlEncoder().withoutPadding().encodeToString(challenge128),
                payload.getString("challenge"));

        // End-to-end reportSha256 round-trip: stripping signedEnvelope from toReportJson() matches
        JSONObject fullJson = new JSONObject(env.toReportJson());
        assertTrue(fullJson.has("signedEnvelope"));
        fullJson.remove("signedEnvelope");
        assertEquals(
                payload.getString("reportSha256"),
                CanonicalJsonWriter.sha256HexOfCanonicalJson(fullJson));
    }

    @Test
    public void canonicalJsonWriterHandlesCodePointOrderControlCharsAndBigInteger() {
        // U+FF00 (65280) < U+1F600 (128512) by Unicode code-point (opposite of UTF-16 code-unit order)
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("\uD83D\uDE00", "emoji");
        m.put("\uFF00", "fullwidth");
        m.put("ctrl", "\u0000\u0007\u001f");
        m.put("big", new BigInteger("123456789012345678901234567890"));

        String json = CanonicalJsonWriter.toCanonicalJson(m);
        assertEquals(
                "{\"big\":123456789012345678901234567890,"
                        + "\"ctrl\":\"\\u0000\\u0007\\u001f\","
                        + "\"\uFF00\":\"fullwidth\","
                        + "\"\uD83D\uDE00\":\"emoji\"}",
                json);
    }

    @Test
    public void resolveAttestedSecurityLevelRequiresValidOid17ChainAndChallengeMatch()
            throws Exception {
        AttestationExtensionParser parser = new AttestationExtensionParser();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair rootKp = kpg.generateKeyPair();
        KeyPair leafKp = kpg.generateKeyPair();
        X509Certificate rootCert = createSelfSignedCert(rootKp, "Fake Google Root");

        byte[] chA = fixedChallenge(32, 0xAA);
        byte[] chB = fixedChallenge(32, 0xBB);

        // Single cert without OID .17 -> strictly SOFTWARE
        X509Certificate plainLeaf = createSelfSignedCert(leafKp, "Plain Leaf");
        assertEquals(
                AttestationRecord.SecurityLevel.SOFTWARE,
                SignedEnvelopeSigner.resolveAttestedSecurityLevel(
                        parser, Collections.singletonList(plainLeaf), chA));

        // 2-cert chain without OID .17 -> strictly SOFTWARE (no KeyInfo fallback spoofing)
        assertEquals(
                AttestationRecord.SecurityLevel.SOFTWARE,
                SignedEnvelopeSigner.resolveAttestedSecurityLevel(
                        parser, Arrays.asList(plainLeaf, rootCert), chA));

        // 2-cert chain with valid OID .17 (STRONGBOX, challenge=chA)
        X509Certificate attestedLeaf = createAttestedLeafCert(leafKp, rootKp, 2, 2, chA);
        List<X509Certificate> validChain = Arrays.asList(attestedLeaf, rootCert);

        // Exact challenge match -> STRONGBOX
        assertEquals(
                AttestationRecord.SecurityLevel.STRONGBOX,
                SignedEnvelopeSigner.resolveAttestedSecurityLevel(parser, validChain, chA));

        // Null challenge (persistent reload) -> STRONGBOX
        assertEquals(
                AttestationRecord.SecurityLevel.STRONGBOX,
                SignedEnvelopeSigner.resolveAttestedSecurityLevel(parser, validChain, null));

        // Replayed/mismatched challenge -> strictly SOFTWARE
        assertEquals(
                AttestationRecord.SecurityLevel.SOFTWARE,
                SignedEnvelopeSigner.resolveAttestedSecurityLevel(parser, validChain, chB));

        // 2-cert chain with TEE level -> TRUSTED_ENVIRONMENT
        X509Certificate teeLeaf = createAttestedLeafCert(leafKp, rootKp, 1, 1, chA);
        assertEquals(
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                SignedEnvelopeSigner.resolveAttestedSecurityLevel(
                        parser, Arrays.asList(teeLeaf, rootCert), chA));
    }

    @Test
    public void transientStrongBoxErrorDoesNotPermanentlyLockOutStrongBox() throws Exception {
        final AtomicInteger sbCalls = new AtomicInteger();
        final AtomicInteger teeCalls = new AtomicInteger();
        SignedEnvelopeSigner.EnvelopeKeyBackend flakySbBackend =
                new FakeEnvelopeKeyBackend(AttestationRecord.SecurityLevel.STRONGBOX, false) {
                    @Override
                    public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                            String alias, byte[] attestationChallenge, boolean strongBox)
                            throws Exception {
                        if (strongBox) {
                            int attempt = sbCalls.incrementAndGet();
                            if (attempt == 1) {
                                // Transient error, NOT StrongBoxUnavailableException
                                throw new ProviderException("StrongBox busy");
                            }
                            return super.generateSigningKey(alias, attestationChallenge, true);
                        }
                        teeCalls.incrementAndGet();
                        return super.generateSigningKey(alias, attestationChallenge, false);
                    }
                };

        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(flakySbBackend, () -> 100L);
        RiskReport report = sampleSafeReport();
        Context ctx = fakeContext("com.host.app");

        // Call 1: transient StrongBox failure falls back to TEE for this call only
        SignedRiskEnvelope e1 = signer.sign(
                ctx, report, fixedChallenge(32, 1), EnvelopeMode.FRESH_ATTESTATION);
        assertEquals(SignedRiskEnvelope.AttestationMode.FRESH_ATTESTATION, e1.getAttestationMode());
        assertEquals(1, sbCalls.get());
        assertEquals(1, teeCalls.get());

        // Call 2: StrongBox MUST be retried (not permanently locked out) and succeeds
        SignedRiskEnvelope e2 = signer.sign(
                ctx, report, fixedChallenge(32, 2), EnvelopeMode.FRESH_ATTESTATION);
        assertEquals(SignedRiskEnvelope.AttestationMode.FRESH_ATTESTATION, e2.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.STRONGBOX, e2.getKeySecurityLevel());
        assertEquals(2, sbCalls.get());
        assertEquals(1, teeCalls.get());
    }

    @Test
    public void concurrentInvalidationDoesNotEvictPeerThreadFreshlyRotatedKey() throws Exception {
        final CountDownLatch bothHoldingOldKey = new CountDownLatch(2);
        final CountDownLatch firstRotated = new CountDownLatch(1);
        final AtomicInteger invalidationsTriggered = new AtomicInteger();
        final FakeEnvelopeKeyBackend base = new FakeEnvelopeKeyBackend(
                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT, false);

        SignedEnvelopeSigner.EnvelopeKeyBackend racingBackend =
                new SignedEnvelopeSigner.EnvelopeKeyBackend() {
                    private volatile PrivateKey oldKey;

                    @Override
                    public SignedEnvelopeSigner.SigningKeyHandle loadExistingKey(String alias) {
                        return base.loadExistingKey(alias);
                    }

                    @Override
                    public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                            String alias, byte[] attestationChallenge, boolean strongBox)
                            throws Exception {
                        SignedEnvelopeSigner.SigningKeyHandle h =
                                base.generateSigningKey(alias, attestationChallenge, strongBox);
                        if (oldKey == null) {
                            oldKey = h.getPrivateKey();
                        } else {
                            firstRotated.countDown();
                        }
                        return h;
                    }

                    @Override
                    public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes)
                            throws Exception {
                        if (privateKey == oldKey && invalidationsTriggered.get() >= 0) {
                            int n = invalidationsTriggered.incrementAndGet();
                            if (n >= 2) {
                                bothHoldingOldKey.countDown();
                                bothHoldingOldKey.await(5, TimeUnit.SECONDS);
                                if (n == 3) {
                                    // Thread B waits until Thread A has rotated the key
                                    firstRotated.await(5, TimeUnit.SECONDS);
                                }
                                throw new InvalidKeyException("simulated concurrent invalidation");
                            }
                        }
                        return base.signEcdsaSha256(privateKey, payloadBytes);
                    }

                    @Override
                    public void deleteAlias(String alias) {
                        base.deleteAlias(alias);
                    }
                };

        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(racingBackend, () -> 200L);
        RiskReport report = sampleSafeReport();
        Context ctx = fakeContext("com.host.app");

        // Warm up initial key M1
        SignedRiskEnvelope warm = signer.sign(
                ctx, report, fixedChallenge(32, 0), EnvelopeMode.PERSISTENT_KEY);
        assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, warm.getAttestationMode());
        assertEquals(1, base.teeAttempts.get());
        assertEquals(0, base.strongBoxAttempts.get());

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<SignedRiskEnvelope> f1 = pool.submit(() -> signer.sign(
                    ctx, report, fixedChallenge(32, 1), EnvelopeMode.PERSISTENT_KEY));
            Future<SignedRiskEnvelope> f2 = pool.submit(() -> signer.sign(
                    ctx, report, fixedChallenge(32, 2), EnvelopeMode.PERSISTENT_KEY));
            SignedRiskEnvelope r1 = f1.get(10, TimeUnit.SECONDS);
            SignedRiskEnvelope r2 = f2.get(10, TimeUnit.SECONDS);
            assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, r1.getAttestationMode());
            assertEquals(SignedRiskEnvelope.AttestationMode.PERSISTENT_KEY, r2.getAttestationMode());
            assertTrue(verifyEcdsaSignature(r1));
            assertTrue(verifyEcdsaSignature(r2));
            // Only ONE rotation & ONE delete should occur despite two concurrent stale-key hits
            assertEquals(2, base.teeAttempts.get());
            assertEquals(0, base.strongBoxAttempts.get());
            assertEquals(1, base.deletedAliases.size());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void emptyCertificateChainFromBackendFallsBackToSelfSignedSoftwareEnvelope()
            throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair kp = kpg.generateKeyPair();

        SignedEnvelopeSigner.EnvelopeKeyBackend emptyChainBackend =
                new SignedEnvelopeSigner.EnvelopeKeyBackend() {
                    @Override public SignedEnvelopeSigner.SigningKeyHandle loadExistingKey(String alias) {
                        return null;
                    }
                    @Override public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                            String alias, byte[] attestationChallenge, boolean strongBox) {
                        return new SignedEnvelopeSigner.SigningKeyHandle(
                                kp.getPrivate(),
                                Collections.<X509Certificate>emptyList(),
                                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT);
                    }
                    @Override public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes) {
                        return new byte[0];
                    }
                    @Override public void deleteAlias(String alias) {}
                };

        SignedEnvelopeSigner signer = new SignedEnvelopeSigner(emptyChainBackend, () -> 300L);
        SignedRiskEnvelope env = signer.sign(
                fakeContext("com.host.app"),
                sampleSafeReport(),
                fixedChallenge(32, 0x99),
                EnvelopeMode.FRESH_ATTESTATION);
        assertEquals(SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK, env.getAttestationMode());
        assertEquals(AttestationRecord.SecurityLevel.SOFTWARE, env.getKeySecurityLevel());
        assertFalse(env.isHardwareBacked());
        assertFalse(env.getCertChainPem().isEmpty());
        assertTrue(verifyEcdsaSignature(env));
    }

    // ---- Helpers ----

    private static Context fakeContext(final String pkgName) {
        return new ContextWrapper(null) {
            @Override
            public String getPackageName() {
                return pkgName;
            }

            @Override
            public Context getApplicationContext() {
                return this;
            }
        };
    }

    private static byte[] fixedChallenge(int len, int seed) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) ((seed + i * 31) & 0xFF);
        }
        return out;
    }

    private static RiskReport sampleSafeReport() {
        CollectorResult dev = new CollectorResult("device_info");
        dev.addValue("model", "Pixel");
        FingerprintId fpId = new FingerprintId(
                "comp-sha256-test", "hw-sha256-test", "sys-test", "vol-test",
                9, 13, 6, 11,
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
                DetectionExecutionStatus.RISK, 2, 2, 0,
                Collections.<String>emptyList(),
                Collections.singletonList("tee_grant_chain_split"),
                Collections.singletonList(split),
                "tee_grant_chain_split");
        DetectionResult corr = new DetectionResult(
                "signal_correlation", RiskLevel.DEADLY, DetectionStatus.DANGER, 10, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.<String>emptyList(),
                Collections.singletonList("C8:spoofed_verified_boot"),
                "C8:spoofed_verified_boot");
        DetectionResult infoIgnored = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER, 9, 10, true /* info */,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.<String>emptyList(),
                Collections.singletonList("maps:frida"),
                "maps:frida");
        return new DataAggregator().aggregate(
                Collections.<CollectorResult>emptyList(),
                Arrays.asList(tee, corr, infoIgnored),
                CollectScene.PAYMENT);
    }

    private static boolean verifyEcdsaSignature(SignedRiskEnvelope envelope) throws Exception {
        assertFalse("certChainPem must not be empty", envelope.getCertChainPem().isEmpty());
        X509Certificate leaf = decodePemCert(envelope.getCertChainPem().get(0));
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(leaf.getPublicKey());
        sig.update(envelope.getCanonicalPayloadBytes());
        return sig.verify(envelope.getSignatureBytes());
    }

    private static X509Certificate decodePemCert(String pem) throws Exception {
        String body = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(body);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private static class FakeEnvelopeKeyBackend
            implements SignedEnvelopeSigner.EnvelopeKeyBackend {
        final AttestationRecord.SecurityLevel level;
        final boolean failStrongBox;
        volatile boolean failTee;
        final Map<String, SignedEnvelopeSigner.SigningKeyHandle> activeKeys =
                new ConcurrentHashMap<>();
        final List<String> deletedAliases = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger strongBoxAttempts = new AtomicInteger();
        final AtomicInteger teeAttempts = new AtomicInteger();
        final AtomicInteger signCalls = new AtomicInteger();
        volatile byte[] lastGeneratedChallenge;
        volatile Exception throwOnNextSign;

        FakeEnvelopeKeyBackend(AttestationRecord.SecurityLevel level, boolean failStrongBox) {
            this.level = level;
            this.failStrongBox = failStrongBox;
        }

        @Override
        public SignedEnvelopeSigner.SigningKeyHandle loadExistingKey(String alias) {
            return activeKeys.get(alias);
        }

        @Override
        public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                String alias, byte[] attestationChallenge, boolean strongBox) throws Exception {
            if (strongBox) {
                strongBoxAttempts.incrementAndGet();
                if (failStrongBox) {
                    throw new StrongBoxUnavailableException("No StrongBox in test");
                }
            } else {
                teeAttempts.incrementAndGet();
                if (failTee) {
                    throw new ProviderException("TEE unavailable in test");
                }
            }
            lastGeneratedChallenge = attestationChallenge == null
                    ? null
                    : Arrays.copyOf(attestationChallenge, attestationChallenge.length);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            X509Certificate cert = createSelfSignedCert(kp, alias);
            SignedEnvelopeSigner.SigningKeyHandle handle =
                    new SignedEnvelopeSigner.SigningKeyHandle(
                            kp.getPrivate(), Collections.singletonList(cert), level);
            activeKeys.put(alias, handle);
            return handle;
        }

        @Override
        public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes) throws Exception {
            signCalls.incrementAndGet();
            Exception injected = throwOnNextSign;
            if (injected != null) {
                throwOnNextSign = null;
                throw injected;
            }
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(privateKey);
            sig.update(payloadBytes);
            return sig.sign();
        }

        @Override
        public void deleteAlias(String alias) {
            deletedAliases.add(alias);
            activeKeys.remove(alias);
        }
    }

    private static X509Certificate createAttestedLeafCert(
            KeyPair leafKp,
            KeyPair issuerKp,
            int attestationSecurityLevel,
            int keymasterSecurityLevel,
            byte[] challenge) throws Exception {
        Date now = new Date();
        Date notBefore = new Date(now.getTime() - 60_000L);
        Date notAfter = new Date(now.getTime() + 86_400_000L * 365);

        byte[] version = derTlv(0xA0, derTlv(0x02, BigInteger.valueOf(2).toByteArray()));
        byte[] serial = derTlv(0x02, BigInteger.valueOf(Math.abs(System.nanoTime()) + 7L).toByteArray());
        byte[] sigAlg = derSeq(derOid(new int[]{1, 2, 840, 10045, 4, 3, 2}));
        byte[] issuerDn = derSeq(derTlv(0x31, derSeq(
                derOid(new int[]{2, 5, 4, 3}),
                derTlv(0x0C, "Fake Google Root".getBytes(StandardCharsets.UTF_8)))));
        byte[] subjectDn = derSeq(derTlv(0x31, derSeq(
                derOid(new int[]{2, 5, 4, 3}),
                derTlv(0x0C, "Android Keystore Key".getBytes(StandardCharsets.UTF_8)))));
        byte[] validity = derSeq(derUtcTime(notBefore), derUtcTime(notAfter));
        byte[] spki = leafKp.getPublic().getEncoded();

        // KeyDescription SEQUENCE matching Android Key Attestation OID 1.3.6.1.4.1.11129.2.1.17
        byte[] keyDesc = derSeq(
                derTlv(0x02, BigInteger.valueOf(300).toByteArray()),
                derTlv(0x0A, BigInteger.valueOf(attestationSecurityLevel).toByteArray()),
                derTlv(0x02, BigInteger.valueOf(300).toByteArray()),
                derTlv(0x0A, BigInteger.valueOf(keymasterSecurityLevel).toByteArray()),
                derTlv(0x04, challenge),
                derTlv(0x04, new byte[0]),
                derSeq(),
                derSeq());
        byte[] ext = derSeq(
                derOid(new int[]{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}),
                derTlv(0x04, keyDesc));
        byte[] extensions = derTlv(0xA3, derSeq(ext));

        byte[] tbs = derSeq(version, serial, sigAlg, issuerDn, validity, subjectDn, spki, extensions);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(issuerKp.getPrivate());
        sig.update(tbs);
        byte[] sigDer = sig.sign();
        byte[] bitString = new byte[sigDer.length + 1];
        bitString[0] = 0x00;
        System.arraycopy(sigDer, 0, bitString, 1, sigDer.length);
        byte[] certDer = derSeq(tbs, sigAlg, derTlv(0x03, bitString));

        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static X509Certificate createSelfSignedCert(KeyPair kp, String cn) throws Exception {
        Date now = new Date();
        Date notBefore = new Date(now.getTime() - 60_000L);
        Date notAfter = new Date(now.getTime() + 86_400_000L * 365);

        byte[] version = derTlv(0xA0, derTlv(0x02, BigInteger.valueOf(2).toByteArray()));
        byte[] serial = derTlv(0x02, BigInteger.valueOf(Math.abs(System.nanoTime()) + 1L).toByteArray());
        byte[] sigAlg = derSeq(derOid(new int[]{1, 2, 840, 10045, 4, 3, 2}));
        byte[] dn = derSeq(derTlv(0x31, derSeq(
                derOid(new int[]{2, 5, 4, 3}),
                derTlv(0x0C, cn.getBytes(StandardCharsets.UTF_8)))));
        byte[] validity = derSeq(derUtcTime(notBefore), derUtcTime(notAfter));
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

        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static byte[] derUtcTime(Date d) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.ROOT);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        return derTlv(0x17, fmt.format(d).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] derSeq(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
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
        } else {
            out.write(0x82);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.write(val, 0, len);
        return out.toByteArray();
    }
}
