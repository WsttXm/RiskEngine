package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.attestation.AttestationExtensionParser;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.attestation.CertificateTrustAnalyzer;
import com.wsttxm.riskenginesdk.attestation.GoogleAttestationRootStore;
import com.wsttxm.riskenginesdk.attestation.RkpExtensionParser;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Unit tests for P3-2: {@link GoogleAttestationRootStore}, {@link CertificateTrustAnalyzer},
 * {@link AttestationCapability}, {@link RiskEngineConfig#isEnableTeeAttestation()}, and
 * {@link SignalSnapshot#getAttestationSnapshot(boolean)}.
 */
public class AttestationTrustAndCapabilityTest {

    // -------------------------------------------------------------------------
    // GoogleAttestationRootStore monotonic floor & root anchors
    // -------------------------------------------------------------------------

    @Test
    public void googleRootStoreEmbedsAnchorsAndMonotonicCrlFloor() {
        GoogleAttestationRootStore def = GoogleAttestationRootStore.getDefault();
        assertTrue(def.getRootSpkiSha256Set().size() >= 2);
        assertTrue(def.getRootCertSha256Set().size() >= 2);
        assertTrue("Expected full offline revoked floor (>= 1600)", def.getBuiltinRevokedFloorSize() >= 1600);

        // Known revoked legacy 64-bit decimal serial & modern 128-bit hex serial
        assertTrue(def.isRevokedSerial(new BigInteger("6681152659205225093", 10)));
        assertTrue(def.isRevokedSerial(new BigInteger("c35747a084470c3135aeefe2b8d40cd6", 16)));
        assertFalse(def.isRevokedSerial(BigInteger.valueOf(123456789L)));

        // Monotonic merge never downgrades when given null/empty
        GoogleAttestationRootStore copy = GoogleAttestationRootStore.withAdditions(null, null);
        int baseSize = copy.getTotalRevokedSize();
        copy.mergeRevokedSerials(null);
        copy.mergeRevokedSerials(Collections.<String>emptyList());
        assertEquals(baseSize, copy.getTotalRevokedSize());

        copy.mergeRevokedSerials(Collections.singletonList("00deadbeefcafe1234"));
        assertEquals(baseSize + 1, copy.getTotalRevokedSize());
        assertTrue(copy.isRevokedSerial(new BigInteger("deadbeefcafe1234", 16)));
        assertTrue(copy.isRevokedSerial(new BigInteger("6681152659205225093", 10)));
    }

    // -------------------------------------------------------------------------
    // CertificateTrustAnalyzer full cryptographic chain, validity, anchor & CRL
    // -------------------------------------------------------------------------

    @Test
    public void certificateTrustAnalyzerValidatesGoodTamperedExpiredRevokedAndAospChains()
            throws Exception {
        KeyPair rootKp = genEcKeyPair();
        KeyPair interKp = genEcKeyPair();
        KeyPair leafKp = genEcKeyPair();

        Date now = new Date();
        Date past = new Date(now.getTime() - 86_400_000L * 30);
        Date future = new Date(now.getTime() + 86_400_000L * 365);

        X509Certificate rootCert = buildSignedX509(
                BigInteger.valueOf(1001L),
                "Google Test Hardware Root",
                "Google Test Hardware Root",
                past, future, rootKp.getPublic(), rootKp.getPrivate(), true, null);
        X509Certificate interCert = buildSignedX509(
                BigInteger.valueOf(2002L),
                "Google Test Hardware Root",
                "Google Test Intermediate",
                past, future, interKp.getPublic(), rootKp.getPrivate(), true, null);
        X509Certificate leafCert = buildSignedX509(
                BigInteger.valueOf(3003L),
                "Google Test Intermediate",
                "Android Keystore Key",
                past, future, leafKp.getPublic(), interKp.getPrivate(), false, null);

        String rootSpki = GoogleAttestationRootStore.sha256SpkiHex(rootCert);
        GoogleAttestationRootStore store = GoogleAttestationRootStore.withAdditions(
                Collections.singletonList(rootSpki), null);
        CertificateTrustAnalyzer analyzer = new CertificateTrustAnalyzer(store);

        // 1. Valid trusted chain
        CertificateTrustAnalyzer.TrustResult ok = analyzer.inspect(
                Arrays.asList(leafCert, interCert, rootCert), now);
        assertTrue(ok.isChainSignatureValid());
        assertTrue(ok.isGoogleRootMatched());
        assertTrue(ok.isValidityWindowValid());
        assertTrue(ok.isIssuerChainValid());
        assertFalse(ok.isAnyCertRevoked());
        assertEquals(CertificateTrustAnalyzer.TrustRoot.GOOGLE, ok.getTrustRoot());
        assertTrue(ok.isFullyTrustedGoogleHardware());

        // 2. Tampered signature (leaf signed by wrong key)
        X509Certificate badSigLeaf = buildSignedX509(
                BigInteger.valueOf(3004L),
                "Google Test Intermediate",
                "Android Keystore Key",
                past, future, leafKp.getPublic(), rootKp.getPrivate(), false, null);
        CertificateTrustAnalyzer.TrustResult badSig = analyzer.inspect(
                Arrays.asList(badSigLeaf, interCert, rootCert), now);
        assertFalse(badSig.isChainSignatureValid());
        assertFalse(badSig.isFullyTrustedGoogleHardware());

        // 3. Expired evaluation time
        Date afterExpiry = new Date(future.getTime() + 86_400_000L);
        CertificateTrustAnalyzer.TrustResult expired = analyzer.inspect(
                Arrays.asList(leafCert, interCert, rootCert), afterExpiry);
        assertFalse(expired.isValidityWindowValid());
        assertFalse(expired.isFullyTrustedGoogleHardware());

        // 4. Revoked intermediate keybox serial (real Google CRL decimal serial)
        X509Certificate revokedInter = buildSignedX509(
                new BigInteger("6681152659205225093", 10),
                "Google Test Hardware Root",
                "Google Test Intermediate",
                past, future, interKp.getPublic(), rootKp.getPrivate(), true, null);
        CertificateTrustAnalyzer.TrustResult revoked = analyzer.inspect(
                Arrays.asList(leafCert, revokedInter, rootCert), now);
        assertTrue(revoked.isChainSignatureValid());
        assertTrue(revoked.isAnyCertRevoked());
        assertFalse(revoked.getRevokedSerials().isEmpty());
        assertFalse(revoked.isFullyTrustedGoogleHardware());

        // 5. AOSP software root
        X509Certificate aospRoot = buildSignedX509(
                BigInteger.valueOf(99L),
                "Android Keystore Software Attestation Root",
                "Android Keystore Software Attestation Root",
                past, future, rootKp.getPublic(), rootKp.getPrivate(), true, null);
        X509Certificate aospLeaf = buildSignedX509(
                BigInteger.valueOf(100L),
                "Android Keystore Software Attestation Root",
                "Android Keystore Key",
                past, future, leafKp.getPublic(), rootKp.getPrivate(), false, null);
        CertificateTrustAnalyzer defaultAnalyzer = new CertificateTrustAnalyzer(
                GoogleAttestationRootStore.getDefault());
        CertificateTrustAnalyzer.TrustResult aospRes = defaultAnalyzer.inspect(
                Arrays.asList(aospLeaf, aospRoot), now);
        assertFalse(aospRes.isGoogleRootMatched());
        assertEquals(CertificateTrustAnalyzer.TrustRoot.AOSP_SOFTWARE, aospRes.getTrustRoot());
        assertFalse(aospRes.isFullyTrustedGoogleHardware());
    }

    // -------------------------------------------------------------------------
    // AttestationCapability StrongBox -> TEE fallback & deterministic cleanup
    // -------------------------------------------------------------------------

    @Test
    public void attestationCapabilityFallsBackStrongBoxToTeeAndDeletesAllAliases()
            throws Exception {
        KeyPair rootKp = genEcKeyPair();
        KeyPair leafKp = genEcKeyPair();
        Date now = new Date();
        Date past = new Date(now.getTime() - 86_400_000L);
        Date future = new Date(now.getTime() + 86_400_000L * 30);

        X509Certificate rootCert = buildSignedX509(
                BigInteger.valueOf(11L),
                "Google Hardware Root",
                "Google Hardware Root",
                past, future, rootKp.getPublic(), rootKp.getPrivate(), true, null);
        GoogleAttestationRootStore testStore = GoogleAttestationRootStore.withAdditions(
                Collections.singletonList(GoogleAttestationRootStore.sha256SpkiHex(rootCert)), null);

        List<String> createdAliases = new ArrayList<>();
        List<String> deletedAliases = new ArrayList<>();
        AtomicInteger strongBoxCalls = new AtomicInteger();
        AtomicInteger teeCalls = new AtomicInteger();

        AttestationCapability.KeyAttestationBackend backend = new AttestationCapability.KeyAttestationBackend() {
            @Override
            public List<X509Certificate> generateAttestationChain(
                    String alias, byte[] challenge, boolean strongBox) throws Exception {
                createdAliases.add(alias);
                assertEquals("Challenge must be 32 bytes", 32, challenge.length);
                if (strongBox) {
                    strongBoxCalls.incrementAndGet();
                    throw new IllegalStateException("StrongBoxUnavailable");
                }
                teeCalls.incrementAndGet();
                byte[] ext = buildSimpleLockedAttestationExtension(challenge);
                X509Certificate leaf = buildSignedX509(
                        BigInteger.valueOf(22L),
                        "Google Hardware Root",
                        "Android Keystore Key",
                        past, future, leafKp.getPublic(), rootKp.getPrivate(), false, ext);
                return Arrays.asList(leaf, rootCert);
            }

            @Override
            public void deleteAlias(String alias) {
                deletedAliases.add(alias);
            }
        };

        AttestationCapability capability = new AttestationCapability(
                backend,
                new AttestationExtensionParser(),
                new CertificateTrustAnalyzer(testStore),
                new RkpExtensionParser(),
                new SecureRandom());

        AttestationCapability.AttestationSnapshot snap = capability.collect(now);
        assertTrue(snap.isAvailable());
        assertFalse(snap.isUsedStrongBox());
        assertTrue(snap.isFallbackFromStrongBox());
        assertEquals(1, strongBoxCalls.get());
        assertEquals(1, teeCalls.get());
        assertEquals("Every ephemeral alias must be deleted in finally", createdAliases, deletedAliases);
        assertTrue(snap.isHardwareVerifiedLocked());
        assertNotNull(snap.getRecord());
        assertTrue(snap.getRecord().isChallengeMatched());
    }

    @Test
    public void attestationCapabilityHandlesLinkageErrorAndOomWithoutCrashing() {
        List<String> deleted = new ArrayList<>();
        AttestationCapability.KeyAttestationBackend failingBackend = new AttestationCapability.KeyAttestationBackend() {
            @Override
            public List<X509Certificate> generateAttestationChain(
                    String alias, byte[] challenge, boolean strongBox) {
                if (strongBox) {
                    throw new LinkageError("simulated linkage error");
                }
                throw new OutOfMemoryError("simulated oom");
            }

            @Override
            public void deleteAlias(String alias) {
                deleted.add(alias);
            }
        };

        AttestationCapability cap = new AttestationCapability(
                failingBackend,
                new AttestationExtensionParser(),
                new CertificateTrustAnalyzer(),
                new RkpExtensionParser(),
                new SecureRandom());

        AttestationCapability.AttestationSnapshot snap = cap.collect();
        assertFalse(snap.isAvailable());
        assertTrue(snap.isFallbackFromStrongBox());
        assertNotNull(snap.getFailureReason());
        assertTrue(snap.getFailureReason().contains("OutOfMemoryError"));
        assertEquals("Both StrongBox and TEE temp aliases must still be cleaned up", 2, deleted.size());
    }

    @Test
    public void configDefaultAndSignalSnapshotCachingWorkCleanly() {
        RiskEngineConfig def = new RiskEngineConfig.Builder().build();
        assertTrue(def.isEnableTeeAttestation());

        RiskEngineConfig disabled = new RiskEngineConfig.Builder()
                .enableTeeAttestation(false)
                .build();
        assertFalse(disabled.isEnableTeeAttestation());

        SignalSnapshot snapshot = new SignalSnapshot(null);
        SignalResult<AttestationCapability.AttestationSnapshot> off =
                snapshot.getAttestationSnapshot(false);
        assertEquals(SignalResult.Status.UNAVAILABLE, off.getStatus());
        assertEquals("tee_attestation_disabled", off.getFailureReason());

        AttestationCapability.AttestationSnapshot seeded =
                AttestationCapability.AttestationSnapshot.builder().available(true).build();
        snapshot.seedAttestationSnapshotForTest(SignalResult.success(seeded));
        SignalResult<AttestationCapability.AttestationSnapshot> hit =
                snapshot.getAttestationSnapshot(true);
        assertTrue(hit.isSuccess());
        assertSame(seeded, hit.getValue());

        snapshot.reset();
        // After reset, pure JVM AndroidKeyStore is unavailable (must degrade without crashing)
        SignalResult<AttestationCapability.AttestationSnapshot> afterReset =
                snapshot.getAttestationSnapshot(true);
        assertNotNull(afterReset);
        assertFalse(afterReset.isSuccess());
        // Consecutive calls hit cached result
        SignalResult<AttestationCapability.AttestationSnapshot> secondCall =
                snapshot.getAttestationSnapshot(true);
        assertSame(afterReset, secondCall);
    }

    @Test
    public void certificateTrustAnalyzerEnforcesPathLenKeyUsageNotYetValidSelfIssuedAndNegativeSerial()
            throws Exception {
        KeyPair rootKp = genEcKeyPair();
        KeyPair inter1Kp = genEcKeyPair();
        KeyPair inter2Kp = genEcKeyPair();
        KeyPair leafKp = genEcKeyPair();

        Date now = new Date();
        Date past = new Date(now.getTime() - 86_400_000L * 30);
        Date future = new Date(now.getTime() + 86_400_000L * 365);

        X509Certificate rootCert = buildSignedX509Full(
                BigInteger.valueOf(1L), "Root", "Root", past, future,
                rootKp.getPublic(), rootKp.getPrivate(), true, null, true, null);
        // inter1 has pathLenConstraint = 0 (cannot issue another intermediate CA)
        X509Certificate inter1PathLen0 = buildSignedX509Full(
                BigInteger.valueOf(2L), "Root", "Inter1", past, future,
                inter1Kp.getPublic(), rootKp.getPrivate(), true, 0, true, null);
        X509Certificate inter2 = buildSignedX509Full(
                BigInteger.valueOf(3L), "Inter1", "Inter2", past, future,
                inter2Kp.getPublic(), inter1Kp.getPrivate(), true, null, true, null);
        X509Certificate leafUnderInter2 = buildSignedX509Full(
                BigInteger.valueOf(4L), "Inter2", "Leaf", past, future,
                leafKp.getPublic(), inter2Kp.getPrivate(), false, null, false, null);

        GoogleAttestationRootStore store = GoogleAttestationRootStore.withAdditions(
                Collections.singletonList(GoogleAttestationRootStore.sha256SpkiHex(rootCert)),
                Collections.singletonList("ff01020304050607"));
        CertificateTrustAnalyzer analyzer = new CertificateTrustAnalyzer(store);

        // 1. pathLenConstraint=0 exceeded by inter2
        CertificateTrustAnalyzer.TrustResult pathLenRes = analyzer.inspect(
                Arrays.asList(leafUnderInter2, inter2, inter1PathLen0, rootCert), now);
        assertTrue(pathLenRes.isChainSignatureValid());
        assertFalse(pathLenRes.isIssuerChainValid());
        assertTrue(pathLenRes.getIssuerMismatches().contains("cert_2_pathlen_exceeded"));
        assertFalse(pathLenRes.isFullyTrustedGoogleHardware());

        // 2. Non-CA issuer & missing keyCertSign
        X509Certificate nonCaIssuer = buildSignedX509Full(
                BigInteger.valueOf(5L), "Root", "NonCA", past, future,
                inter1Kp.getPublic(), rootKp.getPrivate(), false, null, false, null);
        X509Certificate leafUnderNonCa = buildSignedX509Full(
                BigInteger.valueOf(6L), "NonCA", "Leaf", past, future,
                leafKp.getPublic(), inter1Kp.getPrivate(), false, null, false, null);
        CertificateTrustAnalyzer.TrustResult nonCaRes = analyzer.inspect(
                Arrays.asList(leafUnderNonCa, nonCaIssuer, rootCert), now);
        assertFalse(nonCaRes.isIssuerChainValid());
        assertTrue(nonCaRes.getIssuerMismatches().contains("cert_1_not_ca"));
        assertTrue(nonCaRes.getIssuerMismatches().contains("cert_1_missing_key_cert_sign"));

        // 3. Single-cert non-CA & non-self-issued root
        X509Certificate nonSelfRoot = buildSignedX509Full(
                BigInteger.valueOf(7L), "Other", "Leaf", past, future,
                leafKp.getPublic(), leafKp.getPrivate(), false, null, false, null);
        CertificateTrustAnalyzer.TrustResult singleRes = analyzer.inspect(
                Collections.singletonList(nonSelfRoot), now);
        assertFalse(singleRes.isIssuerChainValid());
        assertTrue(singleRes.getIssuerMismatches().contains("root_not_self_issued"));
        assertTrue(singleRes.getIssuerMismatches().contains("cert_0_not_ca"));

        // 4. Not yet valid (evalDate before notBefore)
        Date beforeValid = new Date(past.getTime() - 86_400_000L);
        CertificateTrustAnalyzer.TrustResult notYetRes = analyzer.inspect(
                Arrays.asList(leafUnderNonCa, rootCert), beforeValid);
        assertFalse(notYetRes.isValidityWindowValid());

        // 5. Issuer/Subject DN mismatch
        X509Certificate dnMismatchLeaf = buildSignedX509Full(
                BigInteger.valueOf(8L), "WrongIssuer", "Leaf", past, future,
                leafKp.getPublic(), rootKp.getPrivate(), false, null, false, null);
        CertificateTrustAnalyzer.TrustResult dnRes = analyzer.inspect(
                Arrays.asList(dnMismatchLeaf, rootCert), now);
        assertFalse(dnRes.isIssuerChainValid());
        assertTrue(dnRes.getIssuerMismatches().contains("cert_0_issuer_mismatch"));

        // 6. Negative BigInteger serial (unsigned match without leading minus sign)
        BigInteger negSerial = new BigInteger(new byte[] {(byte) 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        assertTrue(negSerial.signum() < 0);
        X509Certificate negSerialLeaf = buildSignedX509Full(
                negSerial, "Root", "Leaf", past, future,
                leafKp.getPublic(), rootKp.getPrivate(), false, null, false, null);
        CertificateTrustAnalyzer.TrustResult negRes = analyzer.inspect(
                Arrays.asList(negSerialLeaf, rootCert), now);
        assertTrue(negRes.isAnyCertRevoked());
        assertEquals(Collections.singletonList("ff01020304050607"), negRes.getRevokedSerials());
    }

    @Test
    public void attestationCapabilityStrongBoxDirectSuccessEmptyFallbackDeleteThrowAndHardGuards()
            throws Exception {
        KeyPair rootKp = genEcKeyPair();
        KeyPair leafKp = genEcKeyPair();
        Date now = new Date();
        Date past = new Date(now.getTime() - 86_400_000L);
        Date future = new Date(now.getTime() + 86_400_000L * 30);

        X509Certificate rootCert = buildSignedX509(
                BigInteger.valueOf(11L), "Google Root", "Google Root",
                past, future, rootKp.getPublic(), rootKp.getPrivate(), true, null);
        GoogleAttestationRootStore testStore = GoogleAttestationRootStore.withAdditions(
                Collections.singletonList(GoogleAttestationRootStore.sha256SpkiHex(rootCert)), null);

        // 1. Direct StrongBox success + deleteAlias throwing exception (must not leak)
        AtomicInteger teeCalls = new AtomicInteger();
        AttestationCapability sbDirect = new AttestationCapability(
                new AttestationCapability.KeyAttestationBackend() {
                    @Override
                    public List<X509Certificate> generateAttestationChain(
                            String alias, byte[] challenge, boolean strongBox) throws Exception {
                        if (!strongBox) {
                            teeCalls.incrementAndGet();
                            return Collections.emptyList();
                        }
                        byte[] ext = buildSimpleLockedAttestationExtension(challenge);
                        X509Certificate leaf = buildSignedX509(
                                BigInteger.valueOf(23L), "Google Root", "Key",
                                past, future, leafKp.getPublic(), rootKp.getPrivate(), false, ext);
                        return Arrays.asList(leaf, rootCert);
                    }

                    @Override
                    public void deleteAlias(String alias) {
                        throw new RuntimeException("delete_boom");
                    }
                },
                new AttestationExtensionParser(),
                new CertificateTrustAnalyzer(testStore),
                new RkpExtensionParser(),
                new SecureRandom());

        AttestationCapability.AttestationSnapshot sbSnap = sbDirect.collect(now);
        assertTrue(sbSnap.isAvailable());
        assertTrue(sbSnap.isUsedStrongBox());
        assertFalse(sbSnap.isFallbackFromStrongBox());
        assertEquals(0, teeCalls.get());
        assertTrue(sbSnap.isHardwareVerifiedLocked());

        // 2. StrongBox returns empty list -> graceful TEE fallback
        AttestationCapability sbEmpty = new AttestationCapability(
                new AttestationCapability.KeyAttestationBackend() {
                    @Override
                    public List<X509Certificate> generateAttestationChain(
                            String alias, byte[] challenge, boolean strongBox) throws Exception {
                        if (strongBox) {
                            return Collections.emptyList();
                        }
                        byte[] ext = buildSimpleLockedAttestationExtension(challenge);
                        X509Certificate leaf = buildSignedX509(
                                BigInteger.valueOf(24L), "Google Root", "Key",
                                past, future, leafKp.getPublic(), rootKp.getPrivate(), false, ext);
                        return Arrays.asList(leaf, rootCert);
                    }

                    @Override
                    public void deleteAlias(String alias) {
                    }
                },
                new AttestationExtensionParser(),
                new CertificateTrustAnalyzer(testStore),
                new RkpExtensionParser(),
                new SecureRandom());
        AttestationCapability.AttestationSnapshot fbSnap = sbEmpty.collect(now);
        assertTrue(fbSnap.isAvailable());
        assertFalse(fbSnap.isUsedStrongBox());
        assertTrue(fbSnap.isFallbackFromStrongBox());

        // 3. Negative guards on isHardwareVerifiedLocked()
        CertificateTrustAnalyzer.TrustResult trusted = sbSnap.getTrust();
        AttestationRecord.RootOfTrust lockedRot = new AttestationRecord.RootOfTrust(
                new byte[32], true, AttestationRecord.VerifiedBootState.VERIFIED, new byte[32], true);

        // Software keymaster security level -> false
        AttestationRecord swKm = AttestationRecord.builder()
                .valid(true).challengeMatched(true)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.SOFTWARE)
                .rootOfTrust(lockedRot)
                .build();
        assertFalse(AttestationCapability.AttestationSnapshot.builder()
                .available(true).record(swKm).trust(trusted).build().isHardwareVerifiedLocked());

        // Leaf shadow attempted -> false
        AttestationRecord shadowed = AttestationRecord.builder()
                .valid(true).challengeMatched(true)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .leafShadowAttempted(true)
                .rootOfTrust(lockedRot)
                .build();
        assertFalse(AttestationCapability.AttestationSnapshot.builder()
                .available(true).record(shadowed).trust(trusted).build().isHardwareVerifiedLocked());

        // Present but invalid RKP -> false
        AttestationRecord cleanRec = AttestationRecord.builder()
                .valid(true).challengeMatched(true)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .rootOfTrust(lockedRot)
                .build();
        RkpExtensionParser.RkpParseResult invalidRkp = new RkpExtensionParser()
                .parseExtensionValue(new byte[] {0x04, 0x01, 0x00}, "Google");
        assertTrue(invalidRkp.isPresent());
        assertFalse(invalidRkp.isValid());
        assertFalse(AttestationCapability.AttestationSnapshot.builder()
                .available(true).record(cleanRec).trust(trusted).rkp(invalidRkp).build()
                .isHardwareVerifiedLocked());
    }

    // -------------------------------------------------------------------------
    // Pure-JDK minimal X.509 v3 DER certificate builder (zero 3rd-party deps)
    // -------------------------------------------------------------------------

    private static KeyPair genEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate buildSignedX509(
            BigInteger serial,
            String issuerCn,
            String subjectCn,
            Date notBefore,
            Date notAfter,
            PublicKey subjectPubKey,
            PrivateKey issuerPrivKey,
            boolean isCa,
            byte[] attestationExtOctetValue) throws Exception {
        return buildSignedX509Full(
                serial, issuerCn, subjectCn, notBefore, notAfter,
                subjectPubKey, issuerPrivKey, isCa, null, isCa, attestationExtOctetValue);
    }

    private static X509Certificate buildSignedX509Full(
            BigInteger serial,
            String issuerCn,
            String subjectCn,
            Date notBefore,
            Date notAfter,
            PublicKey subjectPubKey,
            PrivateKey issuerPrivKey,
            boolean isCa,
            Integer pathLenConstraint,
            boolean keyCertSignUsage,
            byte[] attestationExtOctetValue) throws Exception {
        // OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
        byte[] sigAlgId = derSequence(derOid(new int[] {1, 2, 840, 10045, 4, 3, 2}));
        byte[] version = derContextConstructed(0, derInteger(2)); // v3
        byte[] serialDer = derInteger(serial);
        byte[] issuerDer = derNameCn(issuerCn);
        byte[] validityDer = derSequence(derGeneralizedTime(notBefore), derGeneralizedTime(notAfter));
        byte[] subjectDer = derNameCn(subjectCn);
        byte[] spkiDer = subjectPubKey.getEncoded();

        List<byte[]> exts = new ArrayList<>();
        if (isCa) {
            // BasicConstraints OID 2.5.29.19, critical=true, SEQUENCE { BOOLEAN TRUE [, INTEGER pathLen] }
            byte[] bcVal = pathLenConstraint == null
                    ? derSequence(derBoolean(true))
                    : derSequence(derBoolean(true), derInteger(pathLenConstraint.longValue()));
            exts.add(derSequence(
                    derOid(new int[] {2, 5, 29, 19}),
                    derBoolean(true),
                    derOctetString(bcVal)));
        }
        // KeyUsage OID 2.5.29.15 (bit 0=digitalSignature 0x80, bit 5=keyCertSign 0x04)
        byte kuByte = keyCertSignUsage ? (byte) 0x84 : (byte) 0x80;
        exts.add(derSequence(
                derOid(new int[] {2, 5, 29, 15}),
                derBoolean(true),
                derOctetString(derBitString(new byte[] {kuByte}))));
        if (attestationExtOctetValue != null) {
            exts.add(derSequence(
                    derOid(new int[] {1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}),
                    attestationExtOctetValue));
        }

        ByteArrayOutputStream tbsInner = new ByteArrayOutputStream();
        write(tbsInner, version);
        write(tbsInner, serialDer);
        write(tbsInner, sigAlgId);
        write(tbsInner, issuerDer);
        write(tbsInner, validityDer);
        write(tbsInner, subjectDer);
        write(tbsInner, spkiDer);
        if (!exts.isEmpty()) {
            byte[] extSeq = derSequence(exts.toArray(new byte[0][]));
            write(tbsInner, derContextConstructed(3, extSeq));
        }
        byte[] tbsDer = derTlv(0x30, tbsInner.toByteArray());

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(issuerPrivKey);
        sig.update(tbsDer);
        byte[] sigBytes = sig.sign();

        byte[] certDer = derSequence(tbsDer, sigAlgId, derBitString(sigBytes));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static byte[] buildSimpleLockedAttestationExtension(byte[] challenge) {
        byte[] rot = derSequence(
                derOctetString(new byte[32]),
                derBoolean(true),
                derEnumerated(0),
                derOctetString(new byte[] {1, 2, 3, 4}));
        byte[] hwList = derSequence(derExplicitHighContextTag(704, rot));
        byte[] keyDesc = derSequence(
                derInteger(BigInteger.valueOf(300)),
                derEnumerated(1),
                derInteger(BigInteger.valueOf(300)),
                derEnumerated(1),
                derOctetString(challenge),
                derOctetString(new byte[0]),
                derSequence(),
                hwList);
        return derOctetString(keyDesc);
    }

    private static byte[] derNameCn(String cn) {
        // SEQUENCE { SET { SEQUENCE { OID 2.5.4.3 (CN), UTF8String cn } } }
        byte[] atv = derSequence(
                derOid(new int[] {2, 5, 4, 3}),
                derTlv(0x0C, cn.getBytes(StandardCharsets.UTF_8)));
        return derSequence(derTlv(0x31, atv));
    }

    private static byte[] derGeneralizedTime(Date date) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        return derTlv(0x18, fmt.format(date).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] derOid(int[] arcs) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            int val = arcs[i];
            byte[] buf = new byte[5];
            int idx = 0;
            buf[idx++] = (byte) (val & 0x7F);
            val >>>= 7;
            while (val > 0) {
                buf[idx++] = (byte) ((val & 0x7F) | 0x80);
                val >>>= 7;
            }
            for (int j = idx - 1; j >= 0; j--) {
                out.write(buf[j]);
            }
        }
        return derTlv(0x06, out.toByteArray());
    }

    private static byte[] derBitString(byte[] content) {
        byte[] wrapped = new byte[content.length + 1];
        wrapped[0] = 0x00;
        System.arraycopy(content, 0, wrapped, 1, content.length);
        return derTlv(0x03, wrapped);
    }

    private static byte[] derContextConstructed(int tagNo, byte[] inner) {
        return derTlv(0xA0 | tagNo, inner);
    }

    private static byte[] derExplicitHighContextTag(int tagNumber, byte[] inner) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xBF);
        byte[] buf = new byte[5];
        int idx = 0;
        int n = tagNumber;
        buf[idx++] = (byte) (n & 0x7F);
        n >>>= 7;
        while (n > 0) {
            buf[idx++] = (byte) ((n & 0x7F) | 0x80);
            n >>>= 7;
        }
        for (int i = idx - 1; i >= 0; i--) {
            out.write(buf[i]);
        }
        writeDerLength(out, inner.length);
        write(out, inner);
        return out.toByteArray();
    }

    private static byte[] derSequence(byte[]... items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] item : items) {
            write(out, item);
        }
        return derTlv(0x30, out.toByteArray());
    }

    private static byte[] derOctetString(byte[] content) {
        return derTlv(0x04, content);
    }

    private static byte[] derBoolean(boolean val) {
        return derTlv(0x01, new byte[] {val ? (byte) 0xFF : 0x00});
    }

    private static byte[] derInteger(long v) {
        return derInteger(BigInteger.valueOf(v));
    }

    private static byte[] derInteger(BigInteger v) {
        return derTlv(0x02, v.toByteArray());
    }

    private static byte[] derEnumerated(int v) {
        return derTlv(0x0A, BigInteger.valueOf(v).toByteArray());
    }

    private static byte[] derTlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeDerLength(out, content.length);
        write(out, content);
        return out.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len <= 0xFF) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
    }

    private static void write(ByteArrayOutputStream out, byte[] data) {
        out.write(data, 0, data.length);
    }
}
