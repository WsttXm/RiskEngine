package com.wsttxm.riskenginesdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.attestation.CertificateTrustAnalyzer;
import com.wsttxm.riskenginesdk.attestation.GoogleAttestationRootStore;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.DetectorRegistry;
import com.wsttxm.riskenginesdk.detector.TeeIntegrityDetector;
import com.wsttxm.riskenginesdk.detector.probe.tee.GrantDomainSplitProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.Keystore2DeepProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.TeeNativeProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.VintfHalAndErrorPathProbe;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.ReportStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;

import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Unit tests for {@link TeeIntegrityDetector} (15th converged domain, {@link ScanTier#POSTPONED}),
 * hard triggers ({@code tee_grant_chain_split}, {@code tee_binder_ioctl_hook},
 * {@code tee_keybox_revoked}), and {@link RiskReport.TrustTier#STRONG_HARDWARE} vs
 * {@link RiskReport.TrustTier#LOCAL_VERIFIED} clean degradation.
 */
public class TeeIntegrityDetectorTest {

    @Test
    public void detectorRegistry_registersTeeIntegrityAs15thPostponedDomainAndRespectsConfigToggle() {
        RiskEngineConfig enabled = new RiskEngineConfig.Builder().build();
        List<BaseDetector> all = new DetectorRegistry(null, enabled).getDetectors();
        assertEquals(16, all.size());

        BaseDetector tee = null;
        for (BaseDetector d : all) {
            if ("tee_integrity".equals(d.getName())) {
                tee = d;
            }
        }
        assertNotNull(tee);
        assertEquals(ScanTier.POSTPONED, tee.getScanTier());
        assertFalse(tee.hasPostponedProbes());

        RiskEngineConfig disabled = new RiskEngineConfig.Builder()
                .enableTeeAttestation(false)
                .build();
        List<BaseDetector> withoutTee = new DetectorRegistry(null, disabled).getDetectors();
        assertEquals(15, withoutTee.size());
        for (BaseDetector d : withoutTee) {
            assertFalse("tee_integrity".equals(d.getName()));
        }
    }

    @Test
    public void cleanGoogleHardwareVerifiedLocked_elevatesTrustTierToStrongHardware()
            throws Exception {
        AttestationCapability.AttestationSnapshot trustedSnap = buildTrustedLockedSnapshot(true);
        TeeIntegrityDetector detector = TeeIntegrityDetector.createForTest(
                null,
                new RiskEngineConfig.Builder().build(),
                null,
                new StubTeeEnv(trustedSnap, null, null, null, null));

        DetectionResult det = detector.call();
        assertEquals(ScanTier.POSTPONED, det.getScanTier());
        assertEquals(RiskLevel.SAFE, det.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, det.getStatus());
        assertEquals(DetectionExecutionStatus.SAFE, det.getExecutionStatus());
        assertEquals(0, det.getScore());
        assertTrue(det.getEvidence().startsWith("hardware_attested_locked_verified:STRONGBOX"));

        DataAggregator aggregator = new DataAggregator();
        RiskReport report = aggregator.aggregate(
                Collections.<CollectorResult>emptyList(),
                Collections.singletonList(det),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, report.getOverallRiskLevel());
        assertEquals(ReportStatus.COMPLETE, report.getReportStatus());
        assertEquals(RiskReport.TrustTier.STRONG_HARDWARE, report.getTrustTier());
        assertEquals(
                DevicePosture.KeystoreSecurityLevel.STRONGBOX,
                report.getDevicePosture().getKeystoreSecurityLevel());
    }

    @Test
    public void unavailableHardwareAndHostileProbeExceptions_staySafeCompleteAndLocalVerified() {
        // 1. All 5 TEE sub-probes unavailable -> SAFE + COMPLETE + LOCAL_VERIFIED (never UNKNOWN!)
        TeeIntegrityDetector unavailDetector = TeeIntegrityDetector.createForTest(
                null,
                new RiskEngineConfig.Builder().build(),
                null,
                new StubTeeEnv(
                        AttestationCapability.AttestationSnapshot.unavailable("no_tee_hal"),
                        TeeNativeProbe.run((TeeNativeProbe.NativeTeeAdapter) null, null, true),
                        GrantDomainSplitProbe.evaluate(SignalResult.unavailable("api_30")),
                        Keystore2DeepProbe.run((Keystore2DeepProbe.Keystore2DeepAdapter) null),
                        VintfHalAndErrorPathProbe.run(
                                null, null, k -> null, null)));

        DetectionResult unavailDet = unavailDetector.call();
        assertEquals(RiskLevel.SAFE, unavailDet.getRiskLevel());
        assertEquals(DetectionExecutionStatus.SAFE, unavailDet.getExecutionStatus());
        RiskReport unavailReport = new DataAggregator().aggregate(
                Collections.<CollectorResult>emptyList(),
                Collections.singletonList(unavailDet),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.SAFE, unavailReport.getOverallRiskLevel());
        assertEquals(ReportStatus.COMPLETE, unavailReport.getReportStatus());
        assertEquals(RiskReport.TrustTier.LOCAL_VERIFIED, unavailReport.getTrustTier());

        // 2. Hostile runtime exceptions / LinkageError / OOM inside TeeEnvironment -> 0 crashes, SAFE
        TeeIntegrityDetector hostileDetector = TeeIntegrityDetector.createForTest(
                null,
                new RiskEngineConfig.Builder().build(),
                null,
                new TeeIntegrityDetector.TeeEnvironment() {
                    @Override
                    public AttestationCapability.AttestationSnapshot collectAttestation() {
                        throw new SecurityException("keystore_denied");
                    }

                    @Override
                    public TeeNativeProbe.ProbeResult runNativeProbe(byte[] leafCertDer) {
                        throw new UnsatisfiedLinkError("jni_missing");
                    }

                    @Override
                    public GrantDomainSplitProbe.ProbeResult runGrantDomainSplitProbe(
                            boolean isolatedProbeEnabled) {
                        throw new RuntimeException("bind_failed");
                    }

                    @Override
                    public Keystore2DeepProbe.ProbeResult runKeystore2DeepProbe(
                            AttestationCapability.AttestationSnapshot snapshot) {
                        throw new OutOfMemoryError("simulated_oom");
                    }

                    @Override
                    public VintfHalAndErrorPathProbe.ProbeResult runVintfAndErrorPathProbe(
                            AttestationCapability.AttestationSnapshot snapshot) {
                        throw new NoClassDefFoundError("hidden_api");
                    }
                });
        DetectionResult hostileRes = hostileDetector.call();
        assertEquals(RiskLevel.SAFE, hostileRes.getRiskLevel());
        assertEquals(DetectionExecutionStatus.SAFE, hostileRes.getExecutionStatus());
    }

    @Test
    public void hardTriggersEscalateReportToDeadlyAndMediumProbesScoreActionable4()
            throws Exception {
        // 1. Revoked keybox -> HIGH/9 on tee_integrity + DEADLY overall via hasHardTrigger()
        AttestationCapability.AttestationSnapshot revokedSnap = buildRevokedSnapshot();
        DetectionResult revokedDet = TeeIntegrityDetector.createForTest(
                null,
                new RiskEngineConfig.Builder().build(),
                null,
                new StubTeeEnv(revokedSnap, null, null, null, null)).call();
        assertEquals(RiskLevel.HIGH, revokedDet.getRiskLevel());
        assertEquals(9, revokedDet.getScore());
        assertFalse(revokedDet.isInformational());
        RiskReport revokedReport = new DataAggregator().aggregate(
                Collections.<CollectorResult>emptyList(),
                Collections.singletonList(revokedDet),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.DEADLY, revokedReport.getOverallRiskLevel());
        assertEquals(RiskReport.TrustTier.COMPROMISED, revokedReport.getTrustTier());

        // 2. Grant-Domain chain split -> HIGH/9 + DEADLY hard trigger
        GrantDomainSplitProbe.ProbeResult splitProbe = GrantDomainSplitProbe.evaluateReport(
                new IsolatedProbeClient.IsolatedGrantReport(
                        "OK|1|aaaa|aaaa",
                        "OK|1|bbbb|bbbb",
                        IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.OK,
                        99001,
                        15L,
                        "mismatch"));
        DetectionResult splitDet = TeeIntegrityDetector.createForTest(
                null,
                new RiskEngineConfig.Builder().build(),
                null,
                new StubTeeEnv(null, null, splitProbe, null, null)).call();
        assertEquals(RiskLevel.HIGH, splitDet.getRiskLevel());
        assertEquals(9, splitDet.getScore());
        RiskReport splitReport = new DataAggregator().aggregate(
                Collections.<CollectorResult>emptyList(),
                Collections.singletonList(splitDet),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.DEADLY, splitReport.getOverallRiskLevel());

        // 3. Native libbinder ioctl hook -> HIGH/9 + DEADLY hard trigger
        TeeNativeProbe.ProbeResult ioctlHook = TeeNativeProbe.run(
                new TeeNativeProbe.NativeTeeAdapter() {
                    @Override
                    public SignalResult<String> getTeeBinderProbe(boolean includeHoneypotTiming) {
                        return SignalResult.success(
                                "status=OK\terrno=0\nkind=got_ioctl_hook\thook_lib=libtricky.so\tgot=0x1\treal=0x2");
                    }

                    @Override
                    public SignalResult<String> inspectLeafDer(byte[] leafDer) {
                        return SignalResult.unavailable("unused");
                    }
                },
                null,
                true);
        DetectionResult ioctlDet = TeeIntegrityDetector.createForTest(
                null,
                new RiskEngineConfig.Builder().build(),
                null,
                new StubTeeEnv(null, ioctlHook, null, null, null)).call();
        RiskReport ioctlReport = new DataAggregator().aggregate(
                Collections.<CollectorResult>emptyList(),
                Collections.singletonList(ioctlDet),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.DEADLY, ioctlReport.getOverallRiskLevel());

        // 4. Soft StrongBox / Post-Processing latency -> MEDIUM/4 actionable in all scenes
        Keystore2DeepProbe.ProbeResult softSb = Keystore2DeepProbe.run(
                new Keystore2DeepProbe.Keystore2DeepAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 34;
                    }

                    @Override
                    public byte[] captureGenerateKeyReplyParcel(String alias) {
                        return null;
                    }

                    @Override
                    public Keystore2DeepProbe.PostProcessingSessionData collectPostProcessingSamples(
                            String aliasPrefix, int pairCount) {
                        return null;
                    }

                    @Override
                    public Keystore2DeepProbe.OverwriteSessionData collectOverwriteAndLifecycle(
                            String supportAlias, String attackAlias, String lifecycleAlias) {
                        return null;
                    }

                    @Override
                    public Keystore2DeepProbe.StrongBoxObservation collectStrongBoxObservation(
                            String aliasPrefix) {
                        return new Keystore2DeepProbe.StrongBoxObservation(
                                true,
                                Boolean.TRUE,
                                AttestationRecord.SecurityLevel.STRONGBOX,
                                4,
                                500,
                                Keystore2DeepProbe.StrongBoxAcceptance.ACCEPTED,
                                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_FRAMEWORK,
                                null);
                    }

                    @Override
                    public void deleteAlias(String alias) {
                    }
                });
        DetectionResult medDet = TeeIntegrityDetector.createForTest(
                null,
                new RiskEngineConfig.Builder().build(),
                null,
                new StubTeeEnv(null, null, null, softSb, null)).call();
        assertEquals(RiskLevel.MEDIUM, medDet.getRiskLevel());
        assertEquals(4, medDet.getScore());
        assertFalse(medDet.isInformational());
        for (EvidenceItem item : medDet.getEvidenceItems()) {
            assertEquals("tee_tamper", item.getEvidenceFamily());
        }
        RiskReport medReport = new DataAggregator().aggregate(
                Collections.<CollectorResult>emptyList(),
                Collections.singletonList(medDet),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.MEDIUM, medReport.getOverallRiskLevel());
        assertEquals(RiskReport.TrustTier.DEGRADED, medReport.getTrustTier());
    }

    private static AttestationCapability.AttestationSnapshot buildTrustedLockedSnapshot(
            boolean strongBox) throws Exception {
        KeyPair rootKp = genEc();
        KeyPair leafKp = genEc();
        Date now = new Date();
        Date past = new Date(now.getTime() - 86_400_000L);
        Date future = new Date(now.getTime() + 86_400_000L * 30);

        X509Certificate rootCert = AttestationTrustAndCapabilityTestHelper.selfSignedCa(
                BigInteger.valueOf(101L), "Google Hardware Root", past, future, rootKp);
        X509Certificate leafCert = AttestationTrustAndCapabilityTestHelper.issuedLeaf(
                BigInteger.valueOf(202L), "Google Hardware Root", "Key", past, future,
                leafKp.getPublic(), rootKp.getPrivate());

        String rootSpki = GoogleAttestationRootStore.sha256SpkiHex(rootCert);
        CertificateTrustAnalyzer analyzer = new CertificateTrustAnalyzer(
                GoogleAttestationRootStore.withAdditions(
                        Collections.singletonList(rootSpki), null));
        CertificateTrustAnalyzer.TrustResult trust =
                analyzer.inspect(Arrays.asList(leafCert, rootCert), now);

        AttestationRecord.SecurityLevel tier = strongBox
                ? AttestationRecord.SecurityLevel.STRONGBOX
                : AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT;
        AttestationRecord record = AttestationRecord.builder()
                .valid(true)
                .challengeMatched(true)
                .attestationVersion(300)
                .keymasterVersion(300)
                .attestationSecurityLevel(tier)
                .keymasterSecurityLevel(tier)
                .rootOfTrust(new AttestationRecord.RootOfTrust(
                        new byte[]{1, 2, 3},
                        true,
                        AttestationRecord.VerifiedBootState.VERIFIED,
                        new byte[]{4, 5, 6},
                        true))
                .build();

        return AttestationCapability.AttestationSnapshot.builder()
                .available(true)
                .usedStrongBox(strongBox)
                .record(record)
                .trust(trust)
                .certificateChain(Arrays.asList(leafCert, rootCert))
                .build();
    }

    private static AttestationCapability.AttestationSnapshot buildRevokedSnapshot()
            throws Exception {
        KeyPair rootKp = genEc();
        KeyPair leafKp = genEc();
        Date now = new Date();
        Date past = new Date(now.getTime() - 86_400_000L);
        Date future = new Date(now.getTime() + 86_400_000L * 30);

        BigInteger revokedSerial = new BigInteger("6681152659205225093", 10);
        X509Certificate rootCert = AttestationTrustAndCapabilityTestHelper.selfSignedCa(
                BigInteger.valueOf(101L), "Google Hardware Root", past, future, rootKp);
        X509Certificate leafCert = AttestationTrustAndCapabilityTestHelper.issuedLeaf(
                revokedSerial, "Google Hardware Root", "Revoked Leaf", past, future,
                leafKp.getPublic(), rootKp.getPrivate());

        String rootSpki = GoogleAttestationRootStore.sha256SpkiHex(rootCert);
        CertificateTrustAnalyzer analyzer = new CertificateTrustAnalyzer(
                GoogleAttestationRootStore.withAdditions(
                        Collections.singletonList(rootSpki), null));
        CertificateTrustAnalyzer.TrustResult trust =
                analyzer.inspect(Arrays.asList(leafCert, rootCert), now);
        assertTrue(trust.isAnyCertRevoked());

        AttestationRecord record = AttestationRecord.builder()
                .valid(true)
                .challengeMatched(true)
                .attestationVersion(200)
                .keymasterVersion(200)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .build();

        return AttestationCapability.AttestationSnapshot.builder()
                .available(true)
                .record(record)
                .trust(trust)
                .certificateChain(Arrays.asList(leafCert, rootCert))
                .build();
    }

    private static KeyPair genEc() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static final class StubTeeEnv implements TeeIntegrityDetector.TeeEnvironment {
        private final AttestationCapability.AttestationSnapshot snap;
        private final TeeNativeProbe.ProbeResult nativeRes;
        private final GrantDomainSplitProbe.ProbeResult grantRes;
        private final Keystore2DeepProbe.ProbeResult deepRes;
        private final VintfHalAndErrorPathProbe.ProbeResult vintfRes;

        StubTeeEnv(
                AttestationCapability.AttestationSnapshot snap,
                TeeNativeProbe.ProbeResult nativeRes,
                GrantDomainSplitProbe.ProbeResult grantRes,
                Keystore2DeepProbe.ProbeResult deepRes,
                VintfHalAndErrorPathProbe.ProbeResult vintfRes) {
            this.snap = snap;
            this.nativeRes = nativeRes;
            this.grantRes = grantRes;
            this.deepRes = deepRes;
            this.vintfRes = vintfRes;
        }

        @Override
        public AttestationCapability.AttestationSnapshot collectAttestation() {
            return snap;
        }

        @Override
        public TeeNativeProbe.ProbeResult runNativeProbe(byte[] leafCertDer) {
            return nativeRes;
        }

        @Override
        public GrantDomainSplitProbe.ProbeResult runGrantDomainSplitProbe(
                boolean isolatedProbeEnabled) {
            return grantRes;
        }

        @Override
        public Keystore2DeepProbe.ProbeResult runKeystore2DeepProbe(
                AttestationCapability.AttestationSnapshot snapshot) {
            return deepRes;
        }

        @Override
        public VintfHalAndErrorPathProbe.ProbeResult runVintfAndErrorPathProbe(
                AttestationCapability.AttestationSnapshot snapshot) {
            return vintfRes;
        }
    }

    /** Minimal DER X.509 certificate builder for pure-JVM trust tests. */
    private static final class AttestationTrustAndCapabilityTestHelper {
        static X509Certificate selfSignedCa(
                BigInteger serial,
                String cn,
                Date notBefore,
                Date notAfter,
                KeyPair kp) throws Exception {
            return buildX509(serial, cn, cn, notBefore, notAfter, kp.getPublic(), kp.getPrivate(), true);
        }

        static X509Certificate issuedLeaf(
                BigInteger serial,
                String issuerCn,
                String subjectCn,
                Date notBefore,
                Date notAfter,
                java.security.PublicKey pub,
                java.security.PrivateKey issuerPriv) throws Exception {
            return buildX509(serial, issuerCn, subjectCn, notBefore, notAfter, pub, issuerPriv, false);
        }

        private static X509Certificate buildX509(
                BigInteger serial,
                String issuerCn,
                String subjectCn,
                Date notBefore,
                Date notAfter,
                java.security.PublicKey pub,
                java.security.PrivateKey signerPriv,
                boolean isCa) throws Exception {
            byte[] version = derExplicit(0, derInteger(BigInteger.valueOf(2))); // v3
            byte[] serialDer = derInteger(serial);
            byte[] sigAlg = derSequence(derOid(new int[]{1, 2, 840, 10045, 4, 3, 2})); // ecdsa-with-SHA256
            byte[] issuer = derName(issuerCn);
            byte[] validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter));
            byte[] subject = derName(subjectCn);
            byte[] spki = pub.getEncoded();

            byte[] extensions = new byte[0];
            if (isCa) {
                byte[] bcVal = derOctetString(derSequence(new byte[]{0x01, 0x01, (byte) 0xFF}));
                byte[] bcExt = derSequence(
                        derOid(new int[]{2, 5, 29, 19}),
                        new byte[]{0x01, 0x01, (byte) 0xFF},
                        bcVal);
                byte[] kuVal = derOctetString(new byte[]{0x03, 0x02, 0x01, 0x06}); // keyCertSign + cRLSign
                byte[] kuExt = derSequence(
                        derOid(new int[]{2, 5, 29, 15}),
                        new byte[]{0x01, 0x01, (byte) 0xFF},
                        kuVal);
                extensions = derExplicit(3, derSequence(bcExt, kuExt));
            }

            byte[] tbs = derSequence(
                    version, serialDer, sigAlg, issuer, validity, subject, spki, extensions);
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
            sig.initSign(signerPriv);
            sig.update(tbs);
            byte[] sigBytes = sig.sign();
            byte[] bitString = new byte[sigBytes.length + 1];
            bitString[0] = 0x00;
            System.arraycopy(sigBytes, 0, bitString, 1, sigBytes.length);
            byte[] certDer = derSequence(tbs, sigAlg, derTlv(0x03, bitString));

            java.security.cert.CertificateFactory cf =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certDer));
        }

        private static byte[] derName(String cn) {
            byte[] utf8 = derTlv(0x0C, cn.getBytes(StandardCharsets.UTF_8));
            byte[] atv = derSequence(derOid(new int[]{2, 5, 4, 3}), utf8);
            return derSequence(derTlv(0x31, atv));
        }

        private static byte[] derUtcTime(Date d) {
            java.text.SimpleDateFormat fmt =
                    new java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.ROOT);
            fmt.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
            return derTlv(0x17, fmt.format(d).getBytes(StandardCharsets.US_ASCII));
        }

        private static byte[] derInteger(BigInteger val) {
            return derTlv(0x02, val.toByteArray());
        }

        private static byte[] derOctetString(byte[] content) {
            return derTlv(0x04, content);
        }

        private static byte[] derExplicit(int tagNo, byte[] inner) {
            return derTlv(0xA0 | tagNo, inner);
        }

        private static byte[] derSequence(byte[]... parts) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            for (byte[] p : parts) {
                if (p != null && p.length > 0) {
                    out.write(p, 0, p.length);
                }
            }
            return derTlv(0x30, out.toByteArray());
        }

        private static byte[] derOid(int[] arcs) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
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

        private static byte[] derTlv(int tag, byte[] value) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.write(tag);
            int len = value.length;
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
            out.write(value, 0, len);
            return out.toByteArray();
        }
    }
}
