package com.wsttxm.riskenginesdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.detector.probe.tee.Keystore2DeepProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.ProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Unit tests for {@link Keystore2DeepProbe}:
 * (1) {@code generateKey} reply parcel {@code TAG_USER_ID (0x300001F5, SOFTWARE)} verification,
 * (2) API 35+ {@code RkpdProvisioned} vs {@code PURPOSE_ATTEST_KEY} parity &amp; timing,
 * (3) Overwrite-readback anti-cache persistence trap &amp; key-lifecycle freshness,
 * (4) StrongBox RSA-4096/{@code secp521r1} attribution &amp; {@code <2ms}/{@code <20ms} tripwires,
 * (5) Unconditional {@code finally} alias cleanup and zero-FP unavailability handling.
 */
public class Keystore2DeepProbeTest {

    @Test
    public void replyParcelParser_stockKeystore2TrailingUserIdSoftware_isClean() {
        byte[] parcel = buildReplyParcel(
                0,
                Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                Arrays.asList(
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, 0x10000002, 2, 3L, null),
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_KEYSTORE,
                                Keystore2DeepProbe.TAG_CREATION_DATETIME, 13, 1700000000000L, null),
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_SOFTWARE,
                                Keystore2DeepProbe.TAG_USER_ID, 8, 0L, null)),
                new byte[]{0x30, (byte) 0x82, 0x01, 0x05, 0x11},
                new byte[]{0x30, (byte) 0x82, 0x02, 0x00},
                1700000001234L);

        Keystore2DeepProbe.ReplyParcelParseResult res =
                Keystore2DeepProbe.parseGenerateKeyReplyParcel(parcel);
        assertTrue(res.isParseSucceeded());
        assertEquals(Keystore2DeepProbe.ReplyParcelAnomaly.NONE, res.getAnomaly());
        assertEquals(3, res.getAuthorizations().size());
        assertEquals(Integer.valueOf(5), res.getCertificateLength());
        assertEquals(Integer.valueOf(4), res.getCertificateChainLength());
        assertEquals(Long.valueOf(1700000001234L), res.getModificationTimeMs());
    }

    @Test
    public void replyParcelParser_missingOrWrongLevelUserId_flagsSpoof() {
        // Case A: Synthetic reply ends with TAG_ALGORITHM instead of TAG_USER_ID@SOFTWARE
        byte[] missingUserId = buildReplyParcel(
                0,
                Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                Arrays.asList(
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, 0x10000002, 2, 3L, null),
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_KEYSTORE,
                                Keystore2DeepProbe.TAG_CREATION_DATETIME, 13, 1700000000000L, null)),
                null,
                null,
                100L);
        Keystore2DeepProbe.ReplyParcelParseResult resA =
                Keystore2DeepProbe.parseGenerateKeyReplyParcel(missingUserId);
        assertTrue(resA.isParseSucceeded());
        assertEquals(
                Keystore2DeepProbe.ReplyParcelAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE,
                resA.getAnomaly());

        // Case B: TAG_USER_ID present as last item, but stamped at TRUSTED_ENVIRONMENT (1) instead of SOFTWARE (0)
        byte[] wrongLevel = buildReplyParcel(
                0,
                Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                Collections.singletonList(
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                                Keystore2DeepProbe.TAG_USER_ID, 8, 0L, null)),
                null,
                null,
                100L);
        Keystore2DeepProbe.ReplyParcelParseResult resB =
                Keystore2DeepProbe.parseGenerateKeyReplyParcel(wrongLevel);
        assertTrue(resB.isParseSucceeded());
        assertEquals(
                Keystore2DeepProbe.ReplyParcelAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE,
                resB.getAnomaly());
    }

    @Test
    public void replyParcelParser_creationDatetimeOutsideKeystoreAndMalformedBounds() {
        byte[] creationOutside = buildReplyParcel(
                0,
                Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                Arrays.asList(
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_SOFTWARE,
                                Keystore2DeepProbe.TAG_CREATION_DATETIME, 13, 1700000000000L, null),
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_SOFTWARE,
                                Keystore2DeepProbe.TAG_USER_ID, 8, 0L, null)),
                new byte[]{1, 2, 3},
                null,
                999L);
        Keystore2DeepProbe.ReplyParcelParseResult parsed =
                Keystore2DeepProbe.parseGenerateKeyReplyParcel(creationOutside);
        assertTrue(parsed.isParseSucceeded());
        assertEquals(
                Keystore2DeepProbe.ReplyParcelAnomaly.CREATION_DATETIME_OUTSIDE_KEYSTORE,
                parsed.getAnomaly());

        // Non-zero exception code & truncated parcel fail closed with parseSucceeded=false (0 FP)
        ParcelBytes errParcel = new ParcelBytes();
        errParcel.writeInt(-8);
        assertFalse(Keystore2DeepProbe.parseGenerateKeyReplyParcel(errParcel.toByteArray())
                .isParseSucceeded());
        assertFalse(Keystore2DeepProbe.parseGenerateKeyReplyParcel(new byte[]{0, 0})
                .isParseSucceeded());
    }

    @Test
    public void postProcessing_detectsRootOfTrustDivergenceAndHighDeltaWhileIgnoringRkpdOffline() {
        AttestationRecord.RootOfTrust lockedVerified = new AttestationRecord.RootOfTrust(
                new byte[]{1, 2}, true, AttestationRecord.VerifiedBootState.VERIFIED, new byte[]{3}, true);
        AttestationRecord.RootOfTrust unlockedOrange = new AttestationRecord.RootOfTrust(
                new byte[]{1, 2}, false, AttestationRecord.VerifiedBootState.UNVERIFIED, new byte[]{3}, true);

        // 1. Deterministic RootOfTrust divergence between RkpdProvisioned (rewritten to locked/VERIFIED)
        //    and PURPOSE_ATTEST_KEY (true hardware unlocked/UNVERIFIED)
        List<Keystore2DeepProbe.PostProcessingPathSample> rkpSpoofed = new ArrayList<>();
        List<Keystore2DeepProbe.PostProcessingPathSample> akReal = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            rkpSpoofed.add(Keystore2DeepProbe.PostProcessingPathSample.success(85.0, lockedVerified, true));
            akReal.add(Keystore2DeepProbe.PostProcessingPathSample.success(80.0, unlockedOrange, false));
        }
        Keystore2DeepProbe.PostProcessingResult rotRes = Keystore2DeepProbe.evaluatePostProcessing(
                new Keystore2DeepProbe.PostProcessingSessionData(
                        Keystore2DeepProbe.PostProcessingPathSample.success(90.0, lockedVerified, true),
                        true,
                        rkpSpoofed,
                        akReal));
        assertEquals(
                Keystore2DeepProbe.PostProcessingAnomaly.ROOT_OF_TRUST_DIVERGENCE,
                rotRes.getAnomaly());
        assertEquals(2, rotRes.getDivergentFields().size());

        // 2. High one-sided latency delta (+260ms, MAD ~2ms) -> TIMING_DETECTED
        List<Keystore2DeepProbe.PostProcessingPathSample> rkpSlow = new ArrayList<>();
        List<Keystore2DeepProbe.PostProcessingPathSample> akFast = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            rkpSlow.add(Keystore2DeepProbe.PostProcessingPathSample.success(340.0 + (i % 3), lockedVerified, true));
            akFast.add(Keystore2DeepProbe.PostProcessingPathSample.success(78.0 + (i % 2), lockedVerified, false));
        }
        Keystore2DeepProbe.PostProcessingResult timingRes = Keystore2DeepProbe.evaluatePostProcessing(
                new Keystore2DeepProbe.PostProcessingSessionData(
                        Keystore2DeepProbe.PostProcessingPathSample.success(350.0, lockedVerified, true),
                        true,
                        rkpSlow,
                        akFast));
        assertEquals(
                Keystore2DeepProbe.PostProcessingAnomaly.TIMING_DETECTED,
                timingRes.getAnomaly());

        // 3. RKP-only offline failure -> RKP_UNAVAILABLE (0 FP)
        Keystore2DeepProbe.PostProcessingResult offlineRes = Keystore2DeepProbe.evaluatePostProcessing(
                new Keystore2DeepProbe.PostProcessingSessionData(
                        Keystore2DeepProbe.PostProcessingPathSample.failure(
                                "ServiceSpecificException: OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY"),
                        false,
                        Collections.<Keystore2DeepProbe.PostProcessingPathSample>emptyList(),
                        Collections.<Keystore2DeepProbe.PostProcessingPathSample>emptyList()));
        assertEquals(
                Keystore2DeepProbe.PostProcessingAnomaly.RKP_UNAVAILABLE,
                offlineRes.getAnomaly());
    }

    @Test
    public void overwriteTrapAndStrongBoxConstraints_fullEndToEndRunAndCleanup() throws Exception {
        // Verify embedded marker certificate is valid standard X.509 DER
        MethodMarkerHelper.verifyEmbeddedMarkerCert();

        final byte[] priorLeaf = "prior_attested_leaf_der".getBytes(StandardCharsets.UTF_8);
        final byte[] priorInter = "prior_attested_intermediate_der".getBytes(StandardCharsets.UTF_8);
        final byte[] markerDer = "fresh_marker_leaf_der".getBytes(StandardCharsets.UTF_8);

        final Set<String> deletedAliases = new LinkedHashSet<>();

        byte[] spoofedReplyParcel = buildReplyParcel(
                0,
                Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                Collections.singletonList(
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                                0x10000002, 2, 3L, null)),
                null,
                null,
                1000L);

        AttestationRecord.RootOfTrust lockedRot = new AttestationRecord.RootOfTrust(
                new byte[]{1}, true, AttestationRecord.VerifiedBootState.VERIFIED, new byte[]{2}, true);
        List<Keystore2DeepProbe.PostProcessingPathSample> rkpSlow = new ArrayList<>();
        List<Keystore2DeepProbe.PostProcessingPathSample> akFast = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            rkpSlow.add(Keystore2DeepProbe.PostProcessingPathSample.success(310.0, lockedRot, true));
            akFast.add(Keystore2DeepProbe.PostProcessingPathSample.success(75.0, lockedRot, false));
        }

        Keystore2DeepProbe.ProbeResult result = Keystore2DeepProbe.run(
                new Keystore2DeepProbe.Keystore2DeepAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 35;
                    }

                    @Override
                    public byte[] captureGenerateKeyReplyParcel(String alias) {
                        return spoofedReplyParcel;
                    }

                    @Override
                    public Keystore2DeepProbe.PostProcessingSessionData collectPostProcessingSamples(
                            String aliasPrefix, int pairCount) {
                        return new Keystore2DeepProbe.PostProcessingSessionData(
                                Keystore2DeepProbe.PostProcessingPathSample.success(315.0, lockedRot, true),
                                true,
                                rkpSlow,
                                akFast);
                    }

                    @Override
                    public Keystore2DeepProbe.OverwriteSessionData collectOverwriteAndLifecycle(
                            String supportAlias, String attackAlias, String lifecycleAlias) {
                        // First readback looks clean, final readback replays priorInter from TEES-RS stale cache
                        Keystore2DeepProbe.PostUpdateSnapshot snap1 =
                                new Keystore2DeepProbe.PostUpdateSnapshot(
                                        Collections.singletonList(markerDer), true);
                        Keystore2DeepProbe.PostUpdateSnapshot snap2 =
                                new Keystore2DeepProbe.PostUpdateSnapshot(
                                        Arrays.asList(markerDer, priorInter), true);
                        return new Keystore2DeepProbe.OverwriteSessionData(
                                true,
                                Arrays.asList(priorLeaf, priorInter),
                                true,
                                Arrays.asList(snap1, snap2),
                                "deadbeef01",
                                "deadbeef01",
                                true);
                    }

                    @Override
                    public Keystore2DeepProbe.StrongBoxObservation collectStrongBoxObservation(
                            String aliasPrefix) {
                        return new Keystore2DeepProbe.StrongBoxObservation(
                                true,
                                true,
                                AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT,
                                5,
                                420,
                                Keystore2DeepProbe.StrongBoxAcceptance.ACCEPTED,
                                Keystore2DeepProbe.StrongBoxAcceptance.ACCEPTED,
                                null);
                    }

                    @Override
                    public void deleteAlias(String alias) {
                        deletedAliases.add(alias);
                    }
                });

        assertTrue(result.isUsable());
        assertTrue(result.hasFindings());
        assertTrue(result.getStrongTokens().contains(Keystore2DeepProbe.CODE_GENERATE_KEY_PARCEL_SPOOF));
        assertTrue(result.getStrongTokens().contains(Keystore2DeepProbe.CODE_OVERWRITE_STALE_CHAIN));
        assertTrue(result.getStrongTokens().contains(Keystore2DeepProbe.CODE_STRONGBOX_LEVEL_MISMATCH));
        assertTrue(result.getMediumTokens().contains(Keystore2DeepProbe.CODE_POST_PROCESSING_LATENCY));
        assertTrue(result.getMediumTokens().contains(Keystore2DeepProbe.CODE_LIFECYCLE_STALE_SERIAL));
        assertTrue(result.getMediumTokens().contains(Keystore2DeepProbe.CODE_SOFT_STRONGBOX));
        for (EvidenceItem item : result.getEvidenceItems()) {
            assertEquals("tee_tamper", item.getEvidenceFamily());
        }
        // 1 parcel + 1 pp + 3 overwrite/lifecycle + 1 sb = 6 cleanup calls
        assertEquals(6, deletedAliases.size());
    }

    @Test
    public void cleanStockDeviceAndHiddenApiDenials_produceZeroFalsePositivesAndAlwaysCleanup() {
        assertEquals(
                Keystore2DeepProbe.StrongBoxAcceptance.ACCEPTED,
                Keystore2DeepProbe.classifyStrongBoxAcceptance(null));
        assertEquals(
                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_FRAMEWORK,
                Keystore2DeepProbe.classifyStrongBoxAcceptance(
                        new InvalidAlgorithmParameterException("Unsupported StrongBox curve")));
        assertEquals(
                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_KEYSTORE,
                Keystore2DeepProbe.classifyStrongBoxAcceptance(
                        new ProviderException("KeyMint rejected RSA-4096")));
        assertEquals(
                Keystore2DeepProbe.StrongBoxAcceptance.INCONCLUSIVE,
                Keystore2DeepProbe.classifyStrongBoxAcceptance(new IllegalStateException("other")));

        final byte[] validParcel = buildReplyParcel(
                0,
                Keystore2DeepProbe.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                Arrays.asList(
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_KEYSTORE,
                                Keystore2DeepProbe.TAG_CREATION_DATETIME, 13, 1700000000000L, null),
                        new AuthSpec(Keystore2DeepProbe.SECURITY_LEVEL_SOFTWARE,
                                Keystore2DeepProbe.TAG_USER_ID, 8, 0L, null)),
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                1700000000100L);
        final byte[] marker = "marker".getBytes(StandardCharsets.UTF_8);
        final byte[] prior = "prior".getBytes(StandardCharsets.UTF_8);

        // Clean stock device (StrongBox authentic discrete SE)
        Keystore2DeepProbe.ProbeResult clean = Keystore2DeepProbe.run(
                new Keystore2DeepProbe.Keystore2DeepAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 34;
                    }

                    @Override
                    public byte[] captureGenerateKeyReplyParcel(String alias) {
                        return validParcel;
                    }

                    @Override
                    public Keystore2DeepProbe.PostProcessingSessionData collectPostProcessingSamples(
                            String aliasPrefix, int pairCount) {
                        return null;
                    }

                    @Override
                    public Keystore2DeepProbe.OverwriteSessionData collectOverwriteAndLifecycle(
                            String supportAlias, String attackAlias, String lifecycleAlias) {
                        return new Keystore2DeepProbe.OverwriteSessionData(
                                true,
                                Collections.singletonList(prior),
                                true,
                                Collections.singletonList(
                                        new Keystore2DeepProbe.PostUpdateSnapshot(
                                                Collections.singletonList(marker), true)),
                                "1001",
                                "1002",
                                true);
                    }

                    @Override
                    public Keystore2DeepProbe.StrongBoxObservation collectStrongBoxObservation(
                            String aliasPrefix) {
                        return new Keystore2DeepProbe.StrongBoxObservation(
                                true,
                                true,
                                AttestationRecord.SecurityLevel.STRONGBOX,
                                145,
                                14_500,
                                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_KEYSTORE,
                                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_FRAMEWORK,
                                null);
                    }

                    @Override
                    public void deleteAlias(String alias) {
                    }
                });
        assertTrue(clean.isUsable());
        assertFalse(clean.hasFindings());
        assertNull(clean.getFailureReason());

        // Hidden-API / SecurityException / LinkageError -> unavailable, 0 FP, all aliases cleaned
        final List<String> cleanedOnFailure = new ArrayList<>();
        Keystore2DeepProbe.ProbeResult denied = Keystore2DeepProbe.run(
                new Keystore2DeepProbe.Keystore2DeepAdapter() {
                    @Override
                    public int getSdkInt() {
                        return 35;
                    }

                    @Override
                    public byte[] captureGenerateKeyReplyParcel(String alias) {
                        throw new SecurityException("SELinux denied keystore2 binder");
                    }

                    @Override
                    public Keystore2DeepProbe.PostProcessingSessionData collectPostProcessingSamples(
                            String aliasPrefix, int pairCount) {
                        throw new NoClassDefFoundError("hidden_api_blocked");
                    }

                    @Override
                    public Keystore2DeepProbe.OverwriteSessionData collectOverwriteAndLifecycle(
                            String supportAlias, String attackAlias, String lifecycleAlias) {
                        throw new SecurityException("keystore locked");
                    }

                    @Override
                    public Keystore2DeepProbe.StrongBoxObservation collectStrongBoxObservation(
                            String aliasPrefix) {
                        throw new OutOfMemoryError("simulated_oom");
                    }

                    @Override
                    public void deleteAlias(String alias) {
                        cleanedOnFailure.add(alias);
                    }
                });
        assertFalse(denied.isUsable());
        assertFalse(denied.hasFindings());
        assertNotNull(denied.getFailureReason());
        assertEquals(6, cleanedOnFailure.size());
    }

    @Test
    public void defaultSerialOneFallbackAndTransientStrongBoxNullKeyInfo_produceZeroFalsePositives() {
        final byte[] marker = "marker".getBytes(StandardCharsets.UTF_8);
        final byte[] prior = "prior".getBytes(StandardCharsets.UTF_8);

        // Case 1: OEM KeyMint TA ignores TAG_CERTIFICATE_SERIAL (both return "1") with distinct SPKI
        //         AND StrongBox KeyInfo is transiently null while prior attestation was STRONGBOX -> 0 FP!
        Keystore2DeepProbe.ProbeResult zeroFp = Keystore2DeepProbe.run(
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
                        return new Keystore2DeepProbe.OverwriteSessionData(
                                true,
                                Collections.singletonList(prior),
                                true,
                                Collections.singletonList(
                                        new Keystore2DeepProbe.PostUpdateSnapshot(
                                                Collections.singletonList(marker), true)),
                                "1",
                                "1",
                                "spki_hash_fresh_1",
                                "spki_hash_fresh_2",
                                true);
                    }

                    @Override
                    public Keystore2DeepProbe.StrongBoxObservation collectStrongBoxObservation(
                            String aliasPrefix) {
                        return new Keystore2DeepProbe.StrongBoxObservation(
                                true,
                                null,
                                AttestationRecord.SecurityLevel.STRONGBOX,
                                null,
                                null,
                                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_KEYSTORE,
                                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_FRAMEWORK,
                                "StrongBoxUnavailableException");
                    }

                    @Override
                    public void deleteAlias(String alias) {
                    }
                });
        assertTrue(zeroFp.isUsable());
        assertFalse(zeroFp.hasFindings());

        // Case 2: Reused SPKI (even when serial is "1") + explicit Boolean.FALSE KeyInfo vs STRONGBOX -> flagged!
        Keystore2DeepProbe.ProbeResult positive = Keystore2DeepProbe.run(
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
                        return new Keystore2DeepProbe.OverwriteSessionData(
                                true,
                                Collections.singletonList(prior),
                                true,
                                Collections.singletonList(
                                        new Keystore2DeepProbe.PostUpdateSnapshot(
                                                Collections.singletonList(marker), true)),
                                "1",
                                "1",
                                "spki_hash_reused",
                                "spki_hash_reused",
                                true);
                    }

                    @Override
                    public Keystore2DeepProbe.StrongBoxObservation collectStrongBoxObservation(
                            String aliasPrefix) {
                        return new Keystore2DeepProbe.StrongBoxObservation(
                                true,
                                Boolean.FALSE,
                                AttestationRecord.SecurityLevel.STRONGBOX,
                                50,
                                8_000,
                                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_KEYSTORE,
                                Keystore2DeepProbe.StrongBoxAcceptance.REFUSED_BY_FRAMEWORK,
                                null);
                    }

                    @Override
                    public void deleteAlias(String alias) {
                    }
                });
        assertTrue(positive.getMediumTokens().contains(Keystore2DeepProbe.CODE_LIFECYCLE_STALE_SERIAL));
        assertTrue(positive.getStrongTokens().contains(Keystore2DeepProbe.CODE_STRONGBOX_LEVEL_MISMATCH));
    }

    private static final class MethodMarkerHelper {
        static void verifyEmbeddedMarkerCert() throws Exception {
            java.lang.reflect.Method m =
                    Keystore2DeepProbe.class.getDeclaredMethod("loadMarkerCertificate");
            m.setAccessible(true);
            X509Certificate cert = (X509Certificate) m.invoke(null);
            assertNotNull(cert);
            assertTrue(cert.getSubjectX500Principal().getName().contains("RiskEngineMarker"));
        }
    }

    private static final class AuthSpec {
        final int securityLevel;
        final int tag;
        final int valueTag;
        final Long scalar;
        final byte[] blob;

        AuthSpec(int securityLevel, int tag, int valueTag, Long scalar, byte[] blob) {
            this.securityLevel = securityLevel;
            this.tag = tag;
            this.valueTag = valueTag;
            this.scalar = scalar;
            this.blob = blob;
        }
    }

    private static byte[] buildReplyParcel(
            int exceptionCode,
            int keySecurityLevel,
            List<AuthSpec> auths,
            byte[] cert,
            byte[] certChain,
            long modTimeMs) {
        ParcelBytes descriptorBody = new ParcelBytes();
        descriptorBody.writeInt(4); // domain = KEY_ID
        descriptorBody.writeLong(42L); // nspace

        ParcelBytes metadataBody = new ParcelBytes();
        metadataBody.writeParcelable(descriptorBody.toByteArray());
        metadataBody.writeInt(keySecurityLevel);
        metadataBody.writeInt(auths.size());
        for (AuthSpec spec : auths) {
            ParcelBytes kpBody = new ParcelBytes();
            kpBody.writeInt(spec.tag);
            kpBody.writeInt(1); // non-null KeyParameterValue union marker
            kpBody.writeInt(spec.valueTag);
            if (spec.valueTag >= 0 && spec.valueTag <= 11) {
                kpBody.writeInt(spec.scalar.intValue());
            } else if (spec.valueTag == 12 || spec.valueTag == 13) {
                kpBody.writeLong(spec.scalar);
            } else if (spec.valueTag == 14) {
                kpBody.writeByteArray(spec.blob);
            }

            ParcelBytes authBody = new ParcelBytes();
            authBody.writeInt(spec.securityLevel);
            authBody.writeParcelable(kpBody.toByteArray());
            metadataBody.writeParcelable(authBody.toByteArray());
        }
        metadataBody.writeNullableByteArray(cert);
        metadataBody.writeNullableByteArray(certChain);
        metadataBody.writeLong(modTimeMs);

        ParcelBytes root = new ParcelBytes();
        root.writeInt(exceptionCode);
        root.writeParcelable(metadataBody.toByteArray());
        return root.toByteArray();
    }

    private static final class ParcelBytes {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        void writeInt(int v) {
            out.write(v & 0xFF);
            out.write((v >>> 8) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 24) & 0xFF);
        }

        void writeLong(long v) {
            for (int i = 0; i < 8; i++) {
                out.write((int) ((v >>> (i * 8)) & 0xFFL));
            }
        }

        void writeParcelable(byte[] payloadWithoutSizeHeader) {
            writeInt(1); // non-null marker
            writeInt(4 + payloadWithoutSizeHeader.length); // parcelable size counts itself
            out.write(payloadWithoutSizeHeader, 0, payloadWithoutSizeHeader.length);
        }

        void writeByteArray(byte[] data) {
            writeInt(data.length);
            out.write(data, 0, data.length);
            int pad = (4 - (data.length & 3)) & 3;
            for (int i = 0; i < pad; i++) {
                out.write(0);
            }
        }

        void writeNullableByteArray(byte[] data) {
            if (data == null) {
                writeInt(-1);
                return;
            }
            writeByteArray(data);
        }

        byte[] toByteArray() {
            return out.toByteArray();
        }
    }
}
