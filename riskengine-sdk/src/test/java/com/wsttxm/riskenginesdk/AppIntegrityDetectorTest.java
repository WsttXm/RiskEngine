package com.wsttxm.riskenginesdk;

import android.content.pm.ApplicationInfo;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.AppIntegrityDetector;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.DetectorRegistry;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AppIntegrityDetectorTest {

    private static final String CERT_OLD = sha256Base64("cert-old-v1-key");
    private static final String CERT_NEW = sha256Base64("cert-new-v3-rotated-key");
    private static final String CERT_ALT = sha256Base64("cert-second-multi-signer");
    private static final String CERT_EVIL = sha256Base64("cert-repackaged-attacker");

    @Test
    public void declaresCriticalTierAndRegisteredByDefault() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();
        assertTrue(config.isEnableAppIntegrityDetection());

        DetectorRegistry registry = new DetectorRegistry(null, config);
        BaseDetector found = null;
        for (BaseDetector d : registry.getDetectors()) {
            if ("app_integrity".equals(d.getName())) {
                found = d;
                break;
            }
        }
        assertTrue("app_integrity should be registered by default", found != null);
        assertEquals(ScanTier.CRITICAL, found.getScanTier());
    }

    @Test
    public void unconfiguredPinningCleanPlayReleaseProducesSafe() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(
                SignalResult.unavailable("native_library_unavailable"));

        FakeEnv env = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        DetectionResult result = AppIntegrityDetector.createForTest(null, config, signals, env).call();

        assertEquals("app_integrity", result.getDetectorName());
        assertEquals(ScanTier.CRITICAL, result.getScanTier());
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertEquals(0, result.getScore());
        assertFalse(result.isInformational());
        assertEquals(DetectionExecutionStatus.SAFE, result.getExecutionStatus());
    }

    @Test
    public void expectedPackageNameMismatchTriggersDeadlyHardTrigger() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .expectedPackageName("com.bank.genuine")
                .build();
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.unavailable("unavailable"));

        FakeEnv env = FakeEnv.cleanPlayRelease("com.bank.repackaged", CERT_NEW);
        DetectionResult result = AppIntegrityDetector.createForTest(null, config, signals, env).call();

        assertEquals(RiskLevel.DEADLY, result.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, result.getStatus());
        assertEquals(10, result.getScore());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().contains("pkg_name_mismatch:com.bank.repackaged"));
        assertHasEvidence(result, "pkg_name_mismatch", "app_tamper", EvidenceItem.Rank.STRONG);

        RiskReport report = new RiskReport(new DeviceFingerprint(), List.of(result));
        assertEquals(RiskLevel.DEADLY, report.getOverallRiskLevel());
    }

    @Test
    public void apkV3RotatedCertValidatesActiveSignerNotHistoryFirst() {
        // Free-RASP bug regression: history[0] is OLD, active apkContentsSigners[0]/history[last] is NEW.
        FakeEnv env = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        env.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true,
                false,
                List.of(CERT_NEW),
                List.of(CERT_OLD, CERT_NEW));

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.success(
                buildRotatedV2V3V31Payload("/data/app/com.example.app/base.apk", CERT_OLD, CERT_NEW)));

        // 1. Host pins ONLY the active rotated cert (CERT_NEW) -> MUST PASS
        RiskEngineConfig pinNew = new RiskEngineConfig.Builder()
                .expectedPackageName("com.example.app")
                .expectedSigningCertSha256Base64(CERT_NEW)
                .build();
        DetectionResult passNew = AppIntegrityDetector.createForTest(null, pinNew, signals, env).call();
        assertEquals(RiskLevel.SAFE, passNew.getRiskLevel());
        assertEquals(0, passNew.getScore());

        // 2. Host pins ONLY the retired cert (CERT_OLD) -> MUST FAIL (never treat history[0] as active)
        RiskEngineConfig pinOldOnly = new RiskEngineConfig.Builder()
                .expectedPackageName("com.example.app")
                .expectedSigningCertSha256Base64(CERT_OLD)
                .build();
        DetectionResult failOldOnly =
                AppIntegrityDetector.createForTest(null, pinOldOnly, signals, env).call();
        assertEquals(RiskLevel.DEADLY, failOldOnly.getRiskLevel());
        assertEquals(10, failOldOnly.getScore());
        assertFalse(failOldOnly.isInformational());
        assertTrue(failOldOnly.getDetails().contains("apk_sig_mismatch"));
        EvidenceItem merged = findEvidence(failOldOnly, "apk_sig_mismatch");
        assertTrue(merged != null);
        assertEquals(Set.of(EvidenceItem.SourceLayer.JAVA, EvidenceItem.SourceLayer.NATIVE),
                merged.getMergedSources());

        // 3. On API 31 (below v3.1 min_sdk=33), native selects v3 (CERT_OLD) matching Java CERT_OLD
        FakeEnv envApi31 = FakeEnv.cleanPlayRelease("com.example.app", CERT_OLD);
        envApi31.sdkInt = 31;
        envApi31.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true, false, List.of(CERT_OLD), List.of(CERT_OLD));
        DetectionResult passApi31 =
                AppIntegrityDetector.createForTest(null, pinOldOnly, signals, envApi31).call();
        assertEquals(RiskLevel.SAFE, passApi31.getRiskLevel());
    }

    @Test
    public void apkV3HistoryFallbackUsesLastEntryAndDetectsActiveHistoryConflict() {
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.unavailable("no_native"));

        // When apkContentsSigners is empty, active signer falls back to history[last] (CERT_NEW)
        FakeEnv fallbackEnv = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        fallbackEnv.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true, false, Collections.emptyList(), List.of(CERT_OLD, CERT_NEW));
        RiskEngineConfig pinNew = new RiskEngineConfig.Builder()
                .expectedSigningCertSha256Base64(CERT_NEW)
                .build();
        assertEquals(RiskLevel.SAFE,
                AppIntegrityDetector.createForTest(null, pinNew, signals, fallbackEnv).call()
                        .getRiskLevel());

        // When apkContentsSigners[0] disagrees with history[last], flag DEADLY mismatch
        FakeEnv conflictEnv = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        conflictEnv.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true, false, List.of(CERT_NEW), List.of(CERT_NEW, CERT_OLD));
        DetectionResult conflict =
                AppIntegrityDetector.createForTest(null, pinNew, signals, conflictEnv).call();
        assertEquals(RiskLevel.DEADLY, conflict.getRiskLevel());
        assertTrue(conflict.getDetails().stream().anyMatch(d -> d.startsWith("apk_sig_mismatch")));
    }

    @Test
    public void hasMultipleSignersVerifiesAllApkContentsSigners() {
        FakeEnv env = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        env.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true,
                true,
                List.of(CERT_NEW, CERT_ALT),
                Collections.emptyList());

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.success(
                buildV2Payload("/data/app/com.example.app/base.apk", CERT_NEW, CERT_ALT)));

        // Pinning both signers passes
        RiskEngineConfig pinBoth = new RiskEngineConfig.Builder()
                .expectedSigningCertSha256Base64(CERT_NEW, CERT_ALT)
                .build();
        assertEquals(RiskLevel.SAFE,
                AppIntegrityDetector.createForTest(null, pinBoth, signals, env).call()
                        .getRiskLevel());

        // Pinning only one signer MUST fail because the second signer is untrusted
        RiskEngineConfig pinOne = new RiskEngineConfig.Builder()
                .expectedSigningCertSha256Base64(CERT_NEW)
                .build();
        DetectionResult fail = AppIntegrityDetector.createForTest(null, pinOne, signals, env).call();
        assertEquals(RiskLevel.DEADLY, fail.getRiskLevel());
        assertEquals(10, fail.getScore());
        assertTrue(fail.getDetails().contains("apk_sig_mismatch"));
    }

    @Test
    public void nativeVsJavaSigningConflictTriggersDeadlyHardTriggerEvenWithoutPinning() {
        // Simulates PackageManager Binder hook: Java reports CERT_NEW, native raw base.apk has CERT_EVIL
        RiskEngineConfig unpinned = new RiskEngineConfig.Builder().build();
        FakeEnv env = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.success(
                buildV2Payload("/data/app/~~abc/com.example.app-1/base.apk", CERT_EVIL)));

        DetectionResult result =
                AppIntegrityDetector.createForTest(null, unpinned, signals, env).call();

        assertEquals(RiskLevel.DEADLY, result.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, result.getStatus());
        assertEquals(10, result.getScore());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().contains("apk_native_java_sig_conflict"));
        EvidenceItem item = findEvidence(result, "apk_native_java_sig_conflict");
        assertTrue(item != null);
        assertEquals("app_tamper", item.getEvidenceFamily());
        assertEquals(EvidenceItem.Rank.STRONG, item.getRank());
        assertEquals(Set.of(EvidenceItem.SourceLayer.JAVA, EvidenceItem.SourceLayer.NATIVE),
                item.getMergedSources());

        RiskReport report = new RiskReport(new DeviceFingerprint(), List.of(result));
        assertEquals(RiskLevel.DEADLY, report.getOverallRiskLevel());
    }

    @Test
    public void nativeVsJavaRotationLineageMismatchAndEmptiedHistoryTriggerDeadlyConflict() {
        RiskEngineConfig unpinned = new RiskEngineConfig.Builder().build();
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.success(
                buildRotatedV2V3V31Payload("/data/app/com.example.app/base.apk", CERT_OLD, CERT_NEW)));

        // (a) Java tampered predecessor certificate in lineage [CERT_EVIL, CERT_NEW]
        FakeEnv tamperedHistory = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        tamperedHistory.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true, false, List.of(CERT_NEW), List.of(CERT_EVIL, CERT_NEW));
        DetectionResult resTampered =
                AppIntegrityDetector.createForTest(null, unpinned, signals, tamperedHistory).call();
        assertEquals(RiskLevel.DEADLY, resTampered.getRiskLevel());
        assertTrue(resTampered.getDetails().contains("apk_native_java_sig_conflict"));
        assertEquals(RiskLevel.DEADLY,
                new RiskReport(new DeviceFingerprint(), List.of(resTampered)).getOverallRiskLevel());

        // (b) Java hooked getSigningCertificateHistory() to return empty while native has lineage
        FakeEnv emptiedHistory = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        emptiedHistory.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true, false, List.of(CERT_NEW), Collections.emptyList());
        DetectionResult resEmptied =
                AppIntegrityDetector.createForTest(null, unpinned, signals, emptiedHistory).call();
        assertEquals(RiskLevel.DEADLY, resEmptied.getRiskLevel());
        assertTrue(resEmptied.getDetails().contains("apk_native_java_sig_conflict"));
        assertEquals(RiskLevel.DEADLY,
                new RiskReport(new DeviceFingerprint(), List.of(resEmptied)).getOverallRiskLevel());
    }

    @Test
    public void evidenceFamilyPrioritizesAppTamperOverSubstringMatchesInPackageNames() {
        assertEquals("app_tamper",
                EvidenceFamily.familyOf("unofficial_installer:com.holiday.store"));
        assertEquals("app_tamper",
                EvidenceFamily.familyOf("pkg_name_mismatch:com.candidate.app"));
        assertEquals("app_tamper",
                EvidenceFamily.familyOf("unofficial_installer:com.friday.market"));
        assertEquals(Set.of("app_tamper"),
                EvidenceFamily.families(List.of(
                        "unofficial_installer:com.holiday.store",
                        "pkg_name_mismatch:com.candidate.app")));
    }

    @Test
    public void spoofedHasMultipleSignersFalseStillCatchesMultiSignerSmuggling() {
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.unavailable("no_native"));

        FakeEnv spoofed = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        spoofed.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                true,
                false, // Hooked to lie false while two signers are present
                List.of(CERT_NEW, CERT_EVIL),
                List.of(CERT_NEW));

        RiskEngineConfig pinNew = new RiskEngineConfig.Builder()
                .expectedSigningCertSha256Base64(CERT_NEW)
                .build();
        DetectionResult res =
                AppIntegrityDetector.createForTest(null, pinNew, signals, spoofed).call();
        assertEquals(RiskLevel.DEADLY, res.getRiskLevel());
        assertTrue(res.getDetails().contains("apk_sig_mismatch"));
    }

    @Test
    public void nativeV31BlockIsIgnoredBelowApi33() {
        // Non-standard v3.1 claiming min_sdk=30 must be ignored on API 31 (AOSP falls back to v3)
        Map<String, String> header = new LinkedHashMap<>();
        header.put("reason", "ok");
        header.put("apk_path", "/data/app/com.example.app/base.apk");
        List<Map<String, String>> records = List.of(
                signerRec("v3", 0, 28, Integer.MAX_VALUE, CERT_OLD),
                signerRec("v3.1", 0, 30, Integer.MAX_VALUE, CERT_NEW));
        String payload = NativePayloadCodec.encodePayload(
                NativePayloadCodec.Status.OK, 0, header, records);

        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.success(payload));

        FakeEnv envApi31 = FakeEnv.cleanPlayRelease("com.example.app", CERT_OLD);
        envApi31.sdkInt = 31;
        RiskEngineConfig pinOld = new RiskEngineConfig.Builder()
                .expectedSigningCertSha256Base64(CERT_OLD)
                .build();
        DetectionResult res =
                AppIntegrityDetector.createForTest(null, pinOld, signals, envApi31).call();
        assertEquals(RiskLevel.SAFE, res.getRiskLevel());
    }

    @Test
    public void nativeUnsupportedOrRestrictedNeverCausesFalsePositive() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .expectedSigningCertSha256Base64(CERT_NEW)
                .build();
        FakeEnv env = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);

        for (NativePayloadCodec.Status st : List.of(
                NativePayloadCodec.Status.UNSUPPORTED, NativePayloadCodec.Status.RESTRICTED)) {
            SignalSnapshot signals = new SignalSnapshot(null);
            String payload = NativePayloadCodec.encodePayload(
                    st, st == NativePayloadCodec.Status.RESTRICTED ? 13 : 0,
                    Map.of("reason", st == NativePayloadCodec.Status.RESTRICTED
                            ? "open_failed" : "no_apk_sig_block"),
                    Collections.emptyList());
            signals.seedNativeApkSigningInfoForTest(SignalResult.success(payload));

            DetectionResult res = AppIntegrityDetector.createForTest(null, config, signals, env).call();
            assertEquals(RiskLevel.SAFE, res.getRiskLevel());
            assertEquals(DetectionExecutionStatus.SAFE, res.getExecutionStatus());
        }
    }

    @Test
    public void installerPresetsCustomOverrideAndScenePromotionWorkCorrectly() {
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.unavailable("no_native"));

        // Built-in official preset (Huawei AppGallery) -> SAFE
        FakeEnv huaweiEnv = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        huaweiEnv.installSource = new AppIntegrityDetector.InstallSourceSnapshot(
                true, "com.huawei.appmarket", "com.huawei.appmarket");
        RiskEngineConfig defaultConfig = new RiskEngineConfig.Builder().build();
        assertEquals(RiskLevel.SAFE,
                AppIntegrityDetector.createForTest(null, defaultConfig, signals, huaweiEnv).call()
                        .getRiskLevel());

        // Custom trustedInstallerPackages override rejects Play and accepts custom enterprise store
        RiskEngineConfig customStoreConfig = new RiskEngineConfig.Builder()
                .trustedInstallerPackages("com.corp.appstore")
                .build();
        assertTrue(customStoreConfig.hasCustomTrustedInstallerPackages());

        FakeEnv corpEnv = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        corpEnv.installSource = new AppIntegrityDetector.InstallSourceSnapshot(
                true, "com.corp.appstore", "com.corp.appstore");
        assertEquals(RiskLevel.SAFE,
                AppIntegrityDetector.createForTest(null, customStoreConfig, signals, corpEnv).call()
                        .getRiskLevel());

        FakeEnv playEnv = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        DetectionResult raw =
                AppIntegrityDetector.createForTest(null, customStoreConfig, signals, playEnv).call();
        assertEquals(RiskLevel.MEDIUM, raw.getRiskLevel());
        assertEquals(4, raw.getScore());
        assertTrue("unofficial_installer should be informational in STANDARD", raw.isInformational());
        assertHasEvidence(raw, "unofficial_installer", "app_tamper", EvidenceItem.Rank.MEDIUM);

        // STANDARD / LOGIN stay informational; PAYMENT / DIAGNOSTIC promote to actionable
        assertTrue(CorrelationEngine.applyScene(raw, CollectScene.STANDARD).isInformational());
        assertTrue(CorrelationEngine.applyScene(raw, CollectScene.LOGIN).isInformational());
        assertFalse(CorrelationEngine.applyScene(raw, CollectScene.PAYMENT).isInformational());
        assertFalse(CorrelationEngine.applyScene(raw, CollectScene.DIAGNOSTIC).isInformational());
    }

    @Test
    public void obfuscationSentinelSkipsDebuggableAndFlagsUnobfuscatedRelease() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.unavailable("no_native"));

        // Debuggable build with unobfuscated sentinel -> SAFE
        FakeEnv debugEnv = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        debugEnv.appFlags = ApplicationInfo.FLAG_DEBUGGABLE;
        debugEnv.obfuscated = false;
        assertEquals(RiskLevel.SAFE,
                AppIntegrityDetector.createForTest(null, config, signals, debugEnv).call()
                        .getRiskLevel());

        // Non-debuggable release with unobfuscated sentinel -> LOW/2 informational in STANDARD,
        // actionable in PAYMENT/DIAGNOSTIC
        FakeEnv releaseUnobf = FakeEnv.cleanPlayRelease("com.example.app", CERT_NEW);
        releaseUnobf.appFlags = 0;
        releaseUnobf.obfuscated = false;
        DetectionResult res =
                AppIntegrityDetector.createForTest(null, config, signals, releaseUnobf).call();
        assertEquals(RiskLevel.LOW, res.getRiskLevel());
        assertEquals(2, res.getScore());
        assertTrue(res.isInformational());
        assertTrue(res.getDetails().contains("release_unobfuscated"));
        assertHasEvidence(res, "release_unobfuscated", "app_tamper", EvidenceItem.Rank.WEAK);

        assertTrue(CorrelationEngine.applyScene(res, CollectScene.STANDARD).isInformational());
        assertTrue(CorrelationEngine.applyScene(res, CollectScene.LOGIN).isInformational());
        assertFalse(CorrelationEngine.applyScene(res, CollectScene.PAYMENT).isInformational());
        assertFalse(CorrelationEngine.applyScene(res, CollectScene.DIAGNOSTIC).isInformational());
    }

    @Test
    public void riskReportHardTriggersCoverPhase0AndAppIntegrityTokens() {
        List<DetectionResult> hardTriggerCases = Arrays.asList(
                highResult("hook_framework", "text_mismatch"),
                highResult("hook_framework", "native:text_mismatch:libriskengine.so"),
                highResult("hook_framework", "late_text_mismatch"),
                highResult("hook_framework", "jni_self_hook:nativeGetRootEvidenceRaw"),
                highResult("hook_framework", "fn_prologue_hook:hook_ev"),
                highResult("app_integrity", "apk_sig_mismatch"),
                highResult("app_integrity", "pkg_name_mismatch:com.evil"),
                highResult("app_integrity", "apk_native_java_sig_conflict"),
                highResult("signal_correlation", "C6:bridge_or_integrity_tamper")
        );

        for (DetectionResult detection : hardTriggerCases) {
            RiskReport report = new RiskReport(new DeviceFingerprint(), List.of(detection));
            assertEquals("Expected DEADLY hard trigger for " + detection.getDetails(),
                    RiskLevel.DEADLY, report.getOverallRiskLevel());
        }
    }

    @Test
    public void correlationDedupeFamiliesInspectsBothDetailsAndEvidenceItems() {
        // First detector carries app_tamper only via EvidenceItem (custom detail token)
        DetectionResult first = new DetectionResult(
                "app_integrity",
                RiskLevel.MEDIUM,
                DetectionStatus.WARNING,
                4,
                10,
                false,
                List.of("custom_integrity_token_a"),
                "custom_integrity_token_a"
        ).withEvidenceItems(List.of(new EvidenceItem(
                "custom_integrity_token_a",
                EvidenceItem.SourceLayer.JAVA,
                "pkg",
                "val",
                "app_tamper",
                EvidenceItem.Rank.MEDIUM)));

        // Second detector also claims app_tamper via EvidenceItem only -> must be deduped!
        DetectionResult second = new DetectionResult(
                "secondary_integrity",
                RiskLevel.MEDIUM,
                DetectionStatus.WARNING,
                4,
                10,
                false,
                List.of("custom_integrity_token_b"),
                "custom_integrity_token_b"
        ).withEvidenceItems(List.of(new EvidenceItem(
                "custom_integrity_token_b",
                EvidenceItem.SourceLayer.NATIVE,
                "apk",
                "val",
                "app_tamper",
                EvidenceItem.Rank.MEDIUM)));

        assertEquals(Set.of("app_tamper"),
                EvidenceFamily.families(first.getDetails(), first.getEvidenceItems()));

        List<DetectionResult> deduped = CorrelationEngine.dedupeFamilies(List.of(first, second));
        assertFalse(deduped.get(0).isInformational());
        assertTrue("Second detector sharing EvidenceItem family must be deduped",
                deduped.get(1).isInformational());
        assertTrue(deduped.get(1).getDetails().contains("deduped:corroborating_evidence"));
    }

    @Test
    public void hostileEnvironmentFaultsNeverCrashAppIntegrityDetector() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .expectedPackageName("com.example.app")
                .expectedSigningCertSha256Base64(CERT_NEW)
                .build();
        SignalSnapshot signals = new SignalSnapshot(null);
        signals.seedNativeApkSigningInfoForTest(SignalResult.error("SecurityException"));

        AppIntegrityDetector.IntegrityEnvironment hostile =
                new AppIntegrityDetector.IntegrityEnvironment() {
                    @Override public String getRuntimePackageName() { throw new SecurityException("denied"); }
                    @Override public String getApplicationInfoPackageName() { throw new RuntimeException("boom"); }
                    @Override public Integer getApplicationFlags() { throw new UnsatisfiedLinkError("missing"); }
                    @Override public AppIntegrityDetector.JavaSigningSnapshot readJavaSigningSnapshot() {
                        throw new OutOfMemoryError("oom");
                    }
                    @Override public AppIntegrityDetector.InstallSourceSnapshot readInstallSource() {
                        throw new SecurityException("denied");
                    }
                    @Override public int getSdkInt() { return 34; }
                    @Override public boolean isObfuscated() { throw new RuntimeException("boom"); }
                };

        DetectionResult result =
                AppIntegrityDetector.createForTest(null, config, signals, hostile).call();
        assertEquals("app_integrity", result.getDetectorName());
        assertEquals(ScanTier.CRITICAL, result.getScanTier());
        assertEquals(DetectionExecutionStatus.UNAVAILABLE, result.getExecutionStatus());
        assertEquals(RiskLevel.UNKNOWN, result.getRiskLevel());
    }

    private static DetectionResult highResult(String detectorName, String detail) {
        return new DetectionResult(
                detectorName,
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8,
                10,
                false,
                List.of(detail),
                detail
        );
    }

    private static void assertHasEvidence(DetectionResult result,
                                          String code,
                                          String family,
                                          EvidenceItem.Rank rank) {
        EvidenceItem item = findEvidence(result, code);
        assertTrue("Expected EvidenceItem with code=" + code, item != null);
        assertEquals(family, item.getEvidenceFamily());
        assertEquals(rank, item.getRank());
    }

    private static EvidenceItem findEvidence(DetectionResult result, String code) {
        for (EvidenceItem item : result.getEvidenceItems()) {
            if (code.equals(item.getCode())) {
                return item;
            }
        }
        return null;
    }

    private static String buildV2Payload(String apkPath, String... certB64s) {
        Map<String, String> header = new LinkedHashMap<>();
        header.put("reason", "ok");
        header.put("path_source", "maps");
        header.put("apk_path", apkPath);
        header.put("schemes", "v2");
        List<Map<String, String>> records = new ArrayList<>();
        for (int i = 0; i < certB64s.length; i++) {
            Map<String, String> rec = new LinkedHashMap<>();
            rec.put("kind", "signer");
            rec.put("scheme", "v2");
            rec.put("index", Integer.toString(i));
            rec.put("cert_sha256_b64", certB64s[i]);
            records.add(rec);
        }
        return NativePayloadCodec.encodePayload(NativePayloadCodec.Status.OK, 0, header, records);
    }

    private static String buildRotatedV2V3V31Payload(String apkPath, String oldCert, String newCert) {
        Map<String, String> header = new LinkedHashMap<>();
        header.put("reason", "ok");
        header.put("path_source", "maps");
        header.put("apk_path", apkPath);
        header.put("schemes", "v2,v3,v3.1");

        List<Map<String, String>> records = new ArrayList<>();
        records.add(signerRec("v2", 0, null, null, oldCert));
        records.add(signerRec("v3", 0, 24, 32, oldCert));
        records.add(signerRec("v3.1", 0, 33, Integer.MAX_VALUE, newCert));
        records.add(lineageRec("v3.1", 0, 0, oldCert));
        records.add(lineageRec("v3.1", 0, 1, newCert));
        return NativePayloadCodec.encodePayload(NativePayloadCodec.Status.OK, 0, header, records);
    }

    private static Map<String, String> signerRec(String scheme,
                                                 int idx,
                                                 Integer minSdk,
                                                 Integer maxSdk,
                                                 String certB64) {
        Map<String, String> rec = new LinkedHashMap<>();
        rec.put("kind", "signer");
        rec.put("scheme", scheme);
        rec.put("index", Integer.toString(idx));
        if (minSdk != null) rec.put("min_sdk", Integer.toString(minSdk));
        if (maxSdk != null) rec.put("max_sdk", Integer.toString(maxSdk));
        rec.put("cert_sha256_b64", certB64);
        return rec;
    }

    private static Map<String, String> lineageRec(String scheme,
                                                  int signerIdx,
                                                  int level,
                                                  String certB64) {
        Map<String, String> rec = new LinkedHashMap<>();
        rec.put("kind", "lineage");
        rec.put("scheme", scheme);
        rec.put("signer_index", Integer.toString(signerIdx));
        rec.put("level", Integer.toString(level));
        rec.put("cert_sha256_b64", certB64);
        return rec;
    }

    private static String sha256Base64(String seed) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(
                    md.digest(seed.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final class FakeEnv implements AppIntegrityDetector.IntegrityEnvironment {
        String runtimePkg;
        String appInfoPkg;
        Integer appFlags = 0;
        AppIntegrityDetector.JavaSigningSnapshot javaSigning;
        AppIntegrityDetector.InstallSourceSnapshot installSource;
        int sdkInt = 34;
        boolean obfuscated = true;

        static FakeEnv cleanPlayRelease(String pkg, String certB64) {
            FakeEnv env = new FakeEnv();
            env.runtimePkg = pkg;
            env.appInfoPkg = pkg;
            env.appFlags = 0;
            env.javaSigning = new AppIntegrityDetector.JavaSigningSnapshot(
                    true, false, List.of(certB64), List.of(certB64));
            env.installSource = new AppIntegrityDetector.InstallSourceSnapshot(
                    true, "com.android.vending", "com.android.vending");
            env.sdkInt = 34;
            env.obfuscated = true;
            return env;
        }

        @Override public String getRuntimePackageName() { return runtimePkg; }
        @Override public String getApplicationInfoPackageName() { return appInfoPkg; }
        @Override public Integer getApplicationFlags() { return appFlags; }
        @Override public AppIntegrityDetector.JavaSigningSnapshot readJavaSigningSnapshot() {
            return javaSigning;
        }
        @Override public AppIntegrityDetector.InstallSourceSnapshot readInstallSource() {
            return installSource;
        }
        @Override public int getSdkInt() { return sdkInt; }
        @Override public boolean isObfuscated() { return obfuscated; }
    }
}
