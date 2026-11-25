package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.content.ContextWrapper;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskAction;
import com.wsttxm.riskenginesdk.model.RiskDimension;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.model.TierReport;

import org.junit.After;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class RiskPolicyTest {

    @After
    public void tearDown() {
        RiskEngine.shutdown();
        RiskEngine.getInstance().setNativeHooksForTest(null);
    }

    @Test
    public void forSceneProvidesExpectedDefaultsForAllFourScenes() {
        for (CollectScene scene : CollectScene.values()) {
            RiskPolicy policy = RiskPolicy.forScene(scene);
            assertEquals(scene, policy.getBaseScene());
            assertEquals(30, policy.getChallengeThreshold());
            assertEquals(60, policy.getRestrictThreshold());
            assertEquals(85, policy.getBlockThreshold());
            RiskAction expectedHigh = scene == CollectScene.PAYMENT
                    ? RiskAction.BLOCK
                    : RiskAction.RESTRICT;
            assertEquals(expectedHigh, policy.getHighAction());
            for (RiskDimension dim : RiskDimension.values()) {
                assertEquals(1.0d, policy.getDimensionWeight(dim), 1e-9);
            }
            assertTrue(policy.getFamilyModes().isEmpty());
            assertTrue(policy.getFamilyMultipliers().isEmpty());
            assertTrue(policy.getSuppressedHardTriggers().isEmpty());
            assertSame(policy, RiskPolicy.forScene(scene));
        }
    }

    @Test
    public void builderProducesImmutablePolicyAndSupportsToBuilderCloning() {
        RiskPolicy.Builder builder = RiskPolicy.builder(CollectScene.LOGIN)
                .dimensionWeight(RiskDimension.ENVIRONMENT, 2.0d)
                .actionThresholds(20, 45, 75)
                .highAction(RiskAction.BLOCK)
                .allowlistFamily("network_mitm")
                .informationalOnlyFamily("adb")
                .familyMultiplier("virtual_container", 1.5d)
                .suppressHardTrigger("vbmeta_empty_input_digest");

        RiskPolicy first = builder.build();
        // Mutating builder after build must not mutate built policy
        builder.dimensionWeight(RiskDimension.ENVIRONMENT, 0.5d)
                .familyMultiplier("network_mitm", 2.0d)
                .suppressHardTrigger("inline_hook:");

        assertEquals(CollectScene.LOGIN, first.getBaseScene());
        assertEquals(2.0d, first.getDimensionWeight(RiskDimension.ENVIRONMENT), 1e-9);
        assertEquals(20, first.getChallengeThreshold());
        assertEquals(45, first.getRestrictThreshold());
        assertEquals(75, first.getBlockThreshold());
        assertEquals(RiskAction.BLOCK, first.getHighAction());
        assertEquals(RiskPolicy.FamilyMode.ALLOWLIST, first.getFamilyMode("network_mitm"));
        assertEquals(RiskPolicy.FamilyMode.INFORMATIONAL_ONLY, first.getFamilyMode("adb"));
        assertEquals(RiskPolicy.FamilyMode.DEFAULT, first.getFamilyMode("virtual_container"));
        assertEquals(1.5d, first.getFamilyMultiplier("virtual_container"), 1e-9);
        assertEquals(1, first.getSuppressedHardTriggers().size());
        assertTrue(first.getSuppressedHardTriggers().contains("vbmeta_empty_input_digest"));

        // Returned collections must be unmodifiable
        assertThrows(UnsupportedOperationException.class,
                () -> first.getDimensionWeights().put(RiskDimension.PRIVILEGE, 3.0d));
        assertThrows(UnsupportedOperationException.class,
                () -> first.getFamilyModes().put("root_fw", RiskPolicy.FamilyMode.ALLOWLIST));
        assertThrows(UnsupportedOperationException.class,
                () -> first.getFamilyMultipliers().put("root_fw", 2.0d));
        assertThrows(UnsupportedOperationException.class,
                () -> first.getSuppressedHardTriggers().add("C3:"));

        // Chaining mode/multiplier on the same family replaces prior override cleanly
        RiskPolicy cloned = first.toBuilder()
                .familyMultiplier("network_mitm", 1.2d)
                .allowlistFamily("virtual_container")
                .build();
        assertNotEquals(first, cloned);
        assertEquals(RiskPolicy.FamilyMode.DEFAULT, cloned.getFamilyMode("network_mitm"));
        assertEquals(1.2d, cloned.getFamilyMultiplier("network_mitm"), 1e-9);
        assertEquals(RiskPolicy.FamilyMode.ALLOWLIST, cloned.getFamilyMode("virtual_container"));
        assertEquals(1.0d, cloned.getFamilyMultiplier("virtual_container"), 1e-9);

        // Equality check for identical clone
        assertEquals(first, first.toBuilder().build());
        assertEquals(first.hashCode(), first.toBuilder().build().hashCode());
    }

    @Test
    public void builderFailsFastOnInvalidInputs() {
        assertThrows(IllegalArgumentException.class, () -> RiskPolicy.forScene(null));
        assertThrows(IllegalArgumentException.class, () -> RiskPolicy.builder(null));

        RiskPolicy.Builder b = RiskPolicy.builder(CollectScene.STANDARD);

        // Invalid dimension weights
        assertThrows(IllegalArgumentException.class, () -> b.dimensionWeight(null, 1.0d));
        assertThrows(IllegalArgumentException.class,
                () -> b.dimensionWeight(RiskDimension.TAMPERING, -0.01d));
        assertThrows(IllegalArgumentException.class,
                () -> b.dimensionWeight(RiskDimension.TAMPERING, Double.NaN));
        assertThrows(IllegalArgumentException.class,
                () -> b.dimensionWeight(RiskDimension.TAMPERING, Double.POSITIVE_INFINITY));
        assertThrows(IllegalArgumentException.class,
                () -> b.dimensionWeight(RiskDimension.TAMPERING, Double.NEGATIVE_INFINITY));

        // Invalid action thresholds (out of range or out of order)
        assertThrows(IllegalArgumentException.class, () -> b.actionThresholds(0, 60, 85));
        assertThrows(IllegalArgumentException.class, () -> b.actionThresholds(-1, 60, 85));
        assertThrows(IllegalArgumentException.class, () -> b.actionThresholds(30, 60, 101));
        assertThrows(IllegalArgumentException.class, () -> b.actionThresholds(30, 30, 85));
        assertThrows(IllegalArgumentException.class, () -> b.actionThresholds(65, 60, 85));
        assertThrows(IllegalArgumentException.class, () -> b.actionThresholds(30, 85, 85));
        assertThrows(IllegalArgumentException.class, () -> b.actionThresholds(30, 90, 85));

        // Invalid highAction
        assertThrows(IllegalArgumentException.class, () -> b.highAction(null));

        // Invalid family keys & modes & multipliers
        assertThrows(IllegalArgumentException.class, () -> b.allowlistFamily(null));
        assertThrows(IllegalArgumentException.class, () -> b.allowlistFamily(""));
        assertThrows(IllegalArgumentException.class, () -> b.allowlistFamily("   "));
        assertThrows(IllegalArgumentException.class, () -> b.informationalOnlyFamily(null));
        assertThrows(IllegalArgumentException.class, () -> b.informationalOnlyFamily("  "));
        assertThrows(IllegalArgumentException.class,
                () -> b.familyMode("adb", null));
        assertThrows(IllegalArgumentException.class,
                () -> b.familyMode("", RiskPolicy.FamilyMode.ALLOWLIST));
        assertThrows(IllegalArgumentException.class,
                () -> b.familyMultiplier(null, 1.0d));
        assertThrows(IllegalArgumentException.class,
                () -> b.familyMultiplier("   ", 1.0d));
        assertThrows(IllegalArgumentException.class,
                () -> b.familyMultiplier("emulator", -0.5d));
        assertThrows(IllegalArgumentException.class,
                () -> b.familyMultiplier("emulator", Double.NaN));
        assertThrows(IllegalArgumentException.class,
                () -> b.familyMultiplier("emulator", Double.POSITIVE_INFINITY));

        // Invalid hard trigger suppression codes
        assertThrows(IllegalArgumentException.class, () -> b.suppressHardTrigger(null));
        assertThrows(IllegalArgumentException.class, () -> b.suppressHardTrigger(""));
        assertThrows(IllegalArgumentException.class, () -> b.suppressHardTrigger("  "));
    }

    @Test
    public void gamingPolicyBoostsEnvironmentDimensionAndVirtualContainerMultiplier() {
        DetectionResult virtualContainer = new DetectionResult(
                "multi_instance", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true, List.of("nested_container_path:/data/user/999"),
                "nested_container_path:/data/user/999");

        DataAggregator aggregator = new DataAggregator();
        RiskReport defaultLogin = aggregator.aggregate(
                List.of(), List.of(virtualContainer), RiskPolicy.forScene(CollectScene.LOGIN));
        assertEquals(38, defaultLogin.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, defaultLogin.getOverallRiskLevel());
        assertEquals(RiskAction.CHALLENGE, defaultLogin.getRecommendedAction());

        // Boost ENVIRONMENT dimension weight to 2.0 -> 1 - (1 - 0.38)^2 = 62 -> HIGH/RESTRICT
        RiskPolicy boostedDim = RiskPolicy.builder(CollectScene.LOGIN)
                .dimensionWeight(RiskDimension.ENVIRONMENT, 2.0d)
                .build();
        RiskReport dimBoostedReport = aggregator.aggregate(
                List.of(), List.of(virtualContainer), boostedDim);
        assertEquals(38, dimBoostedReport.getDimensionScore(RiskDimension.ENVIRONMENT));
        assertEquals(62, dimBoostedReport.getRiskScore());
        assertEquals(RiskLevel.HIGH, dimBoostedReport.getOverallRiskLevel());
        assertEquals(RiskAction.RESTRICT, dimBoostedReport.getRecommendedAction());

        // Boost virtual_container family multiplier to 2.0 -> raises dimension & overall score
        RiskPolicy boostedFamily = RiskPolicy.builder(CollectScene.LOGIN)
                .familyMultiplier("virtual_container", 2.0d)
                .highAction(RiskAction.BLOCK)
                .build();
        RiskReport familyBoostedReport = aggregator.aggregate(
                List.of(), List.of(virtualContainer), boostedFamily);
        assertEquals(62, familyBoostedReport.getDimensionScore(RiskDimension.ENVIRONMENT));
        assertEquals(62, familyBoostedReport.getRiskScore());
        assertEquals(RiskLevel.HIGH, familyBoostedReport.getOverallRiskLevel());
        assertEquals(RiskAction.BLOCK, familyBoostedReport.getRecommendedAction());

        // Zeroing dimension weight suppresses contribution to overall score
        RiskPolicy zeroDim = RiskPolicy.builder(CollectScene.LOGIN)
                .dimensionWeight(RiskDimension.ENVIRONMENT, 0.0d)
                .build();
        RiskReport zeroedReport = aggregator.aggregate(
                List.of(), List.of(virtualContainer), zeroDim);
        assertEquals(0, zeroedReport.getRiskScore());
        assertEquals(RiskLevel.LOW, zeroedReport.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, zeroedReport.getRecommendedAction());
    }

    @Test
    public void corroborationLiftRemainsStrictlyMonotonicUnderHighFamilyMultiplier() {
        DataAggregator aggregator = new DataAggregator();
        RiskPolicy boostedRoot = RiskPolicy.builder(CollectScene.STANDARD)
                .familyMultiplier("root_fw", 2.0d)
                .build();

        DetectionResult singleLayerDeadlyRoot = new DetectionResult(
                "root", RiskLevel.DEADLY, DetectionStatus.DANGER,
                10, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su")
                .withEvidenceItems(List.of(new EvidenceItem(
                        "su_found", EvidenceItem.SourceLayer.NATIVE,
                        "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)));

        DetectionResult multiLayerDeadlyRoot = new DetectionResult(
                "root", RiskLevel.DEADLY, DetectionStatus.DANGER,
                10, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su")
                .withEvidenceItems(List.of(
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.JAVA,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG),
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.NATIVE,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)));

        RiskReport uncorroborated = aggregator.aggregate(
                List.of(), List.of(singleLayerDeadlyRoot), boostedRoot);
        RiskReport corroborated = aggregator.aggregate(
                List.of(), List.of(multiLayerDeadlyRoot), boostedRoot);

        assertEquals(99, uncorroborated.getRiskScore());
        assertTrue("Corroborated score (" + corroborated.getRiskScore()
                        + ") must never be lower than uncorroborated score ("
                        + uncorroborated.getRiskScore() + ")",
                corroborated.getRiskScore() >= uncorroborated.getRiskScore());
        assertEquals(100, corroborated.getRiskScore());
        assertTrue(corroborated.getRiskScore() <= 100);
    }

    @Test
    public void customActionThresholdsAndHighActionOverrideActionWithoutRewritingRiskLevelBands() {
        DetectionResult mediumFinding = new DetectionResult(
                "root", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su");

        RiskPolicy strict = RiskPolicy.builder(CollectScene.STANDARD)
                .actionThresholds(15, 35, 70)
                .highAction(RiskAction.BLOCK)
                .build();
        RiskReport strictReport = new DataAggregator().aggregate(
                List.of(), List.of(mediumFinding), strict);
        // Score 38 remains fixed RiskLevel.MEDIUM (30–59), while crossing custom restrictThreshold=35 -> highAction=BLOCK
        assertEquals(38, strictReport.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, strictReport.getOverallRiskLevel());
        assertEquals(RiskAction.BLOCK, strictReport.getRecommendedAction());
        assertEquals(70, strictReport.getNextRiskThreshold());
        assertEquals(strict, strictReport.getRiskPolicy());

        RiskPolicy lenient = RiskPolicy.builder(CollectScene.PAYMENT)
                .actionThresholds(45, 70, 90)
                .highAction(RiskAction.CHALLENGE)
                .build();
        RiskReport lenientReport = new DataAggregator().aggregate(
                List.of(), List.of(mediumFinding), lenient);
        // Score 38 remains fixed RiskLevel.MEDIUM (30–59), while staying below custom challengeThreshold=45 -> ALLOW
        assertEquals(38, lenientReport.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, lenientReport.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, lenientReport.getRecommendedAction());
        assertEquals(45, lenientReport.getNextRiskThreshold());

        // Fixed DEADLY (score >= 85) MUST still yield RiskAction.BLOCK even when custom blockThreshold=90
        DetectionResult highRoot = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su");
        DetectionResult medEmu = new DetectionResult(
                "emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                5, 10, false, List.of("virtual_gpu:swiftshader"), "virtual_gpu:swiftshader");
        // 1 - (1 - 0.72) * (1 - 0.46) = 1 - 0.28 * 0.54 = 0.8488 -> 85 (DEADLY, < custom blockThreshold 90)
        RiskReport deadlyUnderLenient = new DataAggregator().aggregate(
                List.of(), List.of(highRoot, medEmu), lenient);
        assertEquals(85, deadlyUnderLenient.getRiskScore());
        assertEquals(RiskLevel.DEADLY, deadlyUnderLenient.getOverallRiskLevel());
        assertEquals(RiskAction.BLOCK, deadlyUnderLenient.getRecommendedAction());

        // Pure informational finding stays 0 / LOW / ALLOW even under ultra-strict thresholds (1, 2, 3)
        RiskPolicy ultraStrict = RiskPolicy.builder(CollectScene.STANDARD)
                .actionThresholds(1, 2, 3)
                .highAction(RiskAction.BLOCK)
                .build();
        DetectionResult infoAdb = new DetectionResult(
                "adb", RiskLevel.LOW, DetectionStatus.WARNING,
                2, 10, true, List.of("settings_adb_enabled"), "settings_adb_enabled");
        RiskReport infoReport = new DataAggregator().aggregate(
                List.of(), List.of(infoAdb), ultraStrict);
        assertEquals(0, infoReport.getRiskScore());
        assertEquals(RiskLevel.LOW, infoReport.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, infoReport.getRecommendedAction());

        // UNKNOWN ALWAYS recommends REVIEW regardless of custom thresholds
        RiskReport unknownReport = new DataAggregator().aggregate(
                List.of(),
                List.of(DetectionResult.timeout("hook_framework", "deadline").withScanTier(ScanTier.CRITICAL)),
                ultraStrict);
        assertEquals(RiskLevel.UNKNOWN, unknownReport.getOverallRiskLevel());
        assertEquals(RiskAction.REVIEW, unknownReport.getRecommendedAction());
    }

    @Test
    public void suppressingHardTriggerRemovesFloorWhileKeepingNormalScoreAndOtherTriggers() {
        DetectionResult fridaPort = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                7, 10, false, List.of("frida_pid_port:27042"), "frida_pid_port:27042");

        DataAggregator aggregator = new DataAggregator();
        RiskReport unsuppressed = aggregator.aggregate(
                List.of(), List.of(fridaPort), RiskPolicy.forScene(CollectScene.STANDARD));
        assertEquals(95, unsuppressed.getRiskScore());
        assertEquals(RiskLevel.DEADLY, unsuppressed.getOverallRiskLevel());
        assertEquals(RiskAction.BLOCK, unsuppressed.getRecommendedAction());
        assertTrue(unsuppressed.getHardTriggers().contains("frida_pid_port:27042"));

        // Prefix suppression removes frida_pid_port:27042 hard trigger floor; score falls back to 64 (HIGH)
        RiskPolicy suppressed = RiskPolicy.builder(CollectScene.STANDARD)
                .suppressHardTrigger("frida_pid_port")
                .build();
        RiskReport suppressedReport = aggregator.aggregate(
                List.of(), List.of(fridaPort), suppressed);
        assertTrue(suppressedReport.getHardTriggers().isEmpty());
        assertEquals(64, suppressedReport.getRiskScore());
        assertEquals(RiskLevel.HIGH, suppressedReport.getOverallRiskLevel());
        assertEquals(RiskAction.RESTRICT, suppressedReport.getRecommendedAction());

        // Non-suppressed hard trigger on the same report must still trigger DEADLY + floor 95
        DetectionResult apkTamper = new DetectionResult(
                "app_integrity", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("apk_sig_mismatch"), "apk_sig_mismatch");
        RiskReport partialSuppressed = aggregator.aggregate(
                List.of(), List.of(fridaPort, apkTamper), suppressed);
        assertFalse(partialSuppressed.getHardTriggers().contains("frida_pid_port:27042"));
        assertTrue(partialSuppressed.getHardTriggers().contains("apk_sig_mismatch"));
        assertEquals(95, partialSuppressed.getRiskScore());
        assertEquals(RiskLevel.DEADLY, partialSuppressed.getOverallRiskLevel());
        assertEquals(RiskAction.BLOCK, partialSuppressed.getRecommendedAction());
    }

    @Test
    public void enterprisePolicyAllowlistsOrDowngradesNetworkMitmInPaymentScene() {
        DetectionResult networkMitm = new DetectionResult(
                "network_risk", RiskLevel.LOW, DetectionStatus.WARNING,
                2, 10, true,
                List.of("user_ca_cert:CorpRootCA", "http_proxy:10.0.0.1:8080"),
                "user_ca_cert:CorpRootCA; http_proxy:10.0.0.1:8080");

        DataAggregator aggregator = new DataAggregator();
        // Default PAYMENT promotes network_risk to actionable MEDIUM (38, CHALLENGE)
        RiskReport defaultPayment = aggregator.aggregate(
                List.of(), List.of(networkMitm), RiskPolicy.forScene(CollectScene.PAYMENT));
        assertEquals(38, defaultPayment.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, defaultPayment.getOverallRiskLevel());
        assertEquals(RiskAction.CHALLENGE, defaultPayment.getRecommendedAction());

        // ALLOWLIST: completely ignores network_mitm -> 0 score, SAFE, ALLOW, no warnings
        RiskPolicy allowlistPolicy = RiskPolicy.builder(CollectScene.PAYMENT)
                .allowlistFamily("network_mitm")
                .build();
        RiskReport allowlisted = aggregator.aggregate(
                List.of(), List.of(networkMitm), allowlistPolicy);
        assertEquals(0, allowlisted.getRiskScore());
        assertEquals(0, allowlisted.getDimensionScore(RiskDimension.FRAUD_CONTEXT));
        assertEquals(RiskLevel.SAFE, allowlisted.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, allowlisted.getRecommendedAction());
        assertEquals(0, allowlisted.getWarningCount());
        assertTrue(allowlisted.getScoreBreakdown().isEmpty());
        assertEquals(100, allowlisted.getConfidencePercent());

        // INFORMATIONAL_ONLY: keeps evidence visible as informational -> 0 score, LOW, ALLOW
        RiskPolicy infoPolicy = RiskPolicy.builder(CollectScene.PAYMENT)
                .informationalOnlyFamily("network_mitm")
                .build();
        RiskReport infoReport = aggregator.aggregate(
                List.of(), List.of(networkMitm), infoPolicy);
        assertEquals(0, infoReport.getRiskScore());
        assertEquals(0, infoReport.getDimensionScore(RiskDimension.FRAUD_CONTEXT));
        assertEquals(RiskLevel.LOW, infoReport.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, infoReport.getRecommendedAction());
        assertTrue(infoReport.getScoreBreakdown().isEmpty());
        DetectionResult netOut = infoReport.getDetections().stream()
                .filter(d -> "network_risk".equals(d.getDetectorName()))
                .findFirst().orElseThrow();
        assertTrue(netOut.isInformational());
        assertTrue(netOut.getDetails().contains("user_ca_cert:CorpRootCA"));
        assertTrue(netOut.getDetails().contains("http_proxy:10.0.0.1:8080"));
    }

    @Test
    public void allowlistPreventsCorrelationRulesAndHardTriggersFromAllowlistedEvidence() {
        DataAggregator aggregator = new DataAggregator();

        // 1) C3 + maps:frida hard trigger: allowlisting frida strips frida evidence so C3 and
        //    maps:frida do NOT fire, while non-allowlisted inline_hook:openat still triggers.
        DetectionResult hookMulti = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                com.wsttxm.riskenginesdk.model.DetectionExecutionStatus.RISK,
                2, 2, 0, List.of(),
                List.of("inline_hook:openat", "maps:frida"),
                List.of(
                        new EvidenceItem("inline_hook", EvidenceItem.SourceLayer.NATIVE,
                                "libc.so", "openat", "hook_integrity", EvidenceItem.Rank.STRONG),
                        new EvidenceItem("maps_frida", EvidenceItem.SourceLayer.JAVA,
                                "/proc/self/maps", "frida", "frida", EvidenceItem.Rank.STRONG)),
                "inline_hook:openat; maps:frida");
        RiskPolicy allowFrida = RiskPolicy.builder(CollectScene.STANDARD)
                .allowlistFamily("frida")
                .build();
        RiskReport hookReport = aggregator.aggregate(List.of(), List.of(hookMulti), allowFrida);
        assertFalse("C3 must not fire when frida is allowlisted",
                hookReport.getHardTriggers().stream().anyMatch(t -> t.startsWith("C3:")));
        assertFalse("maps:frida must not fire when frida is allowlisted",
                hookReport.getHardTriggers().contains("maps:frida"));
        assertTrue("non-allowlisted inline_hook:openat must still fire",
                hookReport.getHardTriggers().contains("inline_hook:openat"));

        // 2) C10 vishing combo in PAYMENT: allowlisting screen_control prevents C10 false positive
        DetectionResult callAndScreen = new DetectionResult(
                "screen_and_fraud", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                5, 10, false,
                List.of("ongoing_call:in_call", "virtual_display:scrcpy"),
                "ongoing_call:in_call; virtual_display:scrcpy");
        RiskPolicy allowScreen = RiskPolicy.builder(CollectScene.PAYMENT)
                .allowlistFamily("screen_control")
                .build();
        RiskReport screenReport = aggregator.aggregate(
                List.of(), List.of(callAndScreen), allowScreen);
        assertTrue("C10 must not fire when screen_control is allowlisted",
                screenReport.getDetections().stream()
                        .noneMatch(d -> "signal_correlation".equals(d.getDetectorName())
                                && d.getDetails().stream().anyMatch(s -> s.startsWith("C10:"))));

        // 3) C8 spoofed_verified_boot + vbmeta_empty_input_digest hard trigger: allowlisting
        //    boot_integrity neutralizes both C8 and the hard trigger completely -> SAFE, 0 score
        DetectionResult spoofedBoot = new DetectionResult(
                "consistency", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                List.of("vbmeta_empty_input_digest", "props_claim_green_locked"),
                "vbmeta_empty_input_digest; props_claim_green_locked");
        RiskPolicy allowBoot = RiskPolicy.builder(CollectScene.STANDARD)
                .allowlistFamily("boot_integrity")
                .build();
        RiskReport bootReport = aggregator.aggregate(List.of(), List.of(spoofedBoot), allowBoot);
        assertEquals(0, bootReport.getRiskScore());
        assertEquals(RiskLevel.SAFE, bootReport.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, bootReport.getRecommendedAction());
        assertTrue(bootReport.getHardTriggers().isEmpty());

        // 4) C4 hidden_root across root + mount_analysis: allowlisting root_fw prevents C4
        DetectionResult rootDet = new DetectionResult(
                "root", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("syscall_mismatch:/system/bin/su"),
                "syscall_mismatch:/system/bin/su");
        DetectionResult mountDet = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("module_mount"), "module_mount");
        RiskPolicy allowRoot = RiskPolicy.builder(CollectScene.STANDARD)
                .allowlistFamily("root_fw")
                .build();
        RiskReport rootReport = aggregator.aggregate(
                List.of(), List.of(rootDet, mountDet), allowRoot);
        assertEquals(0, rootReport.getRiskScore());
        assertEquals(RiskLevel.SAFE, rootReport.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, rootReport.getRecommendedAction());

        // 5) C1 emulator_weak_cluster: ALLOWLIST -> SAFE/0; INFORMATIONAL_ONLY -> LOW/0 without C1 inflation
        DetectionResult weakEmu = new DetectionResult(
                "emulator", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true,
                List.of("disk_small:4gb", "no_thermal", "emulator_ip:10.0.2.15"),
                "disk_small:4gb; no_thermal; emulator_ip:10.0.2.15");
        RiskReport emuAllow = aggregator.aggregate(
                List.of(), List.of(weakEmu),
                RiskPolicy.builder(CollectScene.STANDARD).allowlistFamily("emulator").build());
        assertEquals(0, emuAllow.getRiskScore());
        assertEquals(RiskLevel.SAFE, emuAllow.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, emuAllow.getRecommendedAction());

        RiskReport emuInfo = aggregator.aggregate(
                List.of(), List.of(weakEmu),
                RiskPolicy.builder(CollectScene.STANDARD).informationalOnlyFamily("emulator").build());
        assertEquals(0, emuInfo.getRiskScore());
        assertEquals(RiskLevel.LOW, emuInfo.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, emuInfo.getRecommendedAction());
        assertTrue(emuInfo.getDetections().stream()
                .anyMatch(d -> "emulator".equals(d.getDetectorName())
                        && d.getDetails().contains("no_thermal")));
    }

    @Test
    public void allowlistAndInformationalOnlyApplyToSyntheticHwSpoofInconsistency() {
        CollectorResult c1 = new CollectorResult("build_model", true);
        c1.addValue("java", "Pixel 8");
        c1.addValue("native", "SM-S918B");

        DataAggregator aggregator = new DataAggregator();
        RiskReport defaultReport = aggregator.aggregate(
                List.of(c1), List.of(), RiskPolicy.forScene(CollectScene.STANDARD));
        assertEquals(38, defaultReport.getRiskScore());

        RiskReport allowlisted = aggregator.aggregate(
                List.of(c1), List.of(),
                RiskPolicy.builder(CollectScene.STANDARD).allowlistFamily("hw_spoof").build());
        assertEquals(0, allowlisted.getRiskScore());
        assertEquals(RiskLevel.SAFE, allowlisted.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, allowlisted.getRecommendedAction());

        RiskReport infoOnly = aggregator.aggregate(
                List.of(c1), List.of(),
                RiskPolicy.builder(CollectScene.STANDARD).informationalOnlyFamily("hw_spoof").build());
        assertEquals(0, infoOnly.getRiskScore());
        assertEquals(RiskLevel.LOW, infoOnly.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, infoOnly.getRecommendedAction());
    }

    @Test
    public void configDerivesDefaultPolicyFromSceneAndAcceptsCustomPolicy() {
        RiskEngineConfig defaultCfg = new RiskEngineConfig.Builder().build();
        assertFalse(defaultCfg.hasCustomRiskPolicy());
        assertEquals(RiskPolicy.forScene(CollectScene.STANDARD), defaultCfg.getRiskPolicy());

        RiskEngineConfig paymentCfg = new RiskEngineConfig.Builder()
                .collectScene(CollectScene.PAYMENT)
                .build();
        assertFalse(paymentCfg.hasCustomRiskPolicy());
        assertEquals(RiskPolicy.forScene(CollectScene.PAYMENT), paymentCfg.getRiskPolicy());

        RiskPolicy custom = RiskPolicy.builder(CollectScene.PAYMENT)
                .allowlistFamily("network_mitm")
                .build();
        RiskEngineConfig customCfg = new RiskEngineConfig.Builder()
                .riskPolicy(custom)
                .build();
        assertTrue(customCfg.hasCustomRiskPolicy());
        assertEquals(CollectScene.PAYMENT, customCfg.getCollectScene());
        assertEquals(custom, customCfg.getRiskPolicy());

        // Regardless of builder call order, config.getCollectScene() must stay consistent with
        // the active RiskPolicy.getBaseScene() and resulting RiskReport.getCollectScene().
        RiskEngineConfig sceneThenPolicy = new RiskEngineConfig.Builder()
                .collectScene(CollectScene.LOGIN)
                .riskPolicy(custom)
                .build();
        assertEquals(CollectScene.PAYMENT, sceneThenPolicy.getCollectScene());
        assertEquals(CollectScene.PAYMENT, sceneThenPolicy.getRiskPolicy().getBaseScene());
        assertEquals(custom, sceneThenPolicy.getRiskPolicy());
        RiskReport r1 = new DataAggregator(null, sceneThenPolicy).aggregate(List.of(), List.of());
        assertEquals(sceneThenPolicy.getCollectScene(), r1.getCollectScene());

        RiskEngineConfig policyThenScene = new RiskEngineConfig.Builder()
                .riskPolicy(custom)
                .collectScene(CollectScene.LOGIN)
                .build();
        assertEquals(CollectScene.PAYMENT, policyThenScene.getCollectScene());
        assertEquals(CollectScene.PAYMENT, policyThenScene.getRiskPolicy().getBaseScene());
        assertEquals(custom, policyThenScene.getRiskPolicy());
        RiskReport r2 = new DataAggregator(null, policyThenScene).aggregate(List.of(), List.of());
        assertEquals(policyThenScene.getCollectScene(), r2.getCollectScene());

        assertThrows(IllegalArgumentException.class,
                () -> new RiskEngineConfig.Builder().riskPolicy(null));
    }

    @Test
    public void riskEnginePassesCustomPolicyThroughCollectSyncAndTieredMonitoring()
            throws Exception {
        RiskEngine engine = RiskEngine.getInstance();
        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override public boolean ensureNativeLoaded() { return false; }
            @Override public void setAntiDumpable(boolean enable) {}
            @Override public void startMonitor() {}
            @Override public void stopMonitor() {}
        });

        Context ctx = new ContextWrapper(null) {
            @Override public Context getApplicationContext() { return this; }
        };

        // 1) Without custom riskPolicy, sceneOverride dynamically derives default policy
        RiskEngine.init(ctx, new RiskEngineConfig.Builder()
                .collectScene(CollectScene.STANDARD)
                .enablePeriodicMonitor(false)
                .build());
        BaseDetector networkDetector = new BaseDetector(null) {
            @Override public String getName() { return "network_risk"; }
            @Override public ScanTier getScanTier() { return ScanTier.FAST; }
            @Override
            public DetectionResult detect() {
                return new DetectionResult(
                        "network_risk", RiskLevel.LOW, DetectionStatus.WARNING,
                        2, 10, true, List.of("user_ca_cert:CorpCA"), "user_ca_cert:CorpCA");
            }
        };
        RiskReport stdReport = engine.doCollectSync(
                System.nanoTime(), -1, null, List.of(networkDetector), List.of());
        assertEquals(0, stdReport.getRiskScore());
        assertEquals(RiskLevel.LOW, stdReport.getOverallRiskLevel());

        RiskReport payOverrideReport = engine.doCollectSync(
                System.nanoTime(), -1, CollectScene.PAYMENT, List.of(networkDetector), List.of());
        assertEquals(38, payOverrideReport.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, payOverrideReport.getOverallRiskLevel());
        assertEquals(RiskAction.CHALLENGE, payOverrideReport.getRecommendedAction());

        // 2) With custom RiskPolicy allowlisting network_mitm in PAYMENT, both collectSync and
        //    tiered monitoring (TierReport + ThreatListener + final RiskReport) honor the policy
        RiskEngine.shutdown();
        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override public boolean ensureNativeLoaded() { return false; }
            @Override public void setAntiDumpable(boolean enable) {}
            @Override public void startMonitor() {}
            @Override public void stopMonitor() {}
        });
        RiskPolicy enterprisePayment = RiskPolicy.builder(CollectScene.PAYMENT)
                .allowlistFamily("network_mitm")
                .build();
        RiskEngine.init(ctx, new RiskEngineConfig.Builder()
                .riskPolicy(enterprisePayment)
                .enablePeriodicMonitor(false)
                .build());

        RiskReport syncEnterprise = engine.doCollectSync(
                System.nanoTime(), -1, null, List.of(networkDetector), List.of());
        assertEquals(0, syncEnterprise.getRiskScore());
        assertEquals(RiskLevel.SAFE, syncEnterprise.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, syncEnterprise.getRecommendedAction());
        assertEquals(enterprisePayment, syncEnterprise.getRiskPolicy());

        // Verify Tiered monitoring passes policy to TierReport, ThreatListener, and final RiskReport
        List<ThreatEvent> threats = new CopyOnWriteArrayList<>();
        AtomicReference<TierReport> fastTierRef = new AtomicReference<>();
        AtomicReference<RiskReport> finalReportRef = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);

        engine.doStartMonitoring(
                new ThreatListener() {
                    @Override public void onThreatDetected(ThreatEvent event) { threats.add(event); }
                },
                null,
                new ExecutionStateListener() {
                    @Override public void onFastChecksFinished(TierReport report) { fastTierRef.set(report); }
                    @Override
                    public void onPostponedChecksFinished(RiskReport report) {
                        finalReportRef.set(report);
                        done.countDown();
                    }
                },
                List.of(networkDetector),
                List.of());

        assertTrue("Tiered monitoring did not complete", done.await(5, TimeUnit.SECONDS));
        assertTrue("Allowlisted network_mitm must not fire ThreatListener", threats.isEmpty());
        assertNotNull(fastTierRef.get());
        assertEquals(0, fastTierRef.get().getRiskScore());
        assertEquals(RiskLevel.SAFE, fastTierRef.get().getHighestRiskLevel());
        assertNotNull(finalReportRef.get());
        assertEquals(0, finalReportRef.get().getRiskScore());
        assertEquals(RiskLevel.SAFE, finalReportRef.get().getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, finalReportRef.get().getRecommendedAction());
    }
}
