package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.SignedEnvelopeSigner;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.ReportStatus;
import com.wsttxm.riskenginesdk.model.RiskAction;
import com.wsttxm.riskenginesdk.model.RiskDimension;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.ScoreBreakdown;
import com.wsttxm.riskenginesdk.model.TierReport;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class NormalizedScoringEngineTest {

    @Test
    public void all21EvidenceFamiliesMapDeterministicallyToFourOrthogonalDimensions() {
        String[] tampering = {"app_tamper", "hook_integrity", "frida", "xposed", "debugger", "tee_tamper"};
        String[] privilege = {"root_fw", "boot_integrity", "prop_tamper", "hw_spoof",
                "hma_hiding", "device_binding", "custom_rom", "adb"};
        String[] environment = {"emulator", "virtual_container", "threat_app"};
        String[] fraudContext = {"network_mitm", "location_spoof", "screen_control", "fraud_context"};

        for (String f : tampering) {
            assertEquals(f, RiskDimension.TAMPERING, EvidenceFamily.dimensionOf(f));
        }
        for (String f : privilege) {
            assertEquals(f, RiskDimension.PRIVILEGE, EvidenceFamily.dimensionOf(f));
        }
        for (String f : environment) {
            assertEquals(f, RiskDimension.ENVIRONMENT, EvidenceFamily.dimensionOf(f));
        }
        for (String f : fraudContext) {
            assertEquals(f, RiskDimension.FRAUD_CONTEXT, EvidenceFamily.dimensionOf(f));
        }

        // Verify token inference for the 4 previously unmapped families
        assertEquals("prop_tamper", EvidenceFamily.familyOf("prop_area_hole:ro.debuggable"));
        assertEquals("prop_tamper", EvidenceFamily.familyOf("prop_ro_serial_modified"));
        assertEquals("prop_tamper", EvidenceFamily.familyOf("prop_mismatch:fingerprint"));
        assertEquals("hw_spoof", EvidenceFamily.familyOf("inconsistent_fields:gpu,cpu"));
        assertEquals("hw_spoof", EvidenceFamily.familyOf("widevine_id_mismatch"));
        assertEquals("custom_rom", EvidenceFamily.familyOf("community_rom:LineageOS"));
        assertEquals("custom_rom", EvidenceFamily.familyOf("test_keys"));
        assertEquals("adb", EvidenceFamily.familyOf("settings_adb_enabled"));
        assertEquals("adb", EvidenceFamily.familyOf("tcp_listen:5555"));
    }

    @Test
    public void familyMaxAggregationIsStrictlyIndependentOfDetectorRegistrationOrder() {
        DetectionResult weakMount = new DetectionResult(
                "mount_analysis", RiskLevel.LOW, DetectionStatus.WARNING,
                2, 10, false,
                List.of("system_tmpfs_mount:/system/etc/security/cacerts"),
                "system_tmpfs_mount:/system/etc/security/cacerts")
                .withEvidenceItems(List.of(new EvidenceItem(
                        "system_tmpfs_mount", EvidenceItem.SourceLayer.ISOLATED,
                        "/system/etc/security/cacerts", "tmpfs", "root_fw", EvidenceItem.Rank.WEAK)));
        DetectionResult strongRoot = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                List.of("su_found:/system/bin/su"),
                "su_found:/system/bin/su")
                .withEvidenceItems(List.of(new EvidenceItem(
                        "su_found", EvidenceItem.SourceLayer.NATIVE,
                        "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)));

        DataAggregator aggregator = new DataAggregator();
        RiskReport weakFirst = aggregator.aggregate(
                Collections.emptyList(), Arrays.asList(weakMount, strongRoot), CollectScene.STANDARD);
        RiskReport strongFirst = aggregator.aggregate(
                Collections.emptyList(), Arrays.asList(strongRoot, weakMount), CollectScene.STANDARD);

        assertEquals(strongFirst.getRiskScore(), weakFirst.getRiskScore());
        assertEquals(78, weakFirst.getRiskScore()); // base 72 + 6 corroboration lift
        assertEquals(RiskLevel.HIGH, weakFirst.getOverallRiskLevel());
        assertEquals(strongFirst.getDimensionScores(), weakFirst.getDimensionScores());
        assertEquals(strongFirst.getScoreBreakdown().getEntries(),
                weakFirst.getScoreBreakdown().getEntries());

        DetectionResult weakOut = find(weakFirst, "mount_analysis");
        DetectionResult strongOut = find(weakFirst, "root");
        assertFalse("Strong finding must never be suppressed by earlier weak hit",
                strongOut.isInformational());
        assertTrue("Weaker duplicate should remain visible as corroborating evidence",
                weakOut.isInformational());
        assertTrue(weakOut.getDetails().contains("deduped:corroborating_evidence"));
    }

    @Test
    public void corroborationLiftAppliesForMultiLayerOrMultiDomainAndCapsAt95() {
        DataAggregator aggregator = new DataAggregator();

        // Single-layer, single-domain -> no lift (score 8 -> 72)
        DetectionResult singleLayerRoot = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su")
                .withEvidenceItems(List.of(new EvidenceItem(
                        "su_found", EvidenceItem.SourceLayer.NATIVE,
                        "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)));
        RiskReport singleReport = aggregator.aggregate(
                Collections.emptyList(), List.of(singleLayerRoot), CollectScene.STANDARD);
        assertEquals(72, singleReport.getRiskScore());
        assertFalse(hasBreakdownCategory(singleReport, ScoreBreakdown.Category.CORROBORATION_LIFT));

        // Multi-layer (JAVA + NATIVE) within same detector -> +6 lift (72 + 6 = 78)
        DetectionResult multiLayerRoot = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su")
                .withEvidenceItems(Arrays.asList(
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.JAVA,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.MEDIUM),
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.NATIVE,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)));
        RiskReport multiLayerReport = aggregator.aggregate(
                Collections.emptyList(), List.of(multiLayerRoot), CollectScene.STANDARD);
        assertEquals(78, multiLayerReport.getRiskScore());
        assertTrue(hasBreakdownCategory(multiLayerReport, ScoreBreakdown.Category.CORROBORATION_LIFT));

        // Multi-domain (emulator + cloud_phone) in LOGIN -> +6 lift (38 + 6 = 44), not double-scored
        DetectionResult emu = new DetectionResult(
                "emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true, List.of("virtual_gpu:swiftshader"), "virtual_gpu:swiftshader");
        DetectionResult cloud = new DetectionResult(
                "cloud_phone", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true, List.of("virtual_gpu:swiftshader"), "virtual_gpu:swiftshader");
        RiskReport multiDomainReport = aggregator.aggregate(
                Collections.emptyList(), Arrays.asList(emu, cloud), CollectScene.LOGIN);
        assertEquals(44, multiDomainReport.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, multiDomainReport.getOverallRiskLevel());
        assertTrue(hasBreakdownCategory(multiDomainReport, ScoreBreakdown.Category.CORROBORATION_LIFT));

        // Score 10 (base 0.92) + corroboration lift (+0.06) MUST cap at 0.95 -> 95 (not 98)
        DetectionResult deadlyMultiLayer = new DetectionResult(
                "root", RiskLevel.DEADLY, DetectionStatus.DANGER,
                10, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su")
                .withEvidenceItems(Arrays.asList(
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.JAVA,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG),
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.NATIVE,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)));
        RiskReport cappedReport = aggregator.aggregate(
                Collections.emptyList(), List.of(deadlyMultiLayer), CollectScene.STANDARD);
        assertEquals(95, cappedReport.getRiskScore());
        assertEquals(95, cappedReport.getDimensionScore(RiskDimension.PRIVILEGE));
    }

    @Test
    public void pureLowWeakSignalsInDimensionAreHardCappedAt35() {
        List<DetectionResult> sixWeakPrivilegeHits = Arrays.asList(
                lowHit("root", "su_found:/x", "root_fw", 3),
                lowHit("consistency", "bootloader_unlocked", "boot_integrity", 3),
                lowHit("prop_probe", "prop_mismatch:build", "prop_tamper", 3),
                lowHit("hw_probe", "widevine_mismatch", "hw_spoof", 3),
                lowHit("custom_rom", "community_rom:LineageOS", "custom_rom", 3),
                lowHit("adb", "settings_adb_enabled", "adb", 3)
        );
        RiskReport pureLow = new DataAggregator().aggregate(
                Collections.emptyList(), sixWeakPrivilegeHits, CollectScene.DIAGNOSTIC);

        // Uncapped Noisy-OR of 6 x 0.26 would be 1 - 0.74^6 = 84; pure-LOW cap keeps it <= 35!
        assertEquals(35, pureLow.getDimensionScore(RiskDimension.PRIVILEGE));
        assertEquals(35, pureLow.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, pureLow.getOverallRiskLevel());
        assertEquals(RiskAction.CHALLENGE, pureLow.getRecommendedAction());

        // Adding a single MEDIUM hit in the same dimension lifts the pure-LOW cap
        List<DetectionResult> withMedium = new ArrayList<>(sixWeakPrivilegeHits);
        withMedium.add(new DetectionResult(
                "threat_apps", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                5, 10, false, List.of("hma_uid_visibility_hidden"), "hma_uid_visibility_hidden"));
        RiskReport uncapped = new DataAggregator().aggregate(
                Collections.emptyList(), withMedium, CollectScene.DIAGNOSTIC);
        assertTrue("Medium finding should lift pure-LOW dimension cap above 35",
                uncapped.getDimensionScore(RiskDimension.PRIVILEGE) > 35);
    }

    @Test
    public void orthogonalDimensionsCombineViaNoisyOrWithoutExceeding100() {
        DetectionResult tampering = new DetectionResult(
                "debug", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("tracer_pid:1234"), "tracer_pid:1234");
        DetectionResult privilege = new DetectionResult(
                "root", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su");
        DetectionResult environment = new DetectionResult(
                "multi_instance", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("nested_container_path:/data/user/999"), "nested_container_path:/data/user/999");
        DetectionResult fraud = new DetectionResult(
                "network_risk", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("http_proxy:127.0.0.1:8888"), "http_proxy:127.0.0.1:8888");

        RiskReport report = new DataAggregator().aggregate(
                Collections.emptyList(),
                Arrays.asList(tampering, privilege, environment, fraud),
                CollectScene.STANDARD);

        Map<RiskDimension, Integer> dims = report.getDimensionScores();
        assertEquals(4, dims.size());
        assertEquals(Integer.valueOf(38), dims.get(RiskDimension.TAMPERING));
        assertEquals(Integer.valueOf(38), dims.get(RiskDimension.PRIVILEGE));
        assertEquals(Integer.valueOf(38), dims.get(RiskDimension.ENVIRONMENT));
        assertEquals(Integer.valueOf(38), dims.get(RiskDimension.FRAUD_CONTEXT));

        // 1 - (1 - 0.38)^4 = 1 - 0.62^4 = 0.8522 -> 85 (DEADLY, bounded <= 100)
        assertEquals(85, report.getRiskScore());
        assertEquals(RiskLevel.DEADLY, report.getOverallRiskLevel());
        assertEquals(100, report.getMaxRiskScore());
        assertEquals(100, report.getDisplayThresholdMaximum());
    }

    @Test
    public void correlationRulesC1ThroughC10FeedNormalizedScoringAndBreakdown() {
        DataAggregator aggregator = new DataAggregator();

        // C1: emulator weak cluster -> MEDIUM (38)
        DetectionResult c1Emu = new DetectionResult(
                "emulator", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true,
                List.of("disk_small:4gb", "no_thermal", "emulator_ip:10.0.2.15"),
                "disk_small:4gb; no_thermal; emulator_ip:10.0.2.15");
        RiskReport r1 = aggregator.aggregate(Collections.emptyList(), List.of(c1Emu), CollectScene.STANDARD);
        assertEquals(38, r1.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, r1.getOverallRiskLevel());
        assertTrue(hasBreakdownKeyPrefix(r1, ScoreBreakdown.Category.CORRELATION_RULE, "C1:"));

        // C2: emulator strong + hypervisor -> elevates MEDIUM (38) to HIGH (66)
        DetectionResult c2Emu = new DetectionResult(
                "emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("cpu:hypervisor"), "cpu:hypervisor");
        RiskReport r2 = aggregator.aggregate(Collections.emptyList(), List.of(c2Emu), CollectScene.STANDARD);
        assertTrue("C2 should elevate MEDIUM emulator to HIGH (>= 60), got " + r2.getRiskScore(),
                r2.getRiskScore() >= 60);
        assertEquals(RiskLevel.HIGH, r2.getOverallRiskLevel());
        assertTrue(hasBreakdownKeyPrefix(r2, ScoreBreakdown.Category.CORRELATION_RULE, "C2:"));

        // C3: inline_hook + frida -> DEADLY hard trigger (95–100)
        DetectionResult c3Hook = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("inline_hook:openat", "maps:frida"), "inline_hook:openat; maps:frida");
        RiskReport r3 = aggregator.aggregate(Collections.emptyList(), List.of(c3Hook), CollectScene.STANDARD);
        assertEquals(RiskLevel.DEADLY, r3.getOverallRiskLevel());
        assertTrue(r3.getRiskScore() >= 95 && r3.getRiskScore() <= 100);
        assertTrue(r3.getHardTriggers().stream().anyMatch(t -> t.startsWith("C3:")));

        // C4: hidden root -> HIGH (>= 60)
        DetectionResult c4Root = new DetectionResult(
                "root", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("syscall_mismatch:/system/bin/su"), "syscall_mismatch");
        DetectionResult c4Mount = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("module_mount"), "module_mount");
        RiskReport r4 = aggregator.aggregate(
                Collections.emptyList(), Arrays.asList(c4Root, c4Mount), CollectScene.STANDARD);
        assertEquals(RiskLevel.HIGH, r4.getOverallRiskLevel());
        assertTrue(r4.getRiskScore() >= 60);
        assertTrue(hasBreakdownKeyPrefix(r4, ScoreBreakdown.Category.CORRELATION_RULE, "C4:"));

        // C5: resetprop fingerprint stays informational -> score 0, LOW, ALLOW
        DetectionResult c5Rom = new DetectionResult(
                "custom_rom", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true, List.of("prop_mismatch:fingerprint"), "prop_mismatch:fingerprint");
        RiskReport r5 = aggregator.aggregate(Collections.emptyList(), List.of(c5Rom), CollectScene.STANDARD);
        assertEquals(0, r5.getRiskScore());
        assertEquals(RiskLevel.LOW, r5.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, r5.getRecommendedAction());

        // C6: native self-integrity tamper while Java clean -> DEADLY hard trigger (95–100)
        DetectionResult c6Hook = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("native:text_mismatch"), "native:text_mismatch");
        RiskReport r6 = aggregator.aggregate(Collections.emptyList(), List.of(c6Hook), CollectScene.STANDARD);
        assertEquals(RiskLevel.DEADLY, r6.getOverallRiskLevel());
        assertTrue(r6.getRiskScore() >= 95);
        assertTrue(r6.getHardTriggers().stream().anyMatch(t -> t.startsWith("C6:")));

        // C7: cloud weak cluster in LOGIN -> actionable LOW
        DetectionResult c7Cloud = new DetectionResult(
                "cloud_phone", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true, List.of("battery_zero:v=0,t=0", "very_low_sensor_count:1"), "battery");
        RiskReport r7 = aggregator.aggregate(Collections.emptyList(), List.of(c7Cloud), CollectScene.LOGIN);
        assertTrue(r7.getRiskScore() >= 1 && r7.getRiskScore() <= 29);
        assertEquals(RiskLevel.LOW, r7.getOverallRiskLevel());
        assertTrue(hasBreakdownKeyPrefix(r7, ScoreBreakdown.Category.CORRELATION_RULE, "C7:"));

        // C8: spoofed verified boot -> DEADLY hard trigger (95–100)
        DetectionResult c8Consistency = new DetectionResult(
                "consistency", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                List.of("key_attestation:bootloader_unlocked", "verified_boot_state:green"),
                "spoofed");
        RiskReport r8 = aggregator.aggregate(Collections.emptyList(), List.of(c8Consistency), CollectScene.STANDARD);
        assertEquals(RiskLevel.DEADLY, r8.getOverallRiskLevel());
        assertTrue(r8.getRiskScore() >= 95);
        assertTrue(r8.getHardTriggers().stream().anyMatch(t -> t.startsWith("C8:")));

        // C9: stealth root with unmount -> HIGH (>= 60)
        DetectionResult c9CleanRoot = safeDetector("root", ScanTier.FAST);
        DetectionResult c9Mount = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("isolated_mount_diff:/system/bin"), "isolated_mount_diff");
        RiskReport r9 = aggregator.aggregate(
                Collections.emptyList(), Arrays.asList(c9CleanRoot, c9Mount), CollectScene.STANDARD);
        assertTrue(r9.getRiskScore() >= 60);
        assertTrue(hasBreakdownKeyPrefix(r9, ScoreBreakdown.Category.CORRELATION_RULE, "C9:"));

        // C10: vishing fraud combo in PAYMENT -> BLOCK
        DetectionResult c10Fraud = new DetectionResult(
                "screen_and_fraud", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                5, 10, false,
                List.of("ongoing_call:in_call", "virtual_display:scrcpy"),
                "ongoing_call:in_call; virtual_display:scrcpy");
        RiskReport r10 = aggregator.aggregate(Collections.emptyList(), List.of(c10Fraud), CollectScene.PAYMENT);
        assertEquals(RiskAction.BLOCK, r10.getRecommendedAction());
        assertTrue(hasBreakdownKeyPrefix(r10, ScoreBreakdown.Category.CORRELATION_RULE, "C10:"));
    }

    @Test
    public void hardTriggersAreAuthoritativeUnifiedAndFloorScoreBetween95And100() {
        DetectionResult singleHardTrigger = new DetectionResult(
                "app_integrity", RiskLevel.HIGH, DetectionStatus.DANGER,
                7, 10, false, List.of("apk_sig_mismatch"), "apk_sig_mismatch");
        RiskReport singleReport = new DataAggregator().aggregate(
                Collections.emptyList(), List.of(singleHardTrigger), CollectScene.STANDARD);

        assertEquals(List.of("apk_sig_mismatch"), singleReport.getHardTriggers());
        assertEquals(singleReport.getHardTriggers(),
                SignedEnvelopeSigner.extractHardTriggers(singleReport));
        assertEquals(RiskLevel.DEADLY, singleReport.getOverallRiskLevel());
        assertEquals(RiskAction.BLOCK, singleReport.getRecommendedAction());
        assertEquals(95, singleReport.getRiskScore());
        assertTrue(hasBreakdownCategory(singleReport, ScoreBreakdown.Category.HARD_TRIGGER_FLOOR));

        // Multiple distinct hard triggers scale floor smoothly up to 100
        DetectionResult multiHard = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                Arrays.asList("inline_hook:openat", "got_hook:stat", "maps:frida", "fd:linjector"),
                "multi hard triggers");
        RiskReport multiReport = new DataAggregator().aggregate(
                Collections.emptyList(), Arrays.asList(singleHardTrigger, multiHard), CollectScene.STANDARD);
        assertTrue(multiReport.getHardTriggers().size() >= 4);
        assertEquals(multiReport.getHardTriggers(),
                SignedEnvelopeSigner.extractHardTriggers(multiReport));
        assertEquals(100, multiReport.getRiskScore());
        assertEquals(RiskLevel.DEADLY, multiReport.getOverallRiskLevel());

        // Informational hard-trigger token must NOT fire Hard Trigger
        DetectionResult infoHard = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, true, List.of("maps:frida"), "maps:frida");
        RiskReport infoReport = new RiskReport(new DeviceFingerprint(), List.of(infoHard));
        assertTrue(infoReport.getHardTriggers().isEmpty());
        assertEquals(0, infoReport.getRiskScore());
        assertEquals(RiskLevel.LOW, infoReport.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, infoReport.getRecommendedAction());
    }

    @Test
    public void defaultRiskActionFollowsScenePolicyAcrossAllLevels() {
        DataAggregator aggregator = new DataAggregator();

        // SAFE -> ALLOW
        RiskReport safe = aggregator.aggregate(
                Collections.emptyList(), List.of(safeDetector("root", ScanTier.FAST)), CollectScene.PAYMENT);
        assertEquals(0, safe.getRiskScore());
        assertEquals(RiskLevel.SAFE, safe.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, safe.getRecommendedAction());

        // Pure informational -> 0, LOW, ALLOW
        DetectionResult infoAdb = new DetectionResult(
                "adb", RiskLevel.LOW, DetectionStatus.WARNING,
                2, 10, true, List.of("settings_adb_enabled"), "settings_adb_enabled");
        RiskReport info = aggregator.aggregate(
                Collections.emptyList(), List.of(infoAdb), CollectScene.STANDARD);
        assertEquals(0, info.getRiskScore());
        assertEquals(RiskLevel.LOW, info.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, info.getRecommendedAction());

        // MEDIUM -> CHALLENGE
        DetectionResult med = new DetectionResult(
                "root", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("su_found:/x"), "su_found:/x");
        RiskReport medium = aggregator.aggregate(
                Collections.emptyList(), List.of(med), CollectScene.STANDARD);
        assertEquals(RiskLevel.MEDIUM, medium.getOverallRiskLevel());
        assertEquals(RiskAction.CHALLENGE, medium.getRecommendedAction());

        // HIGH -> RESTRICT in STANDARD/LOGIN/DIAGNOSTIC, BLOCK in PAYMENT
        DetectionResult highDet = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su");
        assertEquals(RiskAction.RESTRICT, aggregator.aggregate(
                Collections.emptyList(), List.of(highDet), CollectScene.STANDARD).getRecommendedAction());
        assertEquals(RiskAction.RESTRICT, aggregator.aggregate(
                Collections.emptyList(), List.of(highDet), CollectScene.LOGIN).getRecommendedAction());
        assertEquals(RiskAction.RESTRICT, aggregator.aggregate(
                Collections.emptyList(), List.of(highDet), CollectScene.DIAGNOSTIC).getRecommendedAction());
        assertEquals(RiskAction.BLOCK, aggregator.aggregate(
                Collections.emptyList(), List.of(highDet), CollectScene.PAYMENT).getRecommendedAction());

        // DEADLY -> BLOCK
        DetectionResult deadlyDet = new DetectionResult(
                "root", RiskLevel.DEADLY, DetectionStatus.DANGER,
                10, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su");
        assertEquals(RiskAction.BLOCK, aggregator.aggregate(
                Collections.emptyList(), List.of(deadlyDet), CollectScene.STANDARD).getRecommendedAction());

        // UNKNOWN -> REVIEW
        RiskReport unknown = aggregator.aggregate(
                Collections.emptyList(),
                List.of(DetectionResult.timeout("hook_framework", "deadline").withScanTier(ScanTier.CRITICAL)),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.UNKNOWN, unknown.getOverallRiskLevel());
        assertEquals(RiskAction.REVIEW, unknown.getRecommendedAction());
    }

    @Test
    public void tieredAssessmentConfidenceDecouplesSingleNonCriticalTimeoutFromUnknown() {
        DataAggregator aggregator = new DataAggregator();

        // Full 16-domain clean scan: 3 CRITICAL (9) + 11 FAST (22) + 2 POSTPONED (2) = 33 weight
        List<DetectionResult> fullClean = buildFull16CleanDetections();
        RiskReport cleanReport = aggregator.aggregate(
                Collections.emptyList(), fullClean, CollectScene.STANDARD);
        assertEquals(100, cleanReport.getConfidencePercent());
        assertEquals(RiskLevel.SAFE, cleanReport.getOverallRiskLevel());
        assertEquals(ReportStatus.COMPLETE, cleanReport.getReportStatus());
        assertEquals(RiskAction.ALLOW, cleanReport.getRecommendedAction());

        // Single POSTPONED timeout (weight 1/33 -> 97%): stays SAFE + PARTIAL + ALLOW
        List<DetectionResult> onePostponedTimeout = replaceDetector(
                fullClean, "tee_integrity",
                DetectionResult.timeout("tee_integrity", "deadline").withScanTier(ScanTier.POSTPONED));
        RiskReport postponedTimeoutReport = aggregator.aggregate(
                Collections.emptyList(), onePostponedTimeout, CollectScene.STANDARD);
        assertEquals(97, postponedTimeoutReport.getConfidencePercent());
        assertEquals(RiskLevel.SAFE, postponedTimeoutReport.getOverallRiskLevel());
        assertEquals(ReportStatus.PARTIAL, postponedTimeoutReport.getReportStatus());
        assertEquals(RiskAction.ALLOW, postponedTimeoutReport.getRecommendedAction());

        // Single FAST timeout (weight 2/33 -> 94%): stays SAFE + PARTIAL + ALLOW
        List<DetectionResult> oneFastTimeout = replaceDetector(
                fullClean, "emulator",
                DetectionResult.timeout("emulator", "deadline").withScanTier(ScanTier.FAST));
        RiskReport fastTimeoutReport = aggregator.aggregate(
                Collections.emptyList(), oneFastTimeout, CollectScene.STANDARD);
        assertEquals(94, fastTimeoutReport.getConfidencePercent());
        assertEquals(RiskLevel.SAFE, fastTimeoutReport.getOverallRiskLevel());
        assertEquals(ReportStatus.PARTIAL, fastTimeoutReport.getReportStatus());
        assertEquals(RiskAction.ALLOW, fastTimeoutReport.getRecommendedAction());

        // Single CRITICAL timeout (weight 3/33 -> 91%): MUST become UNKNOWN + REVIEW!
        List<DetectionResult> oneCriticalTimeout = replaceDetector(
                fullClean, "hook_framework",
                DetectionResult.timeout("hook_framework", "deadline").withScanTier(ScanTier.CRITICAL));
        RiskReport criticalTimeoutReport = aggregator.aggregate(
                Collections.emptyList(), oneCriticalTimeout, CollectScene.STANDARD);
        assertEquals(91, criticalTimeoutReport.getConfidencePercent());
        assertEquals(RiskLevel.UNKNOWN, criticalTimeoutReport.getOverallRiskLevel());
        assertEquals(ReportStatus.PARTIAL, criticalTimeoutReport.getReportStatus());
        assertEquals(RiskAction.REVIEW, criticalTimeoutReport.getRecommendedAction());

        // Non-critical timeouts dropping confidence < 70% (19/33 = 58%): MUST become UNKNOWN + REVIEW
        List<DetectionResult> lowConfidence = new ArrayList<>(fullClean);
        String[] timedOutNonCritical = {
                "root", "mount_analysis", "adb", "emulator", "cloud_phone", "custom_rom",
                "tee_integrity", "threat_apps"
        };
        for (String name : timedOutNonCritical) {
            ScanTier tier = ("tee_integrity".equals(name) || "threat_apps".equals(name))
                    ? ScanTier.POSTPONED : ScanTier.FAST;
            lowConfidence = replaceDetector(
                    lowConfidence, name, DetectionResult.timeout(name, "deadline").withScanTier(tier));
        }
        RiskReport lowConfReport = aggregator.aggregate(
                Collections.emptyList(), lowConfidence, CollectScene.STANDARD);
        assertTrue("Expected confidence < 70%, got " + lowConfReport.getConfidencePercent(),
                lowConfReport.getConfidencePercent() < 70);
        assertEquals(RiskLevel.UNKNOWN, lowConfReport.getOverallRiskLevel());
        assertEquals(RiskAction.REVIEW, lowConfReport.getRecommendedAction());

        // Real risk + CRITICAL timeout must NOT mask the detected risk as UNKNOWN
        List<DetectionResult> riskWithCritTimeout = replaceDetector(
                oneCriticalTimeout, "root",
                new DetectionResult("root", RiskLevel.HIGH, DetectionStatus.DANGER,
                        8, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su")
                        .withScanTier(ScanTier.FAST));
        RiskReport riskReport = aggregator.aggregate(
                Collections.emptyList(), riskWithCritTimeout, CollectScene.STANDARD);
        assertEquals(RiskLevel.HIGH, riskReport.getOverallRiskLevel());
        assertEquals(72, riskReport.getRiskScore());
        assertEquals(91, riskReport.getConfidencePercent());
        assertEquals(ReportStatus.PARTIAL, riskReport.getReportStatus());
    }

    @Test
    public void assessmentConfidenceWeightsDetectionDomainsWithoutCollectorDilution() {
        DataAggregator aggregator = new DataAggregator();
        List<DetectionResult> detections = new ArrayList<>(buildFull16CleanDetections());
        // 5 FAST (weight 10) + 2 POSTPONED (weight 2) timeouts => 21/33 = 64% (< 70%)
        String[] timedOut = {
                "root", "mount_analysis", "adb", "emulator", "cloud_phone",
                "tee_integrity", "threat_apps"
        };
        for (String name : timedOut) {
            ScanTier tier = ("tee_integrity".equals(name) || "threat_apps".equals(name))
                    ? ScanTier.POSTPONED : ScanTier.FAST;
            detections = replaceDetector(
                    detections, name, DetectionResult.timeout(name, "deadline").withScanTier(tier));
        }

        // 22 OK CollectorResults must NOT dilute the Detection Domain denominator (33 -> 55)
        List<com.wsttxm.riskenginesdk.model.CollectorResult> collectors = new ArrayList<>();
        for (int i = 0; i < 22; i++) {
            com.wsttxm.riskenginesdk.model.CollectorResult cr =
                    new com.wsttxm.riskenginesdk.model.CollectorResult("collector_" + i);
            cr.addValue("v", "ok");
            cr.finish();
            collectors.add(cr);
        }

        RiskReport report = aggregator.aggregate(collectors, detections, CollectScene.STANDARD);
        assertEquals(64, report.getConfidencePercent());
        assertEquals(RiskLevel.UNKNOWN, report.getOverallRiskLevel());
        assertEquals(RiskAction.REVIEW, report.getRecommendedAction());
        assertEquals(ReportStatus.PARTIAL, report.getReportStatus());
    }

    @Test
    public void criticalDomainWithPartialSubProbesRemainsSafeWithReducedConfidence() {
        DataAggregator aggregator = new DataAggregator();
        DetectionResult partialCritical = new DetectionResult(
                "hook_framework", RiskLevel.SAFE, DetectionStatus.NORMAL,
                0, 10, false, DetectionExecutionStatus.PARTIAL,
                4, 3, 1, List.of("minor_subprobe_timeout"),
                Collections.emptyList(), "clean_partial")
                .withScanTier(ScanTier.CRITICAL);

        List<DetectionResult> fullWithPartialCritical = replaceDetector(
                buildFull16CleanDetections(), "hook_framework", partialCritical);

        RiskReport report = aggregator.aggregate(
                Collections.emptyList(), fullWithPartialCritical, CollectScene.STANDARD);
        // 30 + 3 * (3/4) = 32.25 / 33 = 98% >= 70%, and criticalFailed must be false
        assertEquals(98, report.getConfidencePercent());
        assertEquals(RiskLevel.SAFE, report.getOverallRiskLevel());
        assertEquals(RiskAction.ALLOW, report.getRecommendedAction());
        assertEquals(ReportStatus.PARTIAL, report.getReportStatus());

        // When total weighted confidence drops below 70% (single CRITICAL domain 1/2 = 50%), UNKNOWN still applies
        DetectionResult halfPartialCritical = new DetectionResult(
                "hook_framework", RiskLevel.SAFE, DetectionStatus.NORMAL,
                0, 10, false, DetectionExecutionStatus.PARTIAL,
                2, 1, 1, List.of("half_failed"),
                Collections.emptyList(), "")
                .withScanTier(ScanTier.CRITICAL);
        RiskReport lowConfReport = aggregator.aggregate(
                Collections.emptyList(), List.of(halfPartialCritical), CollectScene.STANDARD);
        assertEquals(50, lowConfReport.getConfidencePercent());
        assertEquals(RiskLevel.UNKNOWN, lowConfReport.getOverallRiskLevel());
        assertEquals(RiskAction.REVIEW, lowConfReport.getRecommendedAction());
    }

    @Test
    public void tierReportMatchesRiskReportOnUnified0To100Scale() {
        DetectionResult rootHit = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("su_found:/system/bin/su"), "su_found:/system/bin/su")
                .withEvidenceItems(List.of(new EvidenceItem(
                        "su_found", EvidenceItem.SourceLayer.NATIVE,
                        "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)))
                .withScanTier(ScanTier.FAST);
        DetectionResult mountHit = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("system_tmpfs_mount:/x"), "system_tmpfs_mount:/x")
                .withEvidenceItems(List.of(new EvidenceItem(
                        "system_tmpfs_mount", EvidenceItem.SourceLayer.ISOLATED,
                        "/x", "tmpfs", "root_fw", EvidenceItem.Rank.MEDIUM)))
                .withScanTier(ScanTier.FAST);

        List<DetectionResult> stageDetections = Arrays.asList(rootHit, mountHit);
        TierReport tierReport = new TierReport(ScanTier.FAST, stageDetections, 25L);
        RiskReport fullReport = new DataAggregator().aggregate(
                Collections.emptyList(), stageDetections, CollectScene.STANDARD);

        assertEquals(fullReport.getRiskScore(), tierReport.getRiskScore());
        assertEquals(78, tierReport.getRiskScore());
        assertEquals(RiskLevel.HIGH, tierReport.getHighestRiskLevel());

        // Hard trigger in CRITICAL tier floors TierReport to 95–100 + DEADLY
        DetectionResult hardHook = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("inline_hook:openat"), "inline_hook:openat")
                .withScanTier(ScanTier.CRITICAL);
        TierReport criticalTier = new TierReport(ScanTier.CRITICAL, List.of(hardHook), 10L);
        assertEquals(95, criticalTier.getRiskScore());
        assertEquals(RiskLevel.DEADLY, criticalTier.getHighestRiskLevel());
    }

    @Test
    public void directTierReportAppliesPolicyAndTierConfidenceParity() {
        // 1) Direct TierReport applies scene + ALLOWLIST + INFORMATIONAL_ONLY policy rules
        DetectionResult rawNetworkMitm = new DetectionResult(
                "network_risk", RiskLevel.LOW, DetectionStatus.WARNING,
                2, 10, true,
                List.of("user_ca_cert:CorpRootCA"),
                "user_ca_cert:CorpRootCA")
                .withScanTier(ScanTier.FAST);

        TierReport paymentTier = new TierReport(
                ScanTier.FAST, List.of(rawNetworkMitm), 15L, 1000L,
                RiskPolicy.forScene(CollectScene.PAYMENT));
        assertEquals(38, paymentTier.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, paymentTier.getHighestRiskLevel());

        TierReport allowlistedTier = new TierReport(
                ScanTier.FAST, List.of(rawNetworkMitm), 15L, 1000L,
                RiskPolicy.builder(CollectScene.PAYMENT).allowlistFamily("network_mitm").build());
        assertEquals(0, allowlistedTier.getRiskScore());
        assertEquals(RiskLevel.SAFE, allowlistedTier.getHighestRiskLevel());

        TierReport infoOnlyTier = new TierReport(
                ScanTier.FAST, List.of(rawNetworkMitm), 15L, 1000L,
                RiskPolicy.builder(CollectScene.PAYMENT).informationalOnlyFamily("network_mitm").build());
        assertEquals(0, infoOnlyTier.getRiskScore());
        assertEquals(RiskLevel.LOW, infoOnlyTier.getHighestRiskLevel());

        // 2) CRITICAL tier with 1 clean + 1 timed-out CRITICAL domain must report UNKNOWN (not SAFE)
        TierReport critTimeoutTier = new TierReport(
                ScanTier.CRITICAL,
                Arrays.asList(
                        safeDetector("debug", ScanTier.CRITICAL),
                        DetectionResult.timeout("hook_framework", "deadline").withScanTier(ScanTier.CRITICAL)),
                10L);
        assertEquals(0, critTimeoutTier.getRiskScore());
        assertEquals(RiskLevel.UNKNOWN, critTimeoutTier.getHighestRiskLevel());
        assertTrue(critTimeoutTier.isPartial());

        // 3) CRITICAL tier with 2 clean + 1 PARTIAL (3/4 sub-probes ok -> 92% >= 70%) stays SAFE
        DetectionResult partialCrit = new DetectionResult(
                "hook_framework", RiskLevel.SAFE, DetectionStatus.NORMAL,
                0, 10, false, DetectionExecutionStatus.PARTIAL,
                4, 3, 1, List.of("minor_timeout"), Collections.emptyList(), "")
                .withScanTier(ScanTier.CRITICAL);
        TierReport critPartialTier = new TierReport(
                ScanTier.CRITICAL,
                Arrays.asList(
                        safeDetector("debug", ScanTier.CRITICAL),
                        safeDetector("app_integrity", ScanTier.CRITICAL),
                        partialCrit),
                10L);
        assertEquals(0, critPartialTier.getRiskScore());
        assertEquals(RiskLevel.SAFE, critPartialTier.getHighestRiskLevel());
        assertTrue(critPartialTier.isPartial());

        // 4) FAST tier confidence check: 2/3 (67% < 70%) -> UNKNOWN; 4/5 (80% >= 70%) -> SAFE
        TierReport fastLowConf = new TierReport(
                ScanTier.FAST,
                Arrays.asList(
                        safeDetector("root", ScanTier.FAST),
                        safeDetector("adb", ScanTier.FAST),
                        DetectionResult.timeout("emulator", "deadline").withScanTier(ScanTier.FAST)),
                15L);
        assertEquals(RiskLevel.UNKNOWN, fastLowConf.getHighestRiskLevel());

        TierReport fastHighConf = new TierReport(
                ScanTier.FAST,
                Arrays.asList(
                        safeDetector("root", ScanTier.FAST),
                        safeDetector("adb", ScanTier.FAST),
                        safeDetector("mount_analysis", ScanTier.FAST),
                        safeDetector("network_risk", ScanTier.FAST),
                        DetectionResult.timeout("emulator", "deadline").withScanTier(ScanTier.FAST)),
                15L);
        assertEquals(RiskLevel.SAFE, fastHighConf.getHighestRiskLevel());
        assertTrue(fastHighConf.isPartial());
    }

    @Test
    public void consumerProguardRulesKeepNewScoringModelTypes() throws Exception {
        String rules = new String(
                java.nio.file.Files.readAllBytes(java.nio.file.Path.of("consumer-rules.pro")),
                java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.model.RiskDimension"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.model.RiskAction"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.model.ScoreBreakdown"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.model.ScoreBreakdown$*"));
    }

    private static DetectionResult lowHit(String detector, String token, String family, int score) {
        return new DetectionResult(
                detector, RiskLevel.LOW, DetectionStatus.WARNING,
                score, 10, false, List.of(token), token)
                .withEvidenceItems(List.of(new EvidenceItem(
                        token, EvidenceItem.SourceLayer.JAVA, detector, token, family, EvidenceItem.Rank.WEAK)));
    }

    private static DetectionResult safeDetector(String name, ScanTier tier) {
        return new DetectionResult(
                name, RiskLevel.SAFE, DetectionStatus.NORMAL,
                0, 10, false, DetectionExecutionStatus.SAFE,
                1, 1, 0, Collections.emptyList(), Collections.emptyList(), "clean")
                .withScanTier(tier);
    }

    private static List<DetectionResult> buildFull16CleanDetections() {
        return Arrays.asList(
                safeDetector("hook_framework", ScanTier.CRITICAL),
                safeDetector("debug", ScanTier.CRITICAL),
                safeDetector("app_integrity", ScanTier.CRITICAL),
                safeDetector("root", ScanTier.FAST),
                safeDetector("mount_analysis", ScanTier.FAST),
                safeDetector("adb", ScanTier.FAST),
                safeDetector("emulator", ScanTier.FAST),
                safeDetector("cloud_phone", ScanTier.FAST),
                safeDetector("custom_rom", ScanTier.FAST),
                safeDetector("multi_instance", ScanTier.FAST),
                safeDetector("network_risk", ScanTier.FAST),
                safeDetector("location_risk", ScanTier.FAST),
                safeDetector("screen_and_fraud", ScanTier.FAST),
                safeDetector("consistency", ScanTier.FAST),
                safeDetector("tee_integrity", ScanTier.POSTPONED),
                safeDetector("threat_apps", ScanTier.POSTPONED)
        );
    }

    private static List<DetectionResult> replaceDetector(List<DetectionResult> base,
                                                         String name,
                                                         DetectionResult replacement) {
        List<DetectionResult> copy = new ArrayList<>(base.size());
        for (DetectionResult d : base) {
            copy.add(name.equals(d.getDetectorName()) ? replacement : d);
        }
        return copy;
    }

    private static boolean hasBreakdownCategory(RiskReport report, ScoreBreakdown.Category cat) {
        assertNotNull(report.getScoreBreakdown());
        for (ScoreBreakdown.Entry entry : report.getScoreBreakdown().getEntries()) {
            if (entry.getCategory() == cat) return true;
        }
        return false;
    }

    private static boolean hasBreakdownKeyPrefix(RiskReport report,
                                                 ScoreBreakdown.Category cat,
                                                 String prefix) {
        for (ScoreBreakdown.Entry entry : report.getScoreBreakdown().getEntries()) {
            if (entry.getCategory() == cat && entry.getKey().startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static DetectionResult find(RiskReport report, String name) {
        for (DetectionResult d : report.getDetections()) {
            if (name.equals(d.getDetectorName())) {
                return d;
            }
        }
        throw new AssertionError("Missing detector: " + name);
    }
}
