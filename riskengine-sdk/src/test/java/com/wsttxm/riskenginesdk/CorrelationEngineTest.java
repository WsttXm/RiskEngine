package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CorrelationEngineTest {

    @Test
    public void c1PromotesWeakEmulatorClusterToActionableMedium() {
        DetectionResult emulator = new DetectionResult(
                "emulator", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true,
                List.of("disk_small:4gb", "no_thermal", "emulator_ip:10.0.2.15"),
                "disk_small:4gb; no_thermal; emulator_ip:10.0.2.15");
        DetectionResult correlated = CorrelationEngine.correlate(List.of(emulator),
                CollectScene.STANDARD);
        assertNotNull(correlated);
        assertTrue(correlated.getDetails().get(0).startsWith("C1:"));
        assertEquals(RiskLevel.MEDIUM, correlated.getRiskLevel());
        assertFalse(correlated.isInformational());
    }

    @Test
    public void c1DoesNotTriggerOnHardwareNoiseOrTooFewWeakSignals() {
        DetectionResult noiseOnly = new DetectionResult(
                "emulator", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true,
                List.of("aosp_sensor_vendor:x", "missing_feature:telephony", "limited_hardware"),
                "hardware noise");
        assertNull(CorrelationEngine.correlate(List.of(noiseOnly), CollectScene.STANDARD));

        DetectionResult twoWeak = new DetectionResult(
                "emulator", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true,
                List.of("no_thermal", "low_sensor_count:1"),
                "two weak");
        assertNull(CorrelationEngine.correlate(List.of(twoWeak), CollectScene.STANDARD));
    }

    @Test
    public void c2PromotesSingleStrongHypervisorAtMediumToHigh() {
        DetectionResult emulator = new DetectionResult(
                "emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("cpu:hypervisor"), "cpu:hypervisor");
        DetectionResult correlated = CorrelationEngine.correlate(List.of(emulator),
                CollectScene.STANDARD);
        assertNotNull(correlated);
        assertTrue(correlated.getDetails().get(0).startsWith("C2:"));
        assertEquals(RiskLevel.HIGH, correlated.getRiskLevel());
    }

    @Test
    public void c3HardTriggersInlineHookWithFrida() {
        DetectionResult hook = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("inline_hook:openat", "maps:frida"),
                "inline_hook:openat");
        DetectionResult correlated = CorrelationEngine.correlate(List.of(hook),
                CollectScene.STANDARD);
        assertNotNull(correlated);
        assertEquals(RiskLevel.DEADLY, correlated.getRiskLevel());
        assertTrue(correlated.getDetails().get(0).startsWith("C3:"));
    }

    @Test
    public void c4HiddenRootFromSyscallMismatchAndModuleMount() {
        DetectionResult root = new DetectionResult(
                "root", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("syscall_mismatch:/system/bin/su"),
                "syscall_mismatch");
        DetectionResult mount = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("module_mount"), "module_mount");
        DetectionResult correlated = CorrelationEngine.correlate(List.of(root, mount),
                CollectScene.STANDARD);
        assertNotNull(correlated);
        assertEquals(RiskLevel.HIGH, correlated.getRiskLevel());
        assertTrue(correlated.getDetails().stream().anyMatch(item -> item.startsWith("C4:")));
    }

    @Test
    public void c5ResetpropStaysInformational() {
        DetectionResult rom = new DetectionResult(
                "custom_rom", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true, List.of("prop_mismatch:fingerprint"),
                "prop_mismatch:fingerprint");
        DetectionResult correlated = CorrelationEngine.correlate(List.of(rom),
                CollectScene.STANDARD);
        assertNotNull(correlated);
        assertTrue(correlated.isInformational());
        assertEquals(RiskLevel.LOW, correlated.getRiskLevel());
    }

    @Test
    public void c7CloudWeakClusterActionableOnLogin() {
        DetectionResult cloud = new DetectionResult(
                "cloud_phone", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true, List.of("battery_zero:v=0,t=0", "very_low_sensor_count:1"),
                "battery");
        assertNull(CorrelationEngine.correlate(List.of(cloud), CollectScene.STANDARD));
        DetectionResult correlated = CorrelationEngine.correlate(List.of(cloud),
                CollectScene.LOGIN);
        assertNotNull(correlated);
        assertTrue(correlated.getDetails().get(0).startsWith("C7:"));
        assertFalse(correlated.isInformational());
    }

    @Test
    public void c7IgnoresStrongCloudTokensAndNonWeakMetadata() {
        DetectionResult strongCloud = new DetectionResult(
                "cloud_phone", RiskLevel.HIGH, DetectionStatus.DANGER,
                7, 10, false,
                List.of("cloud_prop:ro.redfinger=1", "virtual_gpu:virgl:virgl"),
                "cloud_prop; virtual_gpu");
        assertNull(CorrelationEngine.correlate(List.of(strongCloud), CollectScene.LOGIN));
        assertNull(CorrelationEngine.correlate(List.of(strongCloud), CollectScene.PAYMENT));

        DetectionResult singleWeakWithDedupe = new DetectionResult(
                "cloud_phone", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true,
                List.of("battery_zero:v=0,t=0", "deduped:corroborating_evidence"),
                "battery_zero");
        assertNull(CorrelationEngine.correlate(List.of(singleWeakWithDedupe), CollectScene.LOGIN));
    }

    @Test
    public void bootloaderUnlockAndOrangeBootElevateInLoginAndPaymentOnly() {
        DetectionResult unlockedOnly = new DetectionResult(
                "consistency", RiskLevel.LOW, DetectionStatus.WARNING,
                2, 10, true, List.of("bootloader_unlocked"), "bootloader_unlocked");
        assertTrue(CorrelationEngine.applyScene(unlockedOnly, CollectScene.STANDARD)
                .isInformational());

        DetectionResult loginUnlocked = CorrelationEngine.applyScene(
                unlockedOnly, CollectScene.LOGIN);
        assertFalse(loginUnlocked.isInformational());
        assertEquals(RiskLevel.MEDIUM, loginUnlocked.getRiskLevel());
        assertEquals(4, loginUnlocked.getScore());

        DetectionResult bothSignals = new DetectionResult(
                "consistency", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true,
                List.of("bootloader_unlocked", "verified_boot_state:orange"),
                "bootloader_unlocked; verified_boot_state:orange");
        DetectionResult paymentBoth = CorrelationEngine.applyScene(
                bothSignals, CollectScene.PAYMENT);
        assertFalse(paymentBoth.isInformational());
        assertEquals(RiskLevel.HIGH, paymentBoth.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, paymentBoth.getStatus());
        assertEquals(7, paymentBoth.getScore());

        DetectionResult hardwareAttested = new DetectionResult(
                "consistency", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true,
                List.of("key_attestation:bootloader_unlocked"),
                "key_attestation:bootloader_unlocked");
        DetectionResult loginAttested = CorrelationEngine.applyScene(
                hardwareAttested, CollectScene.LOGIN);
        assertFalse(loginAttested.isInformational());
        assertEquals(RiskLevel.HIGH, loginAttested.getRiskLevel());

        DetectionResult benignWeak = new DetectionResult(
                "consistency", RiskLevel.LOW, DetectionStatus.WARNING,
                2, 10, true, List.of("kernel_dirty_on_release"), "kernel_dirty_on_release");
        assertTrue(CorrelationEngine.applyScene(benignWeak, CollectScene.LOGIN).isInformational());
        assertTrue(CorrelationEngine.applyScene(benignWeak, CollectScene.PAYMENT).isInformational());
    }

    @Test
    public void loginSceneMakesEmulatorActionable() {
        DetectionResult emulator = new DetectionResult(
                "emulator", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true, List.of("generic_fingerprint:x"), "generic");
        DetectionResult updated = CorrelationEngine.applyScene(emulator, CollectScene.LOGIN);
        assertFalse(updated.isInformational());
        assertEquals(1, updated.getScore());
    }

    @Test
    public void paymentSceneMakesAdbActionable() {
        DetectionResult adb = new DetectionResult(
                "adb", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true, List.of("settings_adb_wifi_enabled"), "wifi");
        assertTrue(CorrelationEngine.applyScene(adb, CollectScene.STANDARD).isInformational());
        assertFalse(CorrelationEngine.applyScene(adb, CollectScene.PAYMENT).isInformational());
    }

    @Test
    public void dedupeKeepsFirstFamilyScore() {
        DetectionResult root = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("native:mount:ksu"), "native:mount:ksu");
        DetectionResult mount = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("mountinfo:ksu"), "mountinfo:ksu");
        List<DetectionResult> out = CorrelationEngine.dedupeFamilies(List.of(root, mount));
        assertFalse(out.get(0).isInformational());
        assertTrue(out.get(1).isInformational());
        assertEquals(RiskLevel.LOW, out.get(1).getRiskLevel());
        assertEquals(DetectionStatus.WARNING, out.get(1).getStatus());
        assertTrue(out.get(1).getDetails().contains("deduped:corroborating_evidence"));
    }

    @Test
    public void informationalEvidenceDoesNotSuppressLaterActionableFamily() {
        DetectionResult hint = new DetectionResult(
                "hook_hint", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true, List.of("frida_port_open:27042"), "frida hint");
        DetectionResult confirmed = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("maps:frida"), "maps:frida");

        List<DetectionResult> out = CorrelationEngine.dedupeFamilies(List.of(hint, confirmed));

        assertTrue(out.get(0).isInformational());
        assertFalse(out.get(1).isInformational());
    }

    @Test
    public void c4HiddenRootMatchesRealNativePrefixedTokens() {
        DetectionResult root = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                List.of("native:syscall_mismatch:/system/bin/su", "native:mount:module"),
                "native:syscall_mismatch");
        DetectionResult correlated = CorrelationEngine.correlate(List.of(root),
                CollectScene.STANDARD);
        assertNotNull(correlated);
        assertEquals(RiskLevel.HIGH, correlated.getRiskLevel());
        assertTrue(correlated.getDetails().stream().anyMatch(item -> item.startsWith("C4:")));
    }

    @Test
    public void newFamilyRemainsActionableWhenOnlyPartOfEvidenceIsDuplicated() {
        DetectionResult root = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("native:mount:ksu"), "root");
        DetectionResult combined = new DetectionResult(
                "combined", RiskLevel.DEADLY, DetectionStatus.DANGER,
                10, 10, false,
                List.of("su_found:/system/bin/su", "maps:frida"), "root and hook");

        List<DetectionResult> out = CorrelationEngine.dedupeFamilies(List.of(root, combined));

        assertFalse(out.get(1).isInformational());
    }

    @Test
    public void systemTmpfsMountDeduplicatesAcrossRootAndMountAnalysis() {
        DetectionResult root = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                List.of("native:mount:system_tmpfs:/system/etc/security/cacerts"),
                "system_tmpfs");
        DetectionResult mount = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false,
                List.of("system_tmpfs_mount:/system/etc/security/cacerts"),
                "system_tmpfs");

        List<DetectionResult> out = CorrelationEngine.dedupeFamilies(List.of(root, mount));
        assertFalse(out.get(0).isInformational());
        assertTrue(out.get(1).isInformational());
    }

    @Test
    public void evidenceFamilyIsCoveredByUsesExactFamilyMatchingOnly() {
        assertTrue(EvidenceFamily.isCoveredBy(Set.of("frida"), Set.of("frida", "root_fw")));
        assertFalse(EvidenceFamily.isCoveredBy(Set.of("frida", "xposed"), Set.of("frida")));
        assertFalse(EvidenceFamily.isCoveredBy(Set.of(), Set.of("frida")));
        assertFalse(EvidenceFamily.isCoveredBy(Set.of("hook_framework"), Set.of("frida")));
        assertFalse(EvidenceFamily.isCoveredBy(Set.of("hook_framework"), Set.of("xposed")));
    }

    @Test
    public void c10VishingFraudComboTriggersHigh8InPaymentOnly() {
        DetectionResult callAndShare = new DetectionResult(
                "screen_and_fraud", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                5, 10, false,
                List.of("ongoing_call:in_call", "virtual_display:scrcpy"),
                "ongoing_call:in_call; virtual_display:scrcpy");

        assertNull(CorrelationEngine.correlate(List.of(callAndShare), CollectScene.STANDARD));
        assertNull(CorrelationEngine.correlate(List.of(callAndShare), CollectScene.LOGIN));

        DetectionResult payment = CorrelationEngine.correlate(
                List.of(callAndShare), CollectScene.PAYMENT);
        assertNotNull(payment);
        assertEquals(RiskLevel.HIGH, payment.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, payment.getStatus());
        assertEquals(8, payment.getScore());
        assertFalse(payment.isInformational());
        assertTrue(payment.getDetails().contains("C10:vishing_fraud_combo"));
        assertTrue(payment.getEvidenceItems().stream()
                .anyMatch(e -> "vishing_fraud_combo".equals(e.getCode())
                        && "fraud_context".equals(e.getEvidenceFamily())));
    }

    @Test
    public void c9StealthRootWithUnmountTriggersOnIsolatedDiffOrBionicPropTamperWhenRootClean() {
        DetectionResult cleanRoot = new DetectionResult(
                "root", RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                List.of(), "");
        DetectionResult mountDiff = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                List.of("isolated_mount_diff:hidden:/system/bin (overlay:KSU)"),
                "isolated_mount_diff");

        DetectionResult c9FromMount = CorrelationEngine.correlate(
                List.of(cleanRoot, mountDiff), CollectScene.STANDARD);
        assertNotNull(c9FromMount);
        assertEquals(RiskLevel.HIGH, c9FromMount.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, c9FromMount.getStatus());
        assertEquals(8, c9FromMount.getScore());
        assertFalse(c9FromMount.isInformational());
        assertTrue(c9FromMount.getDetails().contains("C9:stealth_root_with_unmount"));
        assertTrue(c9FromMount.getEvidenceItems().stream()
                .anyMatch(e -> "stealth_root_with_unmount".equals(e.getCode())
                        && "root_fw".equals(e.getEvidenceFamily())));

        DetectionResult bionicPropTamper = new DetectionResult(
                "consistency", RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                List.of("prop_area_hole_critical:adbd_config_prop"),
                "prop_area_hole_critical:adbd_config_prop");
        DetectionResult c9FromProp = CorrelationEngine.correlate(
                List.of(cleanRoot, bionicPropTamper), CollectScene.STANDARD);
        assertNotNull(c9FromProp);
        assertEquals(RiskLevel.HIGH, c9FromProp.getRiskLevel());
        assertTrue(c9FromProp.getDetails().contains("C9:stealth_root_with_unmount"));

        // When conventional root paths already hit, C9 must NOT fire.
        DetectionResult conventionalRoot = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                List.of("su_found:/system/bin/su"), "su_found:/system/bin/su");
        DetectionResult notStealth = CorrelationEngine.correlate(
                List.of(conventionalRoot, mountDiff, bionicPropTamper), CollectScene.STANDARD);
        assertNull(notStealth);

        // When root detector was not run (e.g. enableRoot=false), C9 must NOT fire.
        assertNull(CorrelationEngine.correlate(List.of(bionicPropTamper), CollectScene.STANDARD));
    }

    @Test
    public void teeTamperFamilyMappingDeduplicationAndAllSceneActionability() {
        assertEquals("tee_tamper", EvidenceFamily.familyOf("tee_grant_chain_split"));
        assertEquals("tee_tamper", EvidenceFamily.familyOf("tee_binder_ioctl_hook"));
        assertEquals("tee_tamper", EvidenceFamily.familyOf("tee_keybox_revoked:deadbeef"));
        assertEquals("tee_tamper", EvidenceFamily.familyOf("tee_overwrite_stale_chain"));
        assertEquals("tee_tamper", EvidenceFamily.familyOf("tee_post_processing_latency"));
        assertEquals("tee_tamper", EvidenceFamily.familyOf("tee_soft_strongbox"));
        assertNull(EvidenceFamily.familyOf("soter_fixed_spki"));

        DetectionResult mediumTee = new DetectionResult(
                "tee_integrity", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("tee_soft_strongbox"), "tee_soft_strongbox");
        for (CollectScene scene : CollectScene.values()) {
            DetectionResult applied = CorrelationEngine.applyScene(mediumTee, scene);
            assertFalse(applied.isInformational());
            assertEquals(4, applied.getScore());
            assertEquals(RiskLevel.MEDIUM, applied.getRiskLevel());
        }

        DetectionResult primaryTee = new DetectionResult(
                "tee_integrity", RiskLevel.HIGH, DetectionStatus.DANGER,
                9, 10, false, List.of("tee_grant_chain_split"), "tee_grant_chain_split");
        DetectionResult duplicateTee = new DetectionResult(
                "tee_plugin", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false, List.of("tee_soft_strongbox"), "tee_soft_strongbox");
        List<DetectionResult> deduped = CorrelationEngine.dedupeFamilies(
                List.of(primaryTee, duplicateTee));
        assertFalse(deduped.get(0).isInformational());
        assertTrue(deduped.get(1).isInformational());
    }
}
