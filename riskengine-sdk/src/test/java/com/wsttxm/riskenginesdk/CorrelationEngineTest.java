package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CorrelationEngineTest {

    @Test
    public void c1PromotesWeakEmulatorWithHypervisor() {
        DetectionResult emulator = new DetectionResult(
                "emulator", RiskLevel.LOW, DetectionStatus.WARNING,
                1, 10, true, List.of("aosp_sensor_vendor:x", "cpu:hypervisor"),
                "cpu:hypervisor");
        DetectionResult correlated = CorrelationEngine.correlate(List.of(emulator),
                CollectScene.STANDARD);
        assertNotNull(correlated);
        assertTrue(correlated.getDetails().get(0).startsWith("C1:"));
        assertEquals(RiskLevel.MEDIUM, correlated.getRiskLevel());
        assertFalse(correlated.isInformational());
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
}
