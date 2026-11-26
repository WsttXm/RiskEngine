package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class RiskScoringModelTest {

    @Test
    public void scoreThresholdsHaveStableBoundaries() {
        assertEquals(30, RiskReport.MEDIUM_THRESHOLD);
        assertEquals(60, RiskReport.HIGH_THRESHOLD);
        assertEquals(85, RiskReport.DEADLY_THRESHOLD);
        assertEquals(100, RiskReport.MAX_RISK_SCORE);

        assertEquals(RiskLevel.SAFE, reportAtDetectorScore(0, RiskLevel.SAFE).getOverallRiskLevel());
        assertEquals(0, reportAtDetectorScore(0, RiskLevel.SAFE).getRiskScore());

        RiskReport low = reportAtDetectorScore(2, RiskLevel.LOW);
        assertEquals(RiskLevel.LOW, low.getOverallRiskLevel());
        assertEquals(18, low.getRiskScore());

        RiskReport medium = reportAtDetectorScore(4, RiskLevel.MEDIUM);
        assertEquals(RiskLevel.MEDIUM, medium.getOverallRiskLevel());
        assertEquals(38, medium.getRiskScore());

        RiskReport high = reportAtDetectorScore(7, RiskLevel.HIGH);
        assertEquals(RiskLevel.HIGH, high.getOverallRiskLevel());
        assertEquals(64, high.getRiskScore());

        RiskReport deadly = reportAtDetectorScore(10, RiskLevel.DEADLY);
        assertEquals(RiskLevel.DEADLY, deadly.getOverallRiskLevel());
        assertEquals(92, deadly.getRiskScore());
    }

    @Test
    public void aggregatesWeightedScoreInsteadOfOnlyTakingMaxLevel() {
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                List.of(
                        new DetectionResult("adb", RiskLevel.LOW, DetectionStatus.WARNING,
                                2, 10, true, List.of("settings_adb_enabled"), "settings_adb_enabled"),
                        new DetectionResult("hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                                8, 10, false, List.of("frida_pid_port:27042"), "frida_pid_port:27042"),
                        new DetectionResult("emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                                4, 10, false, List.of("cmdline_mismatch"), "cmdline_mismatch")
                )
        );

        assertEquals(95, report.getRiskScore());
        assertEquals(1, report.getDangerCount());
        assertEquals(2, report.getWarningCount());
        assertEquals(RiskLevel.DEADLY, report.getOverallRiskLevel());
    }

    @Test
    public void warnOnlySignalsDoNotIncreaseOverallScore() {
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                List.of(
                        new DetectionResult("adb", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                                4, 10, true, List.of("tcp_listen:5555"), "tcp_listen:5555")
                )
        );

        assertEquals(0, report.getRiskScore());
        assertEquals(1, report.getWarningCount());
        assertEquals(RiskLevel.LOW, report.getOverallRiskLevel());
    }

    @Test
    public void multipleWarnOnlySignalsRemainLowRisk() {
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                List.of(
                        new DetectionResult("adb", RiskLevel.LOW, DetectionStatus.WARNING,
                                2, 10, true, List.of("settings_adb_enabled"),
                                "settings_adb_enabled"),
                        new DetectionResult("custom_rom", RiskLevel.LOW,
                                DetectionStatus.WARNING, 1, 10, true,
                                List.of("community_rom:LineageOS"),
                                "community_rom:LineageOS")
                )
        );

        assertEquals(2, report.getWarningCount());
        assertEquals(0, report.getRiskScore());
        assertEquals(RiskLevel.LOW, report.getOverallRiskLevel());
    }

    @Test
    public void hookAndMemoryTamperingAreHardTriggers() {
        RiskReport inlineHook = new RiskReport(
                new DeviceFingerprint(),
                List.of(new DetectionResult(
                        "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                        8, 10, false, List.of("inline_hook:openat"),
                        "inline_hook:openat")));
        assertEquals(RiskLevel.DEADLY, inlineHook.getOverallRiskLevel());

        RiskReport gotHook = new RiskReport(
                new DeviceFingerprint(),
                List.of(new DetectionResult(
                        "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                        8, 10, false, List.of("got_hook:__system_property_get"),
                        "got_hook:__system_property_get")));
        assertEquals(RiskLevel.DEADLY, gotHook.getOverallRiskLevel());

        RiskReport artNativeCleared = new RiskReport(
                new DeviceFingerprint(),
                List.of(new DetectionResult(
                        "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                        8, 10, false, List.of("art_native_cleared:nativeGetHookEvidenceRaw"),
                        "art_native_cleared:nativeGetHookEvidenceRaw")));
        assertEquals(RiskLevel.DEADLY, artNativeCleared.getOverallRiskLevel());

        RiskReport memfdElf = new RiskReport(
                new DeviceFingerprint(),
                List.of(new DetectionResult(
                        "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                        8, 10, false, List.of("memfd_private_elf:jit-cache"),
                        "memfd_private_elf:jit-cache")));
        assertEquals(RiskLevel.DEADLY, memfdElf.getOverallRiskLevel());
    }

    private RiskReport reportAtDetectorScore(int score, RiskLevel level) {
        if (score == 0) {
            return new RiskReport(new DeviceFingerprint(), List.of(
                    new DetectionResult("test", RiskLevel.SAFE, DetectionStatus.NORMAL,
                            0, 10, false, List.of(), "")));
        }
        DetectionStatus status = level.getValue() >= RiskLevel.HIGH.getValue()
                ? DetectionStatus.DANGER
                : DetectionStatus.WARNING;
        return new RiskReport(new DeviceFingerprint(), List.of(
                new DetectionResult("test", level, status,
                        score, 10, false, List.of("signal"), "signal")));
    }
}
