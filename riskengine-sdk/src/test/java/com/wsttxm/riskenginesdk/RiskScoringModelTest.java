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
        assertEquals(RiskLevel.SAFE, reportAtScore(0).getOverallRiskLevel());
        assertEquals(RiskLevel.LOW, reportAtScore(1).getOverallRiskLevel());
        assertEquals(RiskLevel.MEDIUM, reportAtScore(4).getOverallRiskLevel());
        assertEquals(RiskLevel.HIGH, reportAtScore(10).getOverallRiskLevel());
        assertEquals(RiskLevel.DEADLY, reportAtScore(18).getOverallRiskLevel());
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

        assertEquals(12, report.getRiskScore());
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

    private RiskReport reportAtScore(int score) {
        if (score == 0) {
            return new RiskReport(new DeviceFingerprint(), List.of(
                    new DetectionResult("test", RiskLevel.SAFE, DetectionStatus.NORMAL,
                            0, 18, false, List.of(), "")));
        }
        return new RiskReport(new DeviceFingerprint(), List.of(
                new DetectionResult("test", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                        score, Math.max(18, score), false, List.of("signal"), "signal")));
    }
}
