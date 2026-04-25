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
    public void aggregatesWeightedScoreInsteadOfOnlyTakingMaxLevel() {
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                List.of(
                        new DetectionResult("adb", RiskLevel.LOW, DetectionStatus.WARNING,
                                2, 10, true, List.of("settings_adb_enabled"), "settings_adb_enabled"),
                        new DetectionResult("hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                                8, 10, false, List.of("dbus_reject:45678"), "dbus_reject:45678"),
                        new DetectionResult("emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                                4, 10, false, List.of("cmdline_mismatch:virtual"), "cmdline_mismatch:virtual")
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
}
