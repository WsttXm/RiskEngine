package org.wstt.riskengineserver.util;

import org.junit.jupiter.api.Test;
import org.wstt.riskengineserver.dto.DetectionResultDTO;
import org.wstt.riskengineserver.dto.RiskReportDTO;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskReportMetricsTest {

    @Test
    void backfillDerivesStatusesScoresAndKeywordsFromLegacyPayload() {
        DetectionResultDTO hook = new DetectionResultDTO();
        hook.setDetectorName("hook_framework");
        hook.setRiskLevel("HIGH");
        hook.setEvidence("dbus_reject:45678; trampoline:2");

        DetectionResultDTO adb = new DetectionResultDTO();
        adb.setDetectorName("adb");
        adb.setRiskLevel("LOW");
        adb.setWarnOnly(true);
        adb.setEvidence("settings_adb_enabled");

        RiskReportDTO report = new RiskReportDTO();
        report.setDetections(List.of(hook, adb));

        RiskReportMetrics.backfill(report);

        assertEquals(7, report.getRiskScore());
        assertEquals(1, report.getDangerCount());
        assertEquals(1, report.getWarningCount());
        assertEquals("DANGER", hook.getStatus());
        assertEquals(7, hook.getScore());
        assertTrue(RiskReportMetrics.buildDetailKeywords(report.getDetections()).contains("dbus_reject"));
    }
}
