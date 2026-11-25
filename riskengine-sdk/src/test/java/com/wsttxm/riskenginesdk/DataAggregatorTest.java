package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.ReportStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DataAggregatorTest {
    @Test
    public void synthesizedFieldsAreExposedButNotDoubleCountedInCoverage() {
        CollectorResult collector = new CollectorResult("build_props");
        collector.addValue("model", "test");
        DetectionResult hook = new DetectionResult(
                "hook_framework", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false, List.of("maps:frida"), "maps:frida");

        RiskReport report = new DataAggregator().aggregate(
                List.of(collector), List.of(hook));

        assertTrue(report.getFingerprint().getResults().containsKey("hook_memory_signals"));
        assertTrue(report.getFingerprint().getResults()
                .containsKey("runtime_integrity_score_inputs"));
        assertTrue(report.getFingerprint().getResults().containsKey("fingerprint_id"));
        // Only raw build_props collector + hook_framework detector count toward coverage;
        // hook_memory_signals, runtime_integrity_score_inputs and fingerprint_id are synthetic.
        assertEquals(2, report.getCheckCount());
        assertEquals(2, report.getCompletedCheckCount());
        assertEquals(0, report.getUnsupportedCheckCount());
        assertEquals(100, report.getCoveragePercent());
    }

    @Test
    public void applySceneExecutesBeforeDedupeFamiliesPreventingDoubleScoring() {
        // Both emulator and cloud_phone start as informational=true sharing the "emulator"
        // evidence family via virtual_gpu:*. Under LOGIN, PAYMENT, and DIAGNOSTIC, applyScene
        // promotes both to actionable BEFORE dedupeFamilies runs, so only the first scores.
        DetectionResult emulator = new DetectionResult(
                "emulator", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true, List.of("virtual_gpu:swiftshader:SwiftShader"),
                "virtual_gpu:swiftshader:SwiftShader");
        DetectionResult cloud = new DetectionResult(
                "cloud_phone", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true, List.of("virtual_gpu:swiftshader:SwiftShader"),
                "virtual_gpu:swiftshader:SwiftShader");

        for (CollectScene scene : new CollectScene[] {
                CollectScene.LOGIN, CollectScene.PAYMENT, CollectScene.DIAGNOSTIC
        }) {
            RiskReport report = new DataAggregator().aggregate(
                    List.of(), List.of(emulator, cloud), scene);
            assertEquals("scene=" + scene + " must apply family-max + corroboration lift without double-scoring",
                    44, report.getRiskScore());
            DetectionResult emuOut = report.getDetections().stream()
                    .filter(d -> "emulator".equals(d.getDetectorName()))
                    .findFirst().orElseThrow();
            DetectionResult cloudOut = report.getDetections().stream()
                    .filter(d -> "cloud_phone".equals(d.getDetectorName()))
                    .findFirst().orElseThrow();
            assertFalse("emulator should remain actionable in " + scene, emuOut.isInformational());
            assertTrue("cloud_phone should be deduped to informational in " + scene,
                    cloudOut.isInformational());
            assertTrue(cloudOut.getDetails().contains("deduped:corroborating_evidence"));
        }
    }

    @Test
    public void unsupportedAndEmptyCollectorsDoNotDegradeCleanSafeReport() {
        CollectorResult build = new CollectorResult("build_props");
        build.addValue("model", "Pixel");
        CollectorResult unsupported = new CollectorResult("telephony");
        unsupported.markUnsupported("no_cellular_radio");
        CollectorResult empty = new CollectorResult("optional_sensor");
        empty.finish(); // status == EMPTY

        DetectionResult cleanRoot = new DetectionResult(
                "root", RiskLevel.SAFE, DetectionStatus.NORMAL,
                0, 10, false, List.of(), "");

        RiskReport report = new DataAggregator().aggregate(
                List.of(build, unsupported, empty), List.of(cleanRoot));

        assertEquals(RiskLevel.SAFE, report.getOverallRiskLevel());
        assertEquals(ReportStatus.COMPLETE, report.getReportStatus());
        assertEquals(0, report.getUnknownCount());
        assertEquals(2, report.getUnsupportedCheckCount());
        assertEquals(2, report.getCheckCount());
        assertEquals(2, report.getCompletedCheckCount());
        assertEquals(0, report.getIncompleteCheckCount());
        assertEquals(100, report.getCoveragePercent());
    }

    @Test
    public void bootloaderUnlockElevatesToActionableInLoginAndPaymentEndToEnd() {
        DetectionResult consistency = new DetectionResult(
                "consistency", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, true,
                List.of("bootloader_unlocked", "verified_boot_state:orange"),
                "bootloader_unlocked; verified_boot_state:orange");

        RiskReport standardReport = new DataAggregator().aggregate(
                List.of(), List.of(consistency), CollectScene.STANDARD);
        assertEquals(0, standardReport.getRiskScore());
        assertEquals(RiskLevel.LOW, standardReport.getOverallRiskLevel());

        RiskReport loginReport = new DataAggregator().aggregate(
                List.of(), List.of(consistency), CollectScene.LOGIN);
        assertEquals(38, loginReport.getRiskScore());
        assertEquals(RiskLevel.MEDIUM, loginReport.getOverallRiskLevel());

        RiskReport paymentReport = new DataAggregator().aggregate(
                List.of(), List.of(consistency), CollectScene.PAYMENT);
        assertEquals(64, paymentReport.getRiskScore());
        assertEquals(RiskLevel.HIGH, paymentReport.getOverallRiskLevel());
    }
}
