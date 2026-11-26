package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.TaskScheduler;
import com.wsttxm.riskenginesdk.detector.HookFrameworkDetector;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.util.RiskReportJsonSerializer;

import org.json.JSONObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class TieredSchedulerAndPostureTest {

    @Test
    public void devicePostureAndJsonV2PopulateSystemVpnAndUnofficialStoreFromDetectors()
            throws Exception {
        DetectionResult networkVpn = new DetectionResult(
                "network_risk",
                RiskLevel.LOW,
                DetectionStatus.WARNING,
                2,
                10,
                true,
                DetectionExecutionStatus.RISK,
                4,
                4,
                0,
                Collections.emptyList(),
                Collections.singletonList("vpn_active:tun0"),
                Collections.singletonList(new EvidenceItem(
                        "vpn_active", EvidenceItem.SourceLayer.NATIVE,
                        "/sys/class/net/tun0", "tun0", "network_mitm", EvidenceItem.Rank.WEAK)),
                "vpn_active:tun0");

        DetectionResult unofficialApp = new DetectionResult(
                "app_integrity",
                RiskLevel.MEDIUM,
                DetectionStatus.WARNING,
                4,
                10,
                true,
                DetectionExecutionStatus.RISK,
                4,
                4,
                0,
                Collections.emptyList(),
                Collections.singletonList("unofficial_installer:com.sideload.store"),
                Collections.singletonList(new EvidenceItem(
                        "unofficial_installer", EvidenceItem.SourceLayer.JAVA,
                        "com.sideload.store", "untrusted", "app_tamper", EvidenceItem.Rank.MEDIUM)),
                "unofficial_installer:com.sideload.store");

        DataAggregator aggregator = new DataAggregator();
        RiskReport report = aggregator.aggregate(
                Collections.emptyList(),
                Arrays.asList(networkVpn, unofficialApp),
                CollectScene.STANDARD);

        DevicePosture posture = report.getDevicePosture();
        assertNotNull(posture);
        assertEquals(Boolean.TRUE, posture.getSystemVpn());
        assertTrue(posture.isSystemVpn());
        assertEquals(Boolean.TRUE, posture.getUnofficialStore());
        assertTrue(posture.isUnofficialStore());

        String jsonStr = RiskReportJsonSerializer.serialize(report);
        JSONObject root = new JSONObject(jsonStr);
        JSONObject postureJson = root.getJSONObject("devicePosture");
        assertTrue(postureJson.getBoolean("systemVpn"));
        assertTrue(postureJson.getBoolean("unofficialStore"));
        // Existing v2 posture fields remain intact
        assertTrue(postureJson.has("storageEncrypted"));
        assertTrue(postureJson.has("keystoreLevel"));
        assertTrue(postureJson.has("biometricStatus"));
        assertTrue(postureJson.has("lockscreenOrBiometricReset"));
    }

    @Test
    public void devicePostureSetsFalseWhenCleanAndNullWhenDetectorsUnavailable() throws Exception {
        DetectionResult cleanNetwork = new DetectionResult(
                "network_risk", RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                DetectionExecutionStatus.SAFE, 4, 4, 0,
                Collections.emptyList(), Collections.emptyList(), "clean");
        DetectionResult cleanApp = new DetectionResult(
                "app_integrity", RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                DetectionExecutionStatus.SAFE, 4, 4, 0,
                Collections.emptyList(), Collections.emptyList(), "clean");

        DataAggregator aggregator = new DataAggregator();
        RiskReport cleanReport = aggregator.aggregate(
                Collections.emptyList(),
                Arrays.asList(cleanNetwork, cleanApp),
                CollectScene.STANDARD);
        assertEquals(Boolean.FALSE, cleanReport.getDevicePosture().getSystemVpn());
        assertEquals(Boolean.FALSE, cleanReport.getDevicePosture().getUnofficialStore());

        RiskReport emptyReport = aggregator.aggregate(
                Collections.emptyList(),
                Collections.emptyList(),
                CollectScene.STANDARD);
        assertNull(emptyReport.getDevicePosture().getSystemVpn());
        assertNull(emptyReport.getDevicePosture().getUnofficialStore());
        JSONObject emptyPostureJson = new JSONObject(RiskReportJsonSerializer.serialize(emptyReport))
                .getJSONObject("devicePosture");
        assertTrue(emptyPostureJson.isNull("systemVpn"));
        assertTrue(emptyPostureJson.isNull("unofficialStore"));

        // When network_risk had only 3/3 checks (VPN check skipped due to visibility loss),
        // DevicePosture.systemVpn must remain null (unknown) rather than falsely asserting FALSE.
        DetectionResult vpnSkippedNetwork = new DetectionResult(
                "network_risk", RiskLevel.LOW, DetectionStatus.WARNING, 2, 10, true,
                DetectionExecutionStatus.RISK, 3, 3, 0,
                Collections.emptyList(),
                Collections.singletonList("http_proxy:jvm_property"),
                "http_proxy:jvm_property");
        RiskReport skippedReport = aggregator.aggregate(
                Collections.emptyList(),
                Collections.singletonList(vpnSkippedNetwork),
                CollectScene.STANDARD);
        assertNull(skippedReport.getDevicePosture().getSystemVpn());
    }

    @Test
    public void lateFridaFdIsMappedToFridaFamilyAndHardTriggersDeadly() {
        assertEquals("frida", EvidenceFamily.familyOf("late_frida_fd"));

        DetectionResult hookWithLateFd = new DetectionResult(
                "hook_framework",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8,
                10,
                false,
                Collections.singletonList("late_frida_fd"),
                "late_frida_fd");
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                Collections.singletonList(hookWithLateFd),
                CollectScene.STANDARD);
        assertEquals(RiskLevel.DEADLY, report.getOverallRiskLevel());
    }

    @Test
    public void hookFrameworkDetectorDeclaresCriticalScanTier() {
        HookFrameworkDetector detector = new HookFrameworkDetector(null);
        assertEquals(ScanTier.CRITICAL, detector.getScanTier());
    }

    @Test
    public void taskSchedulerComputesTierWeightedBudgetsAndRoutesPerTaskTimeoutThroughSafeExecutor() {
        TaskScheduler.TierBudgets budgets = TaskScheduler.computeTierBudgets(10_000L);
        assertEquals(10_000L, budgets.getTotalBudgetMs());
        assertEquals(1_000L, budgets.getCriticalBudgetMs());
        assertEquals(3_500L, budgets.getFastBudgetMs());
        assertEquals(5_500L, budgets.getPostponedBudgetMs());
        assertEquals(budgets.getTotalBudgetMs(),
                budgets.getCriticalBudgetMs()
                        + budgets.getFastBudgetMs()
                        + budgets.getPostponedBudgetMs());

        TaskScheduler scheduler = new TaskScheduler();
        try {
            List<TaskScheduler.TieredTask<String>> tasks = Arrays.asList(
                    new TaskScheduler.TieredTask<>("fast_ok", ScanTier.CRITICAL, 150L, () -> "ok"),
                    new TaskScheduler.TieredTask<>("slow_hung", ScanTier.CRITICAL, 60L, () -> {
                        Thread.sleep(2_000L);
                        return "late";
                    })
            );

            List<TaskScheduler.TaskOutcome<String>> outcomes =
                    scheduler.submitAllWithSafeTimeout(tasks, 1_000L);
            assertEquals(2, outcomes.size());

            TaskScheduler.TaskOutcome<String> fast = outcomes.get(0);
            assertTrue(fast.isSuccess());
            assertEquals("ok", fast.getValueOrNull());

            TaskScheduler.TaskOutcome<String> slow = outcomes.get(1);
            assertFalse(slow.isSuccess());
            assertTrue(slow.isTimedOut());
            assertFalse("Timed-out worker stacktrace should be captured",
                    slow.getResult().getBlockedStackTrace().isEmpty());
        } finally {
            scheduler.shutdown();
        }
    }
}
