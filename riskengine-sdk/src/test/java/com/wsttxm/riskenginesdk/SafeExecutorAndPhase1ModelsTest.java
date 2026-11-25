package com.wsttxm.riskenginesdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.model.TierReport;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class SafeExecutorAndPhase1ModelsTest {

    @Test
    public void safeWithTimeoutReturnsValueOnSuccess() {
        SafeExecutor.SafeResult<String> res = SafeExecutor.safeWithTimeout(
                ScanTier.CRITICAL, () -> "ok");
        assertTrue(res.isSuccess());
        assertEquals("ok", res.getOrNull());
        assertEquals("ok", res.getOrDefault("fallback"));
        assertFalse(res.isTimedOut());
        assertFalse(res.isNestedCallDetected());
        assertFalse(SafeExecutor.isInsideSafeWithTimeout());
    }

    @Test
    public void safeWithTimeoutCatchesExceptionLinkageErrorAndOom() {
        SafeExecutor.SafeResult<String> ex = SafeExecutor.safeWithTimeout(500L, () -> {
            throw new SecurityException("denied");
        });
        assertFalse(ex.isSuccess());
        assertTrue(ex.getError() instanceof SecurityException);
        assertEquals("fallback", ex.getOrDefault("fallback"));

        SafeExecutor.SafeResult<String> linkage = SafeExecutor.safeWithTimeout(500L, () -> {
            throw new UnsatisfiedLinkError("missing_jni");
        });
        assertFalse(linkage.isSuccess());
        assertTrue(linkage.getError() instanceof UnsatisfiedLinkError);

        SafeExecutor.SafeResult<String> oom = SafeExecutor.safeWithTimeout(500L, () -> {
            throw new OutOfMemoryError("oom_simulated");
        });
        assertFalse(oom.isSuccess());
        assertTrue(oom.getError() instanceof OutOfMemoryError);

        SafeExecutor.SafeResult<String> inlineOom = SafeExecutor.safe(() -> {
            throw new OutOfMemoryError("inline_oom");
        });
        assertFalse(inlineOom.isSuccess());
        assertTrue(inlineOom.getError() instanceof OutOfMemoryError);
    }

    @Test
    public void safeWithTimeoutCapturesBlockedWorkerStackTraceOnTimeout() {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch blocker = new CountDownLatch(1);
        ExecutorService single = Executors.newSingleThreadExecutor();
        try {
            SafeExecutor.SafeResult<String> res = SafeExecutor.safeWithTimeout(single, 80L, () -> {
                entered.countDown();
                blocker.await(5, TimeUnit.SECONDS);
                return "never";
            });
            assertFalse(res.isSuccess());
            assertTrue(res.isTimedOut());
            assertTrue(res.getError() instanceof SafeExecutor.ExecutionTimeoutException);
            SafeExecutor.ExecutionTimeoutException timeoutEx =
                    (SafeExecutor.ExecutionTimeoutException) res.getError();
            assertFalse("Expected blocked worker stacktrace frames",
                    res.getBlockedStackTrace().isEmpty());
            assertEquals(res.getBlockedStackTrace(), timeoutEx.getExecutionThreadStackTrace());
            assertTrue(timeoutEx.getMessage().contains("worker stack=["));
        } finally {
            blocker.countDown();
            single.shutdownNow();
        }
    }

    @Test
    public void nestedSafeWithTimeoutExecutesInlineWithoutStarvingSingleThreadPool() {
        ExecutorService single = Executors.newSingleThreadExecutor();
        try {
            SafeExecutor.SafeResult<String> outer = SafeExecutor.safeWithTimeout(single, 500L, () -> {
                assertTrue(SafeExecutor.isInsideSafeWithTimeout());
                SafeExecutor.SafeResult<String> inner = SafeExecutor.safeWithTimeout(single, 500L, () -> "inner-ok");
                assertTrue("Nested call must be detected via ThreadLocal guard",
                        inner.isNestedCallDetected());
                assertTrue("Nested call must succeed inline without deadlocking single-thread pool",
                        inner.isSuccess());
                assertTrue("Outer ThreadLocal flag must remain active after inner call",
                        SafeExecutor.isInsideSafeWithTimeout());
                return "outer+" + inner.getOrNull();
            });
            assertTrue(outer.isSuccess());
            assertFalse(outer.isNestedCallDetected());
            assertEquals("outer+inner-ok", outer.getOrNull());
            assertFalse(SafeExecutor.isInsideSafeWithTimeout());
        } finally {
            single.shutdownNow();
        }
    }

    @Test
    public void scanTierBudgetsAndPrioritiesMatchRfc() {
        assertEquals(150L, ScanTier.CRITICAL.getDefaultTimeoutMs());
        assertEquals(1_000L, ScanTier.FAST.getDefaultTimeoutMs());
        assertEquals(3_000L, ScanTier.POSTPONED.getDefaultTimeoutMs());
        assertTrue(ScanTier.CRITICAL.getPriority() < ScanTier.FAST.getPriority());
        assertTrue(ScanTier.FAST.getPriority() < ScanTier.POSTPONED.getPriority());
    }

    @Test
    public void devicePostureModelsSecurityHygieneCleanly() {
        DevicePosture empty = DevicePosture.empty();
        assertNull(empty.getDeviceSecure());
        assertFalse(empty.isDeviceSecure());
        assertFalse(empty.isHardwareKeystoreBacked());
        assertFalse(empty.isStorageEncrypted());
        assertEquals(DevicePosture.StorageEncryptionStatus.UNKNOWN, empty.getStorageEncryptionStatus());

        DevicePosture posture = new DevicePosture.Builder()
                .setDeviceSecure(true)
                .setStorageEncryptionStatus(DevicePosture.StorageEncryptionStatus.ACTIVE_PER_USER)
                .setKeystoreSecurityLevel(DevicePosture.KeystoreSecurityLevel.STRONGBOX)
                .setBiometricStatus(DevicePosture.BiometricStatus.READY)
                .setDeveloperOptionsEnabled(false)
                .setAdbEnabled(false)
                .setLockscreenOrBiometricReset(true)
                .setEvaluatedAtMs(123456L)
                .build();

        assertTrue(posture.isDeviceSecure());
        assertTrue(posture.isStorageEncrypted());
        assertTrue(posture.isHardwareKeystoreBacked());
        assertEquals(Boolean.FALSE, posture.getDeveloperOptionsEnabled());
        assertTrue(posture.isLockscreenOrBiometricReset());
        assertEquals(123456L, posture.getEvaluatedAtMs());
    }

    @Test
    public void detectionResultPreservesBackwardCompatibilityAndScanTierMetadata() {
        DetectionResult legacy = new DetectionResult("root", RiskLevel.HIGH, "su_binary");
        assertEquals(ScanTier.FAST, legacy.getScanTier());

        DetectionResult critical = legacy.withScanTier(ScanTier.CRITICAL);
        assertEquals(ScanTier.CRITICAL, critical.getScanTier());
        assertEquals(ScanTier.FAST, legacy.getScanTier());

        DetectionResult infoCopy = critical.withInformational(true);
        assertEquals(ScanTier.CRITICAL, infoCopy.getScanTier());
        assertTrue(infoCopy.isInformational());

        EvidenceItem item = new EvidenceItem(
                "su_binary",
                EvidenceItem.SourceLayer.NATIVE,
                "/system/xbin/su",
                "exists",
                "root_artifact",
                EvidenceItem.Rank.STRONG);
        DetectionResult withItems = critical.withEvidenceItems(Collections.singletonList(item));
        assertEquals(ScanTier.CRITICAL, withItems.getScanTier());
        assertEquals(1, withItems.getEvidenceItems().size());

        DetectionResult dup = withItems.asInformationalDuplicate();
        assertEquals(ScanTier.CRITICAL, dup.getScanTier());
        assertTrue(dup.isInformational());

        ThreatEvent event = ThreatEvent.fromDetectionResult(withItems, true);
        assertEquals("root", event.getDetectorName());
        assertEquals(RiskLevel.HIGH, event.getRiskLevel());
        assertEquals(ScanTier.CRITICAL, event.getScanTier());
        assertTrue(event.isRuntimeTamper());
        assertTrue(event.getEvidenceFamilies().contains("root_artifact"));
    }

    @Test
    public void baseDetectorPropagatesScanTierOnSuccessAndFailure() {
        BaseDetector okDetector = new BaseDetector(null) {
            @Override
            public String getName() {
                return "critical_probe";
            }

            @Override
            public ScanTier getScanTier() {
                return ScanTier.CRITICAL;
            }

            @Override
            protected DetectionResult detect() {
                return safe();
            }
        };
        assertEquals(150L, okDetector.getTimeoutMs());
        DetectionResult okRes = okDetector.call();
        assertEquals(ScanTier.CRITICAL, okRes.getScanTier());
        assertEquals(RiskLevel.SAFE, okRes.getRiskLevel());

        BaseDetector crashingDetector = new BaseDetector(null) {
            @Override
            public String getName() {
                return "postponed_probe";
            }

            @Override
            public ScanTier getScanTier() {
                return ScanTier.POSTPONED;
            }

            @Override
            protected DetectionResult detect() {
                throw new UnsatisfiedLinkError("jni_boom");
            }
        };
        DetectionResult errRes = crashingDetector.call();
        assertEquals(ScanTier.POSTPONED, errRes.getScanTier());
        assertEquals(DetectionExecutionStatus.ERROR, errRes.getExecutionStatus());
    }

    @Test
    public void tierReportAggregatesScoreLevelAndPartialCorrectly() {
        DetectionResult safe = new DetectionResult("debug", RiskLevel.SAFE, "no risk")
                .withScanTier(ScanTier.CRITICAL);
        DetectionResult infoHigh = new DetectionResult(
                "info_only", RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, true,
                Collections.singletonList("info_signal"), "info_signal")
                .withScanTier(ScanTier.CRITICAL);
        DetectionResult medium = new DetectionResult("hook", RiskLevel.MEDIUM, "frida_port")
                .withScanTier(ScanTier.CRITICAL);
        DetectionResult timedOut = DetectionResult.timeout("slow_probe", "150ms")
                .withScanTier(ScanTier.CRITICAL);

        List<DetectionResult> items = Arrays.asList(safe, infoHigh, medium, timedOut);
        TierReport report = new TierReport(ScanTier.CRITICAL, items, 12L);
        assertEquals(ScanTier.CRITICAL, report.getTier());
        assertEquals(RiskLevel.MEDIUM, report.getHighestRiskLevel());
        assertEquals(38, report.getRiskScore());
        assertEquals(12L, report.getElapsedMs());
        assertTrue(report.isPartial());
        assertNotNull(report.toString());

        TierReport allUnknown = new TierReport(
                ScanTier.POSTPONED,
                Collections.singletonList(DetectionResult.unavailable("tee", "no_keystore")),
                5L);
        assertEquals(RiskLevel.UNKNOWN, allUnknown.getHighestRiskLevel());
        assertEquals(0, allUnknown.getRiskScore());
        assertTrue(allUnknown.isPartial());
    }
}
