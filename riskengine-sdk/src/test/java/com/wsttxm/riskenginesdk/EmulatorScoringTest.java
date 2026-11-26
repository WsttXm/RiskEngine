package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.EmulatorEvidenceClassifier;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.EmulatorDetector;
import com.wsttxm.riskenginesdk.detector.RootDetector;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class EmulatorScoringTest {
    @Test
    public void aospSensorAndMissingTelephonyAreNoise() {
        assertEquals(EmulatorEvidenceClassifier.Rank.WEAK,
                EmulatorEvidenceClassifier.rank("aosp_sensor_vendor:accel"));
        assertEquals(EmulatorEvidenceClassifier.Rank.WEAK,
                EmulatorEvidenceClassifier.rank("missing_feature:telephony"));
        assertTrue(EmulatorEvidenceClassifier.isHardwareNoise("aosp_sensor_vendor:accel"));
        assertTrue(EmulatorEvidenceClassifier.isHardwareNoise("missing_feature:telephony"));
    }

    @Test
    public void qemuAndHypervisorAreStrong() {
        assertEquals(EmulatorEvidenceClassifier.Rank.STRONG,
                EmulatorEvidenceClassifier.rank("qemu_prop:ro.kernel.qemu"));
        assertEquals(EmulatorEvidenceClassifier.Rank.STRONG,
                EmulatorEvidenceClassifier.rank("cpu:hypervisor"));
        assertEquals(EmulatorEvidenceClassifier.Rank.STRONG,
                EmulatorEvidenceClassifier.rank("emu_file:/dev/qemu_pipe"));
    }

    @Test
    public void emulatorDetectorDetectsX86HypervisorFlagsInCpuInfo() throws Exception {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedCpuInfoForTest(SignalResult.success(
                "model name\t: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz|flags : hypervisor vmx"));
        snapshot.seedDiskSizeDataForTest(SignalResult.success(64L * 1024 * 1024 * 1024));
        snapshot.seedKernelInfoForTest(SignalResult.success("Linux 6.1.0 aarch64"));

        List<String> evidence = invokeCheckCpuAndDisk(new EmulatorDetector(null, snapshot));
        assertTrue("Expected cpu:hypervisor from x86_64 hypervisor flag, got " + evidence,
                evidence.contains("cpu:hypervisor"));
    }

    @Test
    public void emulatorDetectorDetectsQemuModelNameInCpuInfo() throws Exception {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedCpuInfoForTest(SignalResult.success(
                "model name\t: QEMU Virtual CPU version 2.5+"));
        snapshot.seedDiskSizeDataForTest(SignalResult.success(64L * 1024 * 1024 * 1024));
        snapshot.seedKernelInfoForTest(SignalResult.success("Linux 6.1.0 aarch64"));

        List<String> evidence = invokeCheckCpuAndDisk(new EmulatorDetector(null, snapshot));
        assertTrue("Expected cpu:hypervisor from QEMU model name, got " + evidence,
                evidence.contains("cpu:hypervisor"));
    }

    @Test
    public void emulatorDetectorDoesNotFlagCleanArm64CpuInfo() throws Exception {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedCpuInfoForTest(SignalResult.success(
                "Processor\t: AArch64 Processor rev 1 (aarch64)"
                        + "|CPU implementer\t: 0x41|CPU part\t: 0xd46"
                        + "|Hardware\t: Qualcomm Technologies, Inc SM8550"));
        snapshot.seedDiskSizeDataForTest(SignalResult.success(128L * 1024 * 1024 * 1024));
        snapshot.seedKernelInfoForTest(SignalResult.success("Linux 5.15.104-android14 aarch64"));

        List<String> evidence = invokeCheckCpuAndDisk(new EmulatorDetector(null, snapshot));
        assertFalse("Clean ARM64 cpuinfo must not trigger cpu:hypervisor: " + evidence,
                evidence.contains("cpu:hypervisor"));
        assertTrue("Clean ARM64 cpu/disk/kernel should yield no evidence, got " + evidence,
                evidence.isEmpty());
    }

    @Test
    public void rootDetectorConsumesSingleCachedNativeRootEvidence() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        seedAllRootPathsAbsent(snapshot);
        snapshot.seedSelinuxEnforceForTest(SignalResult.success(1));
        snapshot.seedNativeRootEvidenceForTest(SignalResult.success("eacces_exists:/data/adb"));

        // Verify snapshot caches the native root result until reset.
        SignalResult<String> first = snapshot.getNativeRootEvidence();
        SignalResult<String> second = snapshot.getNativeRootEvidence();
        assertSame(first, second);

        DetectionResult result = new RootDetector(null, snapshot).call();
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, result.getStatus());
        assertTrue(result.getDetails().contains("native:eacces_exists:/data/adb"));

        snapshot.reset();
        assertNotSame(first, snapshot.getNativeRootEvidence());
    }

    @Test
    public void rootDetectorCleanNativeEvidenceProducesSafe() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        seedAllRootPathsAbsent(snapshot);
        snapshot.seedSelinuxEnforceForTest(SignalResult.success(1));
        snapshot.seedNativeRootEvidenceForTest(SignalResult.success(""));

        DetectionResult result = new RootDetector(null, snapshot).call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
    }

    private static void seedAllRootPathsAbsent(SignalSnapshot snapshot) {
        String[][] groups = {
                DetectionLists.SU_PATHS,
                DetectionLists.MAGISK_PATHS,
                DetectionLists.KERNELSU_PATHS,
                DetectionLists.APATCH_PATHS,
                DetectionLists.MODULE_PATHS
        };
        for (String[] group : groups) {
            for (String path : group) {
                snapshot.seedPathExistsForTest(path, SignalResult.success(false));
            }
        }
    }

    private static List<String> invokeCheckCpuAndDisk(EmulatorDetector detector) throws Exception {
        Class<?> coverageClass = Class.forName(
                BaseDetector.class.getName() + "$CheckCoverage");
        Constructor<?> ctor = coverageClass.getDeclaredConstructor();
        ctor.setAccessible(true);
        Object coverage = ctor.newInstance();

        Method method = EmulatorDetector.class.getDeclaredMethod(
                "checkCpuAndDisk", List.class, coverageClass);
        method.setAccessible(true);
        List<String> evidence = new ArrayList<>();
        method.invoke(detector, evidence, coverage);
        return evidence;
    }
}
