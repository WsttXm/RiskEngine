package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.MountAnalysisDetector;
import com.wsttxm.riskenginesdk.detector.RootDetector;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;
import com.wsttxm.riskenginesdk.process.MountViewNormalizer;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RootAndMountDetectorTest {

    // ==================== RootDetector ====================

    @Test
    public void rootDetectorTruePositiveOnSuPath() {
        SignalSnapshot snapshot = cleanRootSnapshot();
        snapshot.seedPathExistsForTest(DetectionLists.SU_PATHS[0], SignalResult.success(true));

        DetectionResult result = new RootDetector(null, snapshot).call();
        assertEquals("root", result.getDetectorName());
        assertEquals(RiskLevel.HIGH, result.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, result.getStatus());
        assertEquals(DetectionExecutionStatus.RISK, result.getExecutionStatus());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().contains("su_found:" + DetectionLists.SU_PATHS[0]));
    }

    @Test
    public void rootDetectorTruePositiveMediumAndWeakTiers() {
        SignalSnapshot mediumSnap = cleanRootSnapshot();
        mediumSnap.seedNativeRootEvidenceForTest(
                SignalResult.success("eacces_exists:/data/adb/magisk"));
        DetectionResult medium = new RootDetector(null, mediumSnap).call();
        assertEquals(RiskLevel.MEDIUM, medium.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, medium.getStatus());
        assertFalse(medium.isInformational());

        SignalSnapshot weakSnap = cleanRootSnapshot();
        weakSnap.seedSelinuxEnforceForTest(SignalResult.success(0));
        DetectionResult weak = new RootDetector(null, weakSnap).call();
        assertEquals(RiskLevel.LOW, weak.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, weak.getStatus());
        assertTrue(weak.isInformational());
        assertTrue(weak.getDetails().contains("selinux_permissive"));
    }

    @Test
    public void rootDetectorFalsePositiveGuardOnCleanDevice() {
        DetectionResult result = new RootDetector(null, cleanRootSnapshot()).call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertEquals(DetectionExecutionStatus.SAFE, result.getExecutionStatus());
        assertTrue(result.getDetails().isEmpty());
        assertEquals(0, result.getChecksFailed());
    }

    @Test
    public void rootDetectorPartialCoverageWhenSomeSignalsFail() {
        SignalSnapshot snapshot = cleanRootSnapshot();
        snapshot.seedSelinuxEnforceForTest(SignalResult.error("EACCES"));
        snapshot.seedNativeRootEvidenceForTest(SignalResult.unavailable("native_unavailable"));

        DetectionResult result = new RootDetector(null, snapshot).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, result.getExecutionStatus());
        assertEquals(2, result.getChecksFailed());
        assertTrue(result.getChecksSucceeded() > 0);
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
    }

    @Test
    public void rootDetectorTotalSignalFailureNeverReportsFullSafeCoverage() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        seedAllRootPaths(snapshot, SignalResult.error("SecurityException"));
        snapshot.seedSelinuxEnforceForTest(SignalResult.error("EACCES"));
        snapshot.seedNativeRootEvidenceForTest(SignalResult.error("UnsatisfiedLinkError"));

        DetectionResult result = new RootDetector(null, snapshot).call();
        assertTrue(result.getExecutionStatus() == DetectionExecutionStatus.PARTIAL
                || result.getExecutionStatus() == DetectionExecutionStatus.UNAVAILABLE);
        assertTrue("Expected at least 7 failed root checks, got " + result.getChecksFailed(),
                result.getChecksFailed() >= 7);
    }

    @Test
    public void rootDetectorIncludesSystemExtSuDynamicPathAndIsolatesBusyBoxNoise() {
        // /system_ext/bin/su must be present in DetectionLists.SU_PATHS.
        assertTrue(Arrays.asList(DetectionLists.SU_PATHS).contains("/system_ext/bin/su"));

        // BusyBox alone MUST stay strictly LOW/1 informational (never actionable root).
        SignalSnapshot busyboxSnap = cleanRootSnapshot();
        busyboxSnap.seedNativeRootEvidenceForTest(SignalResult.success("busybox:/system/xbin/busybox"));
        DetectionResult busybox = new RootDetector(null, busyboxSnap).call();
        assertEquals(RiskLevel.LOW, busybox.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, busybox.getStatus());
        assertEquals(1, busybox.getScore());
        assertTrue(busybox.isInformational());
        assertTrue(busybox.getDetails().contains("busybox:/system/xbin/busybox"));
        assertTrue(busybox.getEvidenceItems().stream().anyMatch(
                i -> "busybox".equals(i.getCode())
                        && "root_fw".equals(i.getEvidenceFamily())
                        && i.getRank() == EvidenceItem.Rank.WEAK));

        // Dynamic $PATH Android directory not in static SU_PATHS is merged without duplicates.
        SignalSnapshot dynSnap = cleanRootSnapshot();
        dynSnap.seedPathExistsForTest("/vendor/xbin/su", SignalResult.success(true));
        DetectionResult dynResult = new RootDetector(
                null, dynSnap, () -> "/system/bin:/vendor/xbin/:/vendor/xbin:/usr/bin").call();
        assertEquals(RiskLevel.HIGH, dynResult.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, dynResult.getStatus());
        assertTrue(dynResult.getDetails().contains("su_found:/vendor/xbin/su"));
        assertTrue(dynResult.getEvidenceItems().stream().anyMatch(
                i -> "su_binary".equals(i.getCode())
                        && "/vendor/xbin/su".equals(i.getLocation())
                        && "root_fw".equals(i.getEvidenceFamily())
                        && i.getPrimarySource() == EvidenceItem.SourceLayer.JAVA));
    }

    @Test
    public void rootDetectorConsolidatesSidechannelAndSelinuxAuditInPostponedPass() {
        // Strong hit in POSTPONED elevates clean FAST pass to HIGH/DANGER/8 with root_fw EvidenceItems.
        SignalSnapshot strongSnap = cleanRootSnapshot();
        strongSnap.seedKernelSidechannelEvidenceForTest(true, SignalResult.success(
                "status=OK\terrno=0\tkp_negative_trusted=0\tprobes_run=4\ttiming_ran=1\ttiming_consecutive_hits=0\n"
                        + "kind=ksu_reboot_ioctl\tversion=12100\tflags=1\tfeatures=3\tsafe_mode=0"));
        strongSnap.seedSelinuxAuditEvidenceForTest(SignalResult.success(
                "status=OK\terrno=0\tprobes_evaluated=3\tlink_applicable=1\tlink_enforced=0\tctx_probe_state=COMPLETE\n"
                        + "kind=netlink_link_leak\tif_kind=wifi"));

        RootDetector detector = new RootDetector(null, strongSnap);
        assertTrue(detector.hasPostponedProbes());

        DetectionResult fastPass = detector.call();
        assertEquals(RiskLevel.SAFE, fastPass.getRiskLevel());
        assertTrue(fastPass.getDetails().isEmpty());

        DetectionResult finalPass = detector.callPostponed(fastPass);
        assertEquals(RiskLevel.HIGH, finalPass.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, finalPass.getStatus());
        assertEquals(8, finalPass.getScore());
        assertFalse(finalPass.isInformational());
        assertTrue(finalPass.getDetails().contains("native:ksu_reboot_ioctl:v12100"));
        assertTrue(finalPass.getDetails().contains("native:netlink_link_leak:wifi"));
        assertTrue(finalPass.getEvidenceItems().stream().anyMatch(
                i -> "ksu_reboot_ioctl".equals(i.getCode()) && "root_fw".equals(i.getEvidenceFamily())));
        assertTrue(finalPass.getEvidenceItems().stream().anyMatch(
                i -> "netlink_link_leak".equals(i.getCode()) && "root_fw".equals(i.getEvidenceFamily())));

        // Timing-only anomaly in POSTPONED elevates clean FAST pass to MEDIUM/WARNING/4 (never DANGER).
        SignalSnapshot timingSnap = cleanRootSnapshot();
        timingSnap.seedKernelSidechannelEvidenceForTest(true, SignalResult.success(
                "status=OK\terrno=0\tkp_negative_trusted=1\tprobes_run=4\ttiming_ran=1\ttiming_consecutive_hits=3\n"
                        + "kind=ksu_prctl_timing_anomaly\tcpu=0\tconsecutive_hits=3\tmetrics=z\\=4.5"));
        timingSnap.seedSelinuxAuditEvidenceForTest(SignalResult.success(
                "status=RESTRICTED\terrno=13\tprobes_evaluated=0"));
        RootDetector timingDetector = new RootDetector(null, timingSnap);
        DetectionResult timingFinal = timingDetector.callPostponed(timingDetector.call());
        assertEquals(RiskLevel.MEDIUM, timingFinal.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, timingFinal.getStatus());
        assertEquals(4, timingFinal.getScore());
        assertFalse(timingFinal.isInformational());
        assertTrue(timingFinal.getDetails().contains("native:ksu_prctl_timing_anomaly:cpu0"));
    }

    // ==================== MountAnalysisDetector ====================

    @Test
    public void mountAnalysisDetectorTruePositiveOnMagiskAndSystemTmpfs() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedTextFileForTest("/proc/mounts", SignalResult.success(
                "tmpfs /debug_ramdisk tmpfs rw,seclabel,relatime 0 0\n"
                        + "overlay /data/adb/modules overlay ro 0 0\n"));
        snapshot.seedTextFileForTest("/proc/self/mountinfo", SignalResult.success(
                "42 1 0:25 / /debug_ramdisk rw - tmpfs magisk rw\n"
                        + "43 1 0:26 / /system/etc/security/cacerts rw - tmpfs tmpfs rw\n"));

        DetectionResult result = new MountAnalysisDetector(null, snapshot).call();
        assertEquals("mount_analysis", result.getDetectorName());
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, result.getStatus());
        assertEquals(DetectionExecutionStatus.RISK, result.getExecutionStatus());
        assertEquals("mountinfo:magisk", result.getDetails().get(0));
        assertFalse("Specific magisk attribution should supersede generic debug_ramdisk",
                result.getDetails().contains("debug_ramdisk_mount"));
        assertTrue(result.getDetails().contains("system_tmpfs_mount:/system/etc/security/cacerts"));
    }

    @Test
    public void mountAnalysisDetectorFalsePositiveGuardOnCleanMounts() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedTextFileForTest("/proc/mounts", SignalResult.success(
                "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"
                        + "tmpfs /dev tmpfs rw,nosuid,relatime 0 0\n"));
        snapshot.seedTextFileForTest("/proc/self/mountinfo", SignalResult.success(
                "20 1 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n"
                        + "21 1 0:18 / /dev rw - tmpfs tmpfs rw\n"));

        DetectionResult result = new MountAnalysisDetector(null, snapshot).call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertEquals(DetectionExecutionStatus.SAFE, result.getExecutionStatus());
        assertTrue(result.getDetails().isEmpty());
    }

    @Test
    public void mountAnalysisDetectorPartialCoverageWhenOneProcFileUnreadable() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedTextFileForTest("/proc/mounts", SignalResult.success(
                "/dev/block/dm-0 /system ext4 ro 0 0\n"));
        snapshot.seedTextFileForTest("/proc/self/mountinfo",
                SignalResult.unavailable("file_unreadable"));

        DetectionResult result = new MountAnalysisDetector(null, snapshot).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, result.getExecutionStatus());
        assertEquals(2, result.getChecksAttempted());
        assertEquals(1, result.getChecksSucceeded());
        assertEquals(1, result.getChecksFailed());
    }

    @Test
    public void mountAnalysisDetectorTotalFailureReturnsUnavailable() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedTextFileForTest("/proc/mounts", SignalResult.unavailable("EACCES"));
        snapshot.seedTextFileForTest("/proc/self/mountinfo", SignalResult.error("IOException"));

        DetectionResult result = new MountAnalysisDetector(null, snapshot).call();
        assertEquals(DetectionExecutionStatus.UNAVAILABLE, result.getExecutionStatus());
        assertEquals(RiskLevel.UNKNOWN, result.getRiskLevel());
        assertEquals(DetectionStatus.UNKNOWN, result.getStatus());
    }

    @Test
    public void mountAnalysisDetectorParsesNativeForensicsStrongAndMediumTiers() {
        SignalSnapshot cleanProc = new SignalSnapshot(null);
        cleanProc.seedTextFileForTest("/proc/mounts", SignalResult.success(
                "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"));
        cleanProc.seedTextFileForTest("/proc/self/mountinfo", SignalResult.success(
                "20 1 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n"));

        // Strong native finding: statx STATX_MNT_ID hidden mount -> HIGH/DANGER/8
        MountAnalysisDetector strongDetector = new MountAnalysisDetector(
                null, cleanProc, false,
                () -> SignalResult.success(
                        "status=OK\terrno=0\tstatx_supported=1\tmtime_checked=1\n"
                                + "kind=statx_mnt_id_hidden\tpath=/system/bin\tmnt_id=918"));
        DetectionResult strong = strongDetector.call();
        assertEquals(RiskLevel.HIGH, strong.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, strong.getStatus());
        assertEquals(8, strong.getScore());
        assertFalse(strong.isInformational());
        assertTrue(strong.getDetails().contains("native:statx_mnt_id_hidden:/system/bin"));
        assertTrue(strong.getEvidenceItems().stream().anyMatch(
                i -> "statx_mnt_id_hidden".equals(i.getCode())
                        && i.getPrimarySource() == EvidenceItem.SourceLayer.NATIVE
                        && "root_fw".equals(i.getEvidenceFamily())
                        && i.getRank() == EvidenceItem.Rank.STRONG));

        // Medium native findings: RO rw + st_mtime mismatch + statfs overlay/tmpfs -> MEDIUM/WARNING/4
        MountAnalysisDetector mediumDetector = new MountAnalysisDetector(
                null, cleanProc, false,
                () -> SignalResult.success(
                        "status=OK\terrno=0\tstatx_supported=1\tmtime_checked=1\n"
                                + "kind=system_ro_rw_mount\tpath=/vendor/bin\tfs=ext4\topts=rw,relatime\n"
                                + "kind=mount_mtime_mismatch\tmounts=100\tmountinfo=105\tmountstats=100\n"
                                + "kind=statfs_overlay_on_system\tpath=/system/bin\tmagic=0x794c7630\n"
                                + "kind=statfs_tmpfs_on_system\tpath=/system/etc/security/cacerts\tmagic=0x01021994"));
        DetectionResult medium = mediumDetector.call();
        assertEquals(RiskLevel.MEDIUM, medium.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, medium.getStatus());
        assertEquals(4, medium.getScore());
        assertTrue(medium.getDetails().contains("native:system_ro_rw_mount:/vendor/bin"));
        assertTrue(medium.getDetails().contains("native:mount_mtime_mismatch"));
        assertTrue(medium.getDetails().contains("native:statfs_overlay_on_system:/system/bin"));
        assertTrue(medium.getDetails().contains("native:statfs_tmpfs_on_system:/system/etc/security/cacerts"));
        assertEquals(4, medium.getEvidenceItems().size());
        assertTrue(medium.getEvidenceItems().stream()
                .allMatch(i -> "root_fw".equals(i.getEvidenceFamily())
                        && i.getPrimarySource() == EvidenceItem.SourceLayer.NATIVE));
    }

    @Test
    public void mountAnalysisDetectorRoutesIsolatedDiffInPostponedPassAndDedupesWithRoot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedTextFileForTest("/proc/mounts", SignalResult.success(
                "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"));
        snapshot.seedTextFileForTest("/proc/self/mountinfo", SignalResult.success(
                "20 1 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n"));

        MountViewNormalizer.MountDiffResult diff = MountViewNormalizer.diffViews(
                List.of("20 1 253:0 / /system ro shared:1 - ext4 /dev/block/dm-0 ro"),
                List.of(
                        "20 1 253:0 / /system ro shared:1 - ext4 /dev/block/dm-0 ro",
                        "99 20 0:55 / /system/bin ro shared:2 - overlay KSU lowerdir=/data/adb/modules/x"));
        snapshot.seedIsolatedMountReportForTest(
                SignalResult.success(new IsolatedProbeClient.IsolatedMountReport(diff, 12L)));

        MountAnalysisDetector detector = new MountAnalysisDetector(
                null, snapshot, true, () -> SignalResult.unavailable("jvm_test"));
        assertTrue(detector.hasPostponedProbes());

        DetectionResult fast = detector.call();
        assertEquals(RiskLevel.SAFE, fast.getRiskLevel());
        assertTrue(fast.getDetails().isEmpty());

        DetectionResult postponed = detector.callPostponed(fast);
        assertEquals(RiskLevel.HIGH, postponed.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, postponed.getStatus());
        assertEquals(8, postponed.getScore());
        assertFalse(postponed.isInformational());
        assertTrue(postponed.getDetails().stream().anyMatch(d -> d.startsWith("isolated_mount_diff:root:")));
        assertTrue(postponed.getEvidenceItems().stream().anyMatch(
                i -> "isolated_mount_diff".equals(i.getCode())
                        && i.getPrimarySource() == EvidenceItem.SourceLayer.ISOLATED
                        && "root_fw".equals(i.getEvidenceFamily())
                        && i.getRank() == EvidenceItem.Rank.STRONG));

        // Disabled config leaves fast result untouched.
        MountAnalysisDetector disabledDetector = new MountAnalysisDetector(
                null, snapshot, false, () -> SignalResult.unavailable("jvm_test"));
        DetectionResult disabledPost = disabledDetector.callPostponed(fast);
        assertEquals(RiskLevel.SAFE, disabledPost.getRiskLevel());

        // Deduplication with RootDetector in root_fw must prevent double-scoring.
        DetectionResult rootHit = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                List.of("su_found:/system/bin/su"), "su_found:/system/bin/su");
        List<DetectionResult> deduped = CorrelationEngine.dedupeFamilies(List.of(rootHit, postponed));
        assertFalse(deduped.get(0).isInformational());
        assertTrue(deduped.get(1).isInformational());
    }

    @Test
    public void mountAnalysisDetectorExemptsStockHyperOsReadOnlyOemOverlayWhileCatchingModuleOverlay() {
        // Xiaomi 15 HyperOS stock read-only /mi_ext -> /product/app overlay must stay SAFE.
        SignalSnapshot hyperOs = new SignalSnapshot(null);
        hyperOs.seedTextFileForTest("/proc/mounts", SignalResult.success(
                "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"
                        + "overlay /product/app overlay ro,seclabel,relatime,lowerdir=/mi_ext/product/app:/product/app 0 0\n"));
        hyperOs.seedTextFileForTest("/proc/self/mountinfo", SignalResult.success(
                "20 1 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n"
                        + "88 20 0:51 / /product/app ro,relatime shared:30 - overlay overlay ro,seclabel,lowerdir=/mi_ext/product/app:/product/app\n"));

        MountAnalysisDetector stockDetector = new MountAnalysisDetector(
                null, hyperOs, false,
                () -> SignalResult.success(
                        "status=OK\terrno=0\tstatx_supported=1\tmtime_checked=1\n"
                                + "kind=statfs_overlay_on_system\tpath=/product/app\tmagic=0x794c7630"));
        DetectionResult stockRes = stockDetector.call();
        assertEquals(RiskLevel.SAFE, stockRes.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, stockRes.getStatus());
        assertTrue(stockRes.getDetails().isEmpty());

        // Malicious /data/adb/modules overlay or high-sensitivity /system/bin overlay MUST still flag.
        SignalSnapshot tampered = new SignalSnapshot(null);
        tampered.seedTextFileForTest("/proc/mounts", SignalResult.success(
                "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0\n"));
        tampered.seedTextFileForTest("/proc/self/mountinfo", SignalResult.success(
                "20 1 253:0 / /system ro - ext4 /dev/block/dm-0 ro\n"
                        + "88 20 0:51 / /product/app ro,relatime shared:30 - overlay KSU ro,lowerdir=/data/adb/modules/mod/product/app:/product/app\n"
                        + "89 20 0:52 / /system/bin ro,relatime shared:31 - overlay overlay ro,lowerdir=/mi_ext/bin:/system/bin\n"));

        MountAnalysisDetector tamperedDetector = new MountAnalysisDetector(
                null, tampered, false,
                () -> SignalResult.success(
                        "status=OK\terrno=0\tstatx_supported=1\tmtime_checked=1\n"
                                + "kind=statfs_overlay_on_system\tpath=/product/app\tmagic=0x794c7630\n"
                                + "kind=statfs_overlay_on_system\tpath=/system/bin\tmagic=0x794c7630"));
        DetectionResult tamperedRes = tamperedDetector.call();
        assertEquals(RiskLevel.MEDIUM, tamperedRes.getRiskLevel());
        assertTrue(tamperedRes.getDetails().contains("native:statfs_overlay_on_system:/product/app"));
        assertTrue(tamperedRes.getDetails().contains("native:statfs_overlay_on_system:/system/bin"));
    }

    private static SignalSnapshot cleanRootSnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        seedAllRootPaths(snapshot, SignalResult.success(false));
        snapshot.seedSelinuxEnforceForTest(SignalResult.success(1));
        snapshot.seedNativeRootEvidenceForTest(SignalResult.success(""));
        return snapshot;
    }

    private static void seedAllRootPaths(SignalSnapshot snapshot, SignalResult<Boolean> outcome) {
        String[][] groups = {
                DetectionLists.SU_PATHS,
                DetectionLists.MAGISK_PATHS,
                DetectionLists.KERNELSU_PATHS,
                DetectionLists.APATCH_PATHS,
                DetectionLists.MODULE_PATHS
        };
        for (String[] group : groups) {
            for (String path : group) {
                snapshot.seedPathExistsForTest(path, outcome);
            }
        }
    }
}
