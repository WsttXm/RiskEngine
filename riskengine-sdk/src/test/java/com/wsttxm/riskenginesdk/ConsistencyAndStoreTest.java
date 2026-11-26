package com.wsttxm.riskenginesdk;

import android.content.SharedPreferences;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.attestation.AttestationRecord;
import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.FingerprintStore;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.ConsistencyDetector;
import com.wsttxm.riskenginesdk.detector.probe.consistency.BootloaderProbe;
import com.wsttxm.riskenginesdk.detector.probe.consistency.PlayIntegrityFixProbe;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class ConsistencyAndStoreTest {

    // ==================== ConsistencyDetector ====================

    @Test
    public void consistencyDetectorTruePositiveOnCrossBrandPartitionSpoofing() {
        SignalSnapshot snapshot = cleanConsistencySnapshot();
        snapshot.seedSystemPropertyForTest("ro.vendor.build.fingerprint",
                SignalResult.success("xiaomi/fuxi/fuxi:14/UKQ1/123:user/release-keys"));

        DetectionResult result = new ConsistencyDetector(null, snapshot).call();
        assertEquals("consistency", result.getDetectorName());
        assertEquals(RiskLevel.HIGH, result.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, result.getStatus());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().stream().anyMatch(
                d -> d.contains("partition_fingerprint_mismatch:brand_conflict")));
    }

    @Test
    public void consistencyDetectorTruePositiveMediumOnConfirmedBootloaderUnlock() {
        SignalSnapshot snapshot = cleanConsistencySnapshot();
        snapshot.seedSystemPropertyForTest("ro.boot.flash.locked", SignalResult.success("0"));
        snapshot.seedSystemPropertyForTest("ro.boot.verifiedbootstate", SignalResult.success("orange"));
        snapshot.seedProcCmdlineBootPropsForTest(SignalResult.success(Map.of(
                "androidboot.flash.locked", "0",
                "androidboot.verifiedbootstate", "orange")));

        DetectionResult result = new ConsistencyDetector(null, snapshot).call();
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, result.getStatus());
        assertTrue(result.isInformational());
        assertTrue(result.getDetails().contains("bootloader_unlocked"));
        assertTrue(result.getDetails().contains("verified_boot_state:orange"));
    }

    @Test
    public void consistencyDetectorFalsePositiveGuardOnCleanTrebleDevice() {
        DetectionResult result = new ConsistencyDetector(
                null, cleanConsistencySnapshot()).call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertTrue(result.getDetails().isEmpty());
    }

    @Test
    public void consistencyDetectorPartialAndTotalFailureSemantics() {
        SignalSnapshot partialSnap = cleanConsistencySnapshot();
        for (String prop : DetectionLists.PARTITION_FINGERPRINT_PROPERTIES) {
            partialSnap.seedSystemPropertyForTest(prop, SignalResult.unavailable("EACCES"));
        }
        DetectionResult partial = new ConsistencyDetector(null, partialSnap).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, partial.getExecutionStatus());
        assertTrue(partial.getChecksFailed() >= 1);

        SignalSnapshot totalFailSnap = new SignalSnapshot(null);
        for (String prop : DetectionLists.PARTITION_FINGERPRINT_PROPERTIES) {
            totalFailSnap.seedSystemPropertyForTest(prop, SignalResult.unavailable("native_unavailable"));
        }
        String[] extraProps = {
                "ro.product.model", "ro.product.brand", "ro.product.device",
                "ro.product.manufacturer", "ro.build.version.sdk", "ro.build.version.release",
                "ro.boot.flash.locked", "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state",
                "ro.debuggable", "ro.secure"
        };
        for (String prop : extraProps) {
            totalFailSnap.seedSystemPropertyForTest(prop, SignalResult.unavailable("native_unavailable"));
        }
        totalFailSnap.seedProcCmdlineBootPropsForTest(SignalResult.unavailable("native_unavailable"));
        totalFailSnap.seedKernelInfoForTest(SignalResult.unavailable("native_unavailable"));
        totalFailSnap.seedPossibleCpuCoreCountForTest(SignalResult.unavailable("unavailable"));
        totalFailSnap.seedTextFileForTest("/proc/cpuinfo", SignalResult.unavailable("unreadable"));
        totalFailSnap.seedSelfMapsForTest(SignalResult.unavailable("unreadable"));
        totalFailSnap.seedBionicPropForensicsForTest(SignalResult.unavailable("native_unavailable"));

        DetectionResult totalFail = new ConsistencyDetector(null, totalFailSnap).call();
        assertEquals(DetectionExecutionStatus.UNAVAILABLE, totalFail.getExecutionStatus());
        assertEquals(RiskLevel.UNKNOWN, totalFail.getRiskLevel());
        assertEquals(0, totalFail.getChecksSucceeded());

        // Regression guard: checkCoreCount must read /proc/cpuinfo through SignalSnapshot
        // rather than bypassing it via direct host procfs I/O.
        totalFailSnap.seedTextFileForTest("/proc/cpuinfo", SignalResult.success("processor\t: 0\n"));
        DetectionResult cpuinfoOnly = new ConsistencyDetector(null, totalFailSnap).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, cpuinfoOnly.getExecutionStatus());
        assertEquals(1, cpuinfoOnly.getChecksSucceeded());
    }

    @Test
    public void consistencyDetectorEmitsStructuredEvidenceItemsAcrossFamilies() {
        SignalSnapshot snapshot = cleanConsistencySnapshot();
        snapshot.seedSystemPropertyForTest("ro.vendor.build.fingerprint",
                SignalResult.success("xiaomi/fuxi/fuxi:14/UKQ1/123:user/release-keys"));
        snapshot.seedSystemPropertyForTest("ro.boot.flash.locked", SignalResult.success("0"));
        snapshot.seedSystemPropertyForTest("ro.boot.verifiedbootstate", SignalResult.success("orange"));
        snapshot.seedProcCmdlineBootPropsForTest(SignalResult.success(Map.of(
                "androidboot.flash.locked", "0",
                "androidboot.verifiedbootstate", "orange")));

        DetectionResult result = new ConsistencyDetector(null, snapshot).call();
        assertEquals(RiskLevel.HIGH, result.getRiskLevel());
        assertFalse(result.getEvidenceItems().isEmpty());
        assertTrue(result.getEvidenceItems().stream().anyMatch(
                i -> "prop_tamper".equals(i.getEvidenceFamily())
                        && "partition_fingerprint_mismatch".equals(i.getCode())));
        assertTrue(result.getEvidenceItems().stream().anyMatch(
                i -> "boot_integrity".equals(i.getEvidenceFamily())
                        && "bootloader_unlocked".equals(i.getCode())));
    }

    @Test
    public void consistencyDetectorIntegratesBionicPropProbeIntoPropTamperFamily() {
        SignalSnapshot snapshot = cleanConsistencySnapshot();
        snapshot.seedBionicPropForensicsForTest(SignalResult.success(
                "status=OK\terrno=0\tareas_scanned=4\tro_checked=18\n"
                        + "kind=serial_modified\tprop=ro.boot.verifiedbootstate\twrite_count=2\tserial=0x00000004\n"
                        + "kind=hole\tcontext=u:object_r:adbd_config_prop:s0\thigh_priority=1\tcount=1\tranges=128..256"));

        DetectionResult result = new ConsistencyDetector(null, snapshot).call();
        assertEquals(RiskLevel.HIGH, result.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, result.getStatus());
        assertFalse(result.isInformational());
        assertTrue(result.getDetails().stream().anyMatch(
                d -> d.contains("prop_ro_serial_modified")));
        assertTrue(result.getEvidenceItems().stream().anyMatch(
                i -> "prop_tamper".equals(i.getEvidenceFamily())
                        && "prop_ro_serial_modified".equals(i.getCode())
                        && i.getRank() == EvidenceItem.Rank.STRONG));
        assertTrue(result.getEvidenceItems().stream().anyMatch(
                i -> "prop_tamper".equals(i.getEvidenceFamily())
                        && "prop_area_hole_critical".equals(i.getCode())));
    }

    @Test
    public void playIntegrityFixProbeDetectsSpoofPropsAndMapsWhileSanitizingInstallTokens() {
        // Random Base64 install tokens containing PIF-like substrings must NOT false-positive.
        List<String> cleanMaps = List.of(
                "70000000-70010000 r-xp 00000000 fd:00 123 /data/app/~~pihooksAbCdEfGhIjKlMn==/com.example.bank-pixelprops1234567890==/oat/arm64/base.odex",
                "70020000-70030000 r-xp 00000000 fd:00 124 /system/lib64/libkeystore2.so"
        );
        PlayIntegrityFixProbe.ProbeResult clean = PlayIntegrityFixProbe.evaluate(
                true, Collections.emptyMap(), cleanMaps);
        assertTrue(clean.isUsable());
        assertFalse(clean.hasAny());

        // Real PIF module path + active properties must trigger STRONG prop_tamper evidence.
        SignalSnapshot snapshot = cleanConsistencySnapshot();
        snapshot.seedSelfMapsForTest(SignalResult.success(List.of(
                "71000000-71020000 r-xp 00000000 fd:00 999 /data/adb/modules/playintegrityfix/zygisk/arm64-v8a.so (deleted)"
        )));
        ConsistencyDetector.NativeConsistencySource source = stubNativeSource(
                SignalResult.unavailable("unused"),
                SignalResult.unavailable("unused"),
                SignalResult.success("status=OK\terrno=0\tprops_scanned=100\thits=2\n"
                        + "kind=pif_prop\tkey=persist.sys.pihooks.enable\tvalue=1\n"
                        + "kind=pif_prop\tkey=persist.sys.spoof.gms\tvalue=true"),
                "6.1.75-android14"
        );

        DetectionResult result = new ConsistencyDetector(null, snapshot, source).call();
        assertEquals(RiskLevel.HIGH, result.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, result.getStatus());
        assertTrue(result.getDetails().stream().anyMatch(d -> d.startsWith("pif_prop_active:")));
        assertTrue(result.getDetails().stream().anyMatch(d -> d.startsWith("pif_maps_trace:")));
        assertTrue(result.getEvidenceItems().stream().anyMatch(
                i -> "prop_tamper".equals(i.getEvidenceFamily())
                        && "pif_maps_trace".equals(i.getCode())
                        && i.getRank() == EvidenceItem.Rank.STRONG));
    }

    @Test
    public void threeSourceKernelConsistencyDetectsSusfsSpoofAndToleratesUts64Truncation() {
        // Exact match with >64-char osrelease and 64th-byte whitespace in utsname.version must remain SAFE.
        String longOsRel = "6.1.75-android14-11-g1234567890abcdef-ab1234567890-custom-long-release-tag";
        String utsRel64 = longOsRel.substring(0, 64);
        String fullKVer = "#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2026 android-build-tag-12 extra-long-suffix";
        // Byte 63 of fullKVer is a space, so native trim produces a 63-char string.
        String utsVerTrimmed = fullKVer.substring(0, 64).trim();
        assertTrue(utsVerTrimmed.length() < 64);
        String cleanPayload = "status=OK\terrno=0"
                + "\tuname_release=" + utsRel64
                + "\tuname_version=" + utsVerTrimmed
                + "\tproc_osrelease=" + longOsRel
                + "\tproc_kversion=" + fullKVer
                + "\tproc_version=Linux version " + longOsRel + " (build@host) (clang) " + fullKVer;
        ConsistencyDetector.NativeConsistencySource cleanSource = stubNativeSource(
                SignalResult.unavailable("unused"),
                SignalResult.success(cleanPayload),
                SignalResult.unavailable("unused"),
                utsRel64
        );
        DetectionResult cleanRes = new ConsistencyDetector(
                null, cleanConsistencySnapshot(), cleanSource).call();
        assertEquals(RiskLevel.SAFE, cleanRes.getRiskLevel());
        assertTrue(cleanRes.getDetails().isEmpty());

        // SUSFS spoofed uname.release diverging from /proc/sys/kernel/osrelease & Java os.version.
        String spoofPayload = "status=OK\terrno=0"
                + "\tuname_release=6.1.75-gki-clean"
                + "\tuname_version=#1 SMP PREEMPT"
                + "\tproc_osrelease=6.1.75-ksu-dirty"
                + "\tproc_kversion=#1 SMP PREEMPT"
                + "\tproc_version=Linux version 6.1.75-ksu-dirty (build@host) #1 SMP PREEMPT";
        ConsistencyDetector.NativeConsistencySource spoofSource = stubNativeSource(
                SignalResult.unavailable("unused"),
                SignalResult.success(spoofPayload),
                SignalResult.unavailable("unused"),
                "6.1.75-ksu-dirty"
        );
        DetectionResult spoofRes = new ConsistencyDetector(
                null, cleanConsistencySnapshot(), spoofSource).call();
        assertEquals(RiskLevel.HIGH, spoofRes.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, spoofRes.getStatus());
        assertTrue(spoofRes.getDetails().contains("kernel_uname_osrelease_mismatch"));
        assertTrue(spoofRes.getDetails().contains("kernel_uname_proc_version_mismatch"));
        assertTrue(spoofRes.getDetails().contains("kernel_java_os_version_mismatch"));
        assertTrue(spoofRes.getEvidenceItems().stream().anyMatch(
                i -> "hw_spoof".equals(i.getEvidenceFamily())
                        && "kernel_uname_osrelease_mismatch".equals(i.getCode())));
    }

    @Test
    public void consistencyDetectorPostponedMidrEl1ElevatesOnHardwareMismatchAndIgnoresUnsupported() {
        ConsistencyDetector.NativeConsistencySource mismatchSource = stubNativeSource(
                SignalResult.success("status=OK\terrno=0\tcores_checked=8\tverified_cores=8\tcpuid_emulation=1\n"
                        + "kind=midr_sysfs_mismatch\tcpu=0\tmrs=0x411fd050\tsysfs=0x51af8014"),
                SignalResult.unavailable("unused"),
                SignalResult.unavailable("unused"),
                ""
        );
        ConsistencyDetector detector = new ConsistencyDetector(
                null, cleanConsistencySnapshot(), mismatchSource);
        assertTrue(detector.hasPostponedProbes());

        DetectionResult fastResult = detector.call();
        assertEquals(RiskLevel.SAFE, fastResult.getRiskLevel());

        DetectionResult finalResult = detector.callPostponed(fastResult);
        assertEquals(RiskLevel.HIGH, finalResult.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, finalResult.getStatus());
        assertFalse(finalResult.isInformational());
        assertTrue(finalResult.getDetails().contains("midr_sysfs_mismatch:cpu0"));
        assertTrue(finalResult.getEvidenceItems().stream().anyMatch(
                i -> "hw_spoof".equals(i.getEvidenceFamily())
                        && "midr_sysfs_mismatch".equals(i.getCode())
                        && i.getRank() == EvidenceItem.Rank.STRONG));

        // Non-ARM64 UNSUPPORTED must not degrade or add findings.
        ConsistencyDetector.NativeConsistencySource nonArm64Source = stubNativeSource(
                SignalResult.success("status=UNSUPPORTED\terrno=0\treason=non_arm64"),
                SignalResult.unavailable("unused"),
                SignalResult.unavailable("unused"),
                ""
        );
        ConsistencyDetector nonArm64Detector = new ConsistencyDetector(
                null, cleanConsistencySnapshot(), nonArm64Source);
        DetectionResult unchanged = nonArm64Detector.callPostponed(fastResult);
        assertEquals(RiskLevel.SAFE, unchanged.getRiskLevel());
        assertTrue(unchanged.getDetails().isEmpty());
    }

    @Test
    public void consistencyDetectorAllowsStockXiaomi15HyperOsMissiAndQssiPartitionsWhileCatchingCrossOemSpoof() {
        // Stock Xiaomi 15 (HyperOS 2): device fingerprint (dada) + MISSI system + QTI/Redmi partitions -> SAFE.
        SignalSnapshot xiaomi15 = cleanConsistencySnapshot();
        xiaomi15.seedSystemPropertyForTest("ro.build.fingerprint",
                SignalResult.success("Xiaomi/dada/dada:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));
        xiaomi15.seedSystemPropertyForTest("ro.system.build.fingerprint",
                SignalResult.success("Xiaomi/missi/missi:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));
        xiaomi15.seedSystemPropertyForTest("ro.vendor.build.fingerprint",
                SignalResult.success("qti/qssi/qssi:15/AQ3A.240627.003/123456:user/release-keys"));
        xiaomi15.seedSystemPropertyForTest("ro.odm.build.fingerprint",
                SignalResult.success("Redmi/dada/dada:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));
        xiaomi15.seedSystemPropertyForTest("ro.product.build.fingerprint",
                SignalResult.success("Xiaomi/dada/dada:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));
        xiaomi15.seedSystemPropertyForTest("ro.system_ext.build.fingerprint",
                SignalResult.success("Xiaomi/missi/missi:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));
        xiaomi15.seedSystemPropertyForTest("ro.bootimage.build.fingerprint",
                SignalResult.success("Xiaomi/dada/dada:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));

        DetectionResult stockResult = new ConsistencyDetector(null, xiaomi15).call();
        assertEquals(RiskLevel.SAFE, stockResult.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, stockResult.getStatus());
        assertTrue(stockResult.getDetails().isEmpty());

        // Cross-OEM PlayIntegrityFix spoofing (ro.build.fingerprint spoofed to Google Pixel on Xiaomi device) -> HIGH.
        SignalSnapshot pifSpoofed = cleanConsistencySnapshot();
        pifSpoofed.seedSystemPropertyForTest("ro.build.fingerprint",
                SignalResult.success("google/akita/akita:15/AP3A.241105.007/12470370:user/release-keys"));
        pifSpoofed.seedSystemPropertyForTest("ro.system.build.fingerprint",
                SignalResult.success("Xiaomi/missi/missi:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));
        pifSpoofed.seedSystemPropertyForTest("ro.vendor.build.fingerprint",
                SignalResult.success("Xiaomi/dada/dada:15/AQ3A.240627.003/OS2.0.105.0.VOCCNXM:user/release-keys"));

        DetectionResult spoofResult = new ConsistencyDetector(null, pifSpoofed).call();
        assertEquals(RiskLevel.HIGH, spoofResult.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, spoofResult.getStatus());
        assertTrue(spoofResult.getDetails().stream().anyMatch(
                d -> d.startsWith("partition_fingerprint_mismatch:")));
    }

    @Test
    public void bootloaderProbeCatchesSpecterEmptyVbmetaSha256AndSha512AndTriggersHardReport() {
        // 1. Specter SHA-256("") in ro.boot.vbmeta.digest while props claim green + locked
        SignalSnapshot sha256Snap = cleanConsistencySnapshot();
        sha256Snap.seedSystemPropertyForTest(
                "ro.boot.vbmeta.digest", SignalResult.success(BootloaderProbe.EMPTY_SHA256_HEX));
        DetectionResult res256 = new ConsistencyDetector(null, sha256Snap).call();
        assertEquals(RiskLevel.HIGH, res256.getRiskLevel());
        assertFalse(res256.isInformational());
        assertTrue(res256.getDetails().contains("vbmeta_empty_input_digest:ro.boot.vbmeta.digest"));
        assertTrue(res256.getDetails().contains("spoofed_verified_boot_props"));

        // Hard trigger in RiskReport -> DEADLY
        RiskReport report256 = new RiskReport(new DeviceFingerprint(), Collections.singletonList(res256));
        assertEquals(RiskLevel.DEADLY, report256.getOverallRiskLevel());

        // 2. Empty SHA-512("") inside hardware RootOfTrust.verifiedBootHash
        SignalSnapshot sha512Snap = cleanConsistencySnapshot();
        byte[] empty512 = hexToBytes(BootloaderProbe.EMPTY_SHA512_HEX);
        AttestationRecord rec512 = AttestationRecord.builder()
                .valid(true).challengeMatched(true)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .rootOfTrust(new AttestationRecord.RootOfTrust(
                        new byte[32], true, AttestationRecord.VerifiedBootState.VERIFIED, empty512, true))
                .build();
        sha512Snap.seedAttestationSnapshotForTest(SignalResult.success(
                AttestationCapability.AttestationSnapshot.builder().available(true).record(rec512).build()));
        ConsistencyDetector det512 = new ConsistencyDetector(null, sha512Snap);
        DetectionResult post512 = det512.callPostponed(det512.call());
        assertEquals(RiskLevel.HIGH, post512.getRiskLevel());
        assertTrue(post512.getDetails().contains("vbmeta_empty_input_digest:root_of_trust"));
    }

    @Test
    public void hardwareRootOfTrustUnlockScoresMedium5InStandardHigh7InLoginAndC8DeadlyWhenSpoofed() {
        // 1. Honest unlocked device (props & hardware agree unlocked/orange): actionable MEDIUM/5 in STANDARD -> HIGH/7 in LOGIN
        SignalSnapshot honestUnlocked = cleanConsistencySnapshot();
        honestUnlocked.seedSystemPropertyForTest("ro.boot.flash.locked", SignalResult.success("0"));
        honestUnlocked.seedSystemPropertyForTest("ro.boot.verifiedbootstate", SignalResult.success("orange"));
        honestUnlocked.seedProcCmdlineBootPropsForTest(SignalResult.success(Map.of(
                "androidboot.flash.locked", "0",
                "androidboot.verifiedbootstate", "orange")));
        AttestationRecord hwUnlockedRec = AttestationRecord.builder()
                .valid(true).challengeMatched(true)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT)
                .rootOfTrust(new AttestationRecord.RootOfTrust(
                        new byte[32], false, AttestationRecord.VerifiedBootState.UNVERIFIED, null, true))
                .build();
        honestUnlocked.seedAttestationSnapshotForTest(SignalResult.success(
                AttestationCapability.AttestationSnapshot.builder().available(true).record(hwUnlockedRec).build()));

        ConsistencyDetector detHonest = new ConsistencyDetector(null, honestUnlocked);
        DetectionResult stdPost = detHonest.callPostponed(detHonest.call());
        assertEquals(RiskLevel.MEDIUM, stdPost.getRiskLevel());
        assertEquals(5, stdPost.getScore());
        assertFalse("Hardware-confirmed unlock must be actionable in STANDARD", stdPost.isInformational());
        assertTrue(stdPost.getDetails().contains("key_attestation:bootloader_unlocked"));
        assertTrue(stdPost.getDetails().contains("key_attestation:verified_boot_orange"));
        assertFalse("Honest unlocked props must NOT trigger spoofed_verified_boot_props",
                stdPost.getDetails().contains("spoofed_verified_boot_props"));

        DetectionResult loginApplied = CorrelationEngine.applyScene(stdPost, CollectScene.LOGIN);
        assertEquals(RiskLevel.HIGH, loginApplied.getRiskLevel());
        assertEquals(7, loginApplied.getScore());
        assertFalse(loginApplied.isInformational());

        // 2. Spoofed green+locked props vs hardware unlocked RootOfTrust -> C8:spoofed_verified_boot (DEADLY/10)
        SignalSnapshot spoofedSnap = cleanConsistencySnapshot(); // props say green + flash.locked=1
        spoofedSnap.seedAttestationSnapshotForTest(SignalResult.success(
                AttestationCapability.AttestationSnapshot.builder().available(true).record(hwUnlockedRec).build()));
        ConsistencyDetector detSpoof = new ConsistencyDetector(null, spoofedSnap);
        DetectionResult spoofPost = detSpoof.callPostponed(detSpoof.call());
        assertTrue(spoofPost.getDetails().contains("spoofed_verified_boot_props"));

        DetectionResult corr = CorrelationEngine.correlate(
                Collections.singletonList(spoofPost), CollectScene.STANDARD);
        assertTrue(corr != null);
        assertEquals(RiskLevel.DEADLY, corr.getRiskLevel());
        assertEquals(10, corr.getScore());
        assertTrue(corr.getDetails().contains("C8:spoofed_verified_boot"));

        RiskReport report = new RiskReport(new DeviceFingerprint(), java.util.Arrays.asList(spoofPost, corr));
        assertEquals(RiskLevel.DEADLY, report.getOverallRiskLevel());
    }

    @Test
    public void bootloaderProbeGatesSamsungWarrantyBitAndChecksBootconfigAndCleanLockedZeroFp() {
        // Non-Samsung device with ro.boot.warranty_bit=1 must NOT emit knox_warranty_void
        SignalSnapshot nonSamsung = cleanConsistencySnapshot();
        nonSamsung.seedSystemPropertyForTest("ro.product.manufacturer", SignalResult.success("Google"));
        nonSamsung.seedSystemPropertyForTest("ro.boot.warranty_bit", SignalResult.success("1"));
        DetectionResult nonSamRes = new ConsistencyDetector(null, nonSamsung).call();
        assertEquals(RiskLevel.SAFE, nonSamRes.getRiskLevel());
        assertFalse(nonSamRes.getDetails().contains("knox_warranty_void"));

        // Samsung device with ro.boot.warranty_bit=1 emits knox_warranty_void
        SignalSnapshot samsung = cleanConsistencySnapshot();
        samsung.seedSystemPropertyForTest("ro.product.manufacturer", SignalResult.success("samsung"));
        samsung.seedSystemPropertyForTest("ro.boot.warranty_bit", SignalResult.success("1"));
        DetectionResult samRes = new ConsistencyDetector(null, samsung).call();
        assertTrue(samRes.getDetails().contains("knox_warranty_void"));

        // /proc/bootconfig contradicting ro.boot.verifiedbootstate=green
        SignalSnapshot bootcfgMismatch = cleanConsistencySnapshot();
        bootcfgMismatch.seedTextFileForTest("/proc/bootconfig",
                SignalResult.success("androidboot.verifiedbootstate = \"orange\"\nandroidboot.flash.locked = \"0\"\n"));
        DetectionResult cfgRes = new ConsistencyDetector(null, bootcfgMismatch).call();
        assertEquals(RiskLevel.HIGH, cfgRes.getRiskLevel());
        assertTrue(cfgRes.getDetails().contains("bootconfig_prop_mismatch:verifiedbootstate"));
        assertTrue(cfgRes.getDetails().contains("bootconfig_prop_mismatch:flash_locked"));

        // Stock locked hardware-attested device -> 0 FP
        SignalSnapshot cleanStock = cleanConsistencySnapshot();
        byte[] realVbHash = new byte[] {
            0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0,
            0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0,
            0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0,
            0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0
        };
        cleanStock.seedSystemPropertyForTest("ro.boot.vbmeta.digest",
                SignalResult.success(AttestationRecord.toLowerHex(realVbHash)));
        AttestationRecord lockedRec = AttestationRecord.builder()
                .valid(true).challengeMatched(true)
                .attestationSecurityLevel(AttestationRecord.SecurityLevel.STRONGBOX)
                .keymasterSecurityLevel(AttestationRecord.SecurityLevel.STRONGBOX)
                .rootOfTrust(new AttestationRecord.RootOfTrust(
                        realVbHash, true, AttestationRecord.VerifiedBootState.VERIFIED, realVbHash, true))
                .build();
        cleanStock.seedAttestationSnapshotForTest(SignalResult.success(
                AttestationCapability.AttestationSnapshot.builder().available(true).record(lockedRec).build()));
        ConsistencyDetector cleanDet = new ConsistencyDetector(null, cleanStock);
        DetectionResult cleanFinal = cleanDet.callPostponed(cleanDet.call());
        assertEquals(RiskLevel.SAFE, cleanFinal.getRiskLevel());
        assertTrue(cleanFinal.getDetails().isEmpty());
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static ConsistencyDetector.NativeConsistencySource stubNativeSource(
            SignalResult<String> cpuId,
            SignalResult<String> kernelCons,
            SignalResult<String> pifProps,
            String javaOsVersion) {
        return new ConsistencyDetector.NativeConsistencySource() {
            @Override public SignalResult<String> getHardwareCpuIdentity() { return cpuId; }
            @Override public SignalResult<String> getKernelConsistency() { return kernelCons; }
            @Override public SignalResult<String> getPifProperties() { return pifProps; }
            @Override public String getJavaOsVersion() { return javaOsVersion; }
        };
    }

    // ==================== FingerprintStore ====================

    @Test
    public void fingerprintStoreLifecycleAnchorDriftAndResetPreservesSalt() {
        InMemoryPrefs prefs = new InMemoryPrefs();
        FingerprintStore store = new FingerprintStore(prefs);

        String salt = store.getOrCreateSalt();
        assertFalse(salt.isEmpty());
        assertEquals(salt, store.getOrCreateSalt());

        FingerprintId baseline = makeFp("hw_a", "sys_1", Map.of(
                "gpu", "g1", "cpu", "c1", "sensor", "s1"));
        FingerprintStore.Continuity first = store.recordAndCompare(baseline);
        assertEquals(FingerprintStore.State.FIRST_OBSERVATION, first.getState());
        assertEquals(1, first.getObservationCount());
        assertEquals(0, first.getDriftCount());

        FingerprintStore.Continuity stable = store.recordAndCompare(baseline);
        assertEquals(FingerprintStore.State.STABLE, stable.getState());
        assertEquals(2, stable.getObservationCount());
        assertEquals(0, stable.getDriftCount());

        FingerprintId spoofed = makeFp("hw_b", "sys_1", Map.of(
                "gpu", "g_tampered", "cpu", "c1", "sensor", "s1"));
        FingerprintStore.Continuity drift1 = store.recordAndCompare(spoofed);
        assertEquals(FingerprintStore.State.HARDWARE_CHANGED, drift1.getState());
        assertEquals(1, drift1.getDriftCount());
        assertTrue(drift1.getChangedBuckets().contains("gpu"));

        // Second observation with tampered hardware must STILL report HARDWARE_CHANGED.
        FingerprintStore.Continuity drift2 = store.recordAndCompare(spoofed);
        assertEquals(FingerprintStore.State.HARDWARE_CHANGED, drift2.getState());
        assertEquals(2, drift2.getDriftCount());

        // Reset baseline clears anchor/history while keeping per-install salt intact.
        store.resetBaseline();
        assertEquals(salt, store.getOrCreateSalt());
        FingerprintStore.Continuity reanchored = store.recordAndCompare(spoofed);
        assertEquals(FingerprintStore.State.FIRST_OBSERVATION, reanchored.getState());
        assertEquals(0, reanchored.getDriftCount());
    }

    private static SignalSnapshot cleanConsistencySnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        String sysFp = "google/cheetah/cheetah:14/AP2A.240805.005/12025142:user/release-keys";
        String vendorFp = "google/cheetah/cheetah:14/AP2A.240601.001/11900000:user/release-keys";
        snapshot.seedSystemPropertyForTest("ro.build.fingerprint", SignalResult.success(sysFp));
        snapshot.seedSystemPropertyForTest("ro.system.build.fingerprint", SignalResult.success(sysFp));
        snapshot.seedSystemPropertyForTest("ro.vendor.build.fingerprint", SignalResult.success(vendorFp));
        snapshot.seedSystemPropertyForTest("ro.product.build.fingerprint", SignalResult.success(sysFp));
        snapshot.seedSystemPropertyForTest("ro.odm.build.fingerprint", SignalResult.success(vendorFp));
        snapshot.seedSystemPropertyForTest("ro.bootimage.build.fingerprint", SignalResult.success(sysFp));
        snapshot.seedSystemPropertyForTest("ro.product.model", SignalResult.empty(""));
        snapshot.seedSystemPropertyForTest("ro.product.brand", SignalResult.empty(""));
        snapshot.seedSystemPropertyForTest("ro.product.device", SignalResult.empty(""));
        snapshot.seedSystemPropertyForTest("ro.product.manufacturer", SignalResult.empty(""));
        snapshot.seedSystemPropertyForTest("ro.build.version.sdk", SignalResult.empty(""));
        snapshot.seedSystemPropertyForTest("ro.build.version.release", SignalResult.empty(""));
        snapshot.seedSystemPropertyForTest("ro.boot.flash.locked", SignalResult.success("1"));
        snapshot.seedSystemPropertyForTest("ro.boot.verifiedbootstate", SignalResult.success("green"));
        snapshot.seedSystemPropertyForTest("ro.boot.vbmeta.device_state", SignalResult.success("locked"));
        snapshot.seedSystemPropertyForTest("ro.debuggable", SignalResult.success("0"));
        snapshot.seedSystemPropertyForTest("ro.secure", SignalResult.success("1"));
        snapshot.seedProcCmdlineBootPropsForTest(SignalResult.success(Map.of(
                "androidboot.flash.locked", "1",
                "androidboot.verifiedbootstate", "green")));
        snapshot.seedKernelInfoForTest(SignalResult.success("Linux 5.15.104-android14 aarch64"));
        snapshot.seedPossibleCpuCoreCountForTest(
                SignalResult.success(Runtime.getRuntime().availableProcessors()));
        return snapshot;
    }

    private static FingerprintId makeFp(String hw, String sys, Map<String, String> buckets) {
        return new FingerprintId("comp_" + hw, hw, sys, "vol_1",
                9, 13, 6, 11,
                List.of("gpu", "cpu", "sensor"),
                buckets);
    }

    private static final class InMemoryPrefs implements SharedPreferences {
        private final Map<String, Object> data = new HashMap<>();

        @Override public Map<String, ?> getAll() { return new HashMap<>(data); }
        @Override public String getString(String key, String defValue) {
            Object v = data.get(key);
            return v instanceof String ? (String) v : defValue;
        }
        @Override @SuppressWarnings("unchecked")
        public Set<String> getStringSet(String key, Set<String> defValues) {
            Object v = data.get(key);
            return v instanceof Set ? new HashSet<>((Set<String>) v) : defValues;
        }
        @Override public int getInt(String key, int defValue) {
            Object v = data.get(key);
            return v instanceof Integer ? (Integer) v : defValue;
        }
        @Override public long getLong(String key, long defValue) {
            Object v = data.get(key);
            return v instanceof Long ? (Long) v : defValue;
        }
        @Override public float getFloat(String key, float defValue) {
            Object v = data.get(key);
            return v instanceof Float ? (Float) v : defValue;
        }
        @Override public boolean getBoolean(String key, boolean defValue) {
            Object v = data.get(key);
            return v instanceof Boolean ? (Boolean) v : defValue;
        }
        @Override public boolean contains(String key) { return data.containsKey(key); }
        @Override public Editor edit() { return new InMemoryEditor(); }
        @Override public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l) {}
        @Override public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l) {}

        private final class InMemoryEditor implements Editor {
            private final Map<String, Object> pending = new HashMap<>();
            private final Set<String> removals = new HashSet<>();
            private boolean clear;

            @Override public Editor putString(String k, String v) { pending.put(k, v); return this; }
            @Override public Editor putStringSet(String k, Set<String> v) { pending.put(k, v); return this; }
            @Override public Editor putInt(String k, int v) { pending.put(k, v); return this; }
            @Override public Editor putLong(String k, long v) { pending.put(k, v); return this; }
            @Override public Editor putFloat(String k, float v) { pending.put(k, v); return this; }
            @Override public Editor putBoolean(String k, boolean v) { pending.put(k, v); return this; }
            @Override public Editor remove(String k) { removals.add(k); return this; }
            @Override public Editor clear() { clear = true; return this; }
            @Override public boolean commit() { apply(); return true; }
            @Override public void apply() {
                if (clear) data.clear();
                for (String k : removals) data.remove(k);
                data.putAll(pending);
            }
        }
    }
}
