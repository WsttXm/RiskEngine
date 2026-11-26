package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.collector.java_layer.MediaCodecCollector;
import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.AdbDetector;
import com.wsttxm.riskenginesdk.detector.CloudPhoneDetector;
import com.wsttxm.riskenginesdk.detector.CustomRomDetector;
import com.wsttxm.riskenginesdk.detector.EmulatorDetector;
import com.wsttxm.riskenginesdk.detector.MultiInstanceDetector;
import com.wsttxm.riskenginesdk.detector.probe.virtualization.SensorNoiseProbe;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.AdbInspector;

import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class EmulatorCloudRomAdbDetectorTest {

    // ==================== EmulatorDetector ====================

    @Test
    public void emulatorDetectorTruePositiveStrongSignalsProduceHighAndMedium() {
        SignalSnapshot highSnap = cleanEmulatorSnapshot();
        highSnap.seedSystemPropertyForTest("ro.kernel.qemu", SignalResult.success("1"));
        highSnap.seedCpuInfoForTest(SignalResult.success(
                "model name : QEMU Virtual CPU|flags : hypervisor vmx"));
        DetectionResult high = new EmulatorDetector(null, highSnap).call();
        assertEquals("emulator", high.getDetectorName());
        assertEquals(RiskLevel.HIGH, high.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, high.getStatus());
        assertTrue(high.getDetails().contains("qemu_prop:ro.kernel.qemu"));
        assertTrue(high.getDetails().contains("cpu:hypervisor"));

        SignalSnapshot mediumSnap = cleanEmulatorSnapshot();
        mediumSnap.seedGpuIdentityForTest(SignalResult.success(
                new SignalSnapshot.GpuIdentity("Google Inc.", "Google SwiftShader")));
        DetectionResult medium = new EmulatorDetector(null, mediumSnap).call();
        assertEquals(RiskLevel.MEDIUM, medium.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, medium.getStatus());
    }

    @Test
    public void emulatorDetectorFalsePositiveGuardAndFailureSemantics() {
        DetectionResult clean = new EmulatorDetector(null, cleanEmulatorSnapshot()).call();
        assertEquals(RiskLevel.SAFE, clean.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, clean.getStatus());
        assertTrue(clean.getDetails().isEmpty());

        SignalSnapshot failSnap = new SignalSnapshot(null);
        failSnap.seedSystemPropertyForTest("ro.kernel.qemu", SignalResult.error("EACCES"));
        failSnap.seedSystemPropertyForTest("ro.boot.qemu", SignalResult.error("EACCES"));
        failSnap.seedSystemPropertyForTest("ro.hardware.virtual", SignalResult.error("EACCES"));
        failSnap.seedSystemPropertyForTest("ro.build.characteristics", SignalResult.error("EACCES"));
        failSnap.seedCpuInfoForTest(SignalResult.error("EACCES"));
        failSnap.seedDiskSizeDataForTest(SignalResult.error("EACCES"));
        failSnap.seedKernelInfoForTest(SignalResult.error("EACCES"));
        failSnap.seedScreenMetricsForTest(SignalResult.error("EACCES"));
        failSnap.seedContainerSignalsForTest(SignalResult.error("EACCES"));
        failSnap.seedGpuIdentityForTest(SignalResult.error("EACCES"));

        DetectionResult failed = new EmulatorDetector(null, failSnap).call();
        assertNotEquals(DetectionExecutionStatus.SAFE, failed.getExecutionStatus());
        assertTrue(failed.getChecksFailed() >= 8);
    }

    @Test
    public void emulatorDetectorModernVirtualizationCatalogAndAvfJointGuard() {
        // 1. Modern emulator properties (Waydroid, Cuttlefish, WSA, Corellium, LDPlayer 9, MuMu 12)
        String[][] cases = {
                {"ro.waydroid.version", "1.4.2", "emu_prop:waydroid:ro.waydroid.version"},
                {"ro.wsa.version", "2311.40000", "emu_prop:wsa:ro.wsa.version"},
                {"ro.corellium.version", "2.0", "emu_prop:corellium:ro.corellium.version"},
                {"ro.ldplayer.version", "9.0.60", "emu_prop:ldplayer9:ro.ldplayer.version"},
                {"ro.mumu.version", "12.1", "emu_prop:mumu12:ro.mumu.version"},
                {"ro.boot.hardware", "cutf_cvm", "emu_prop:cuttlefish:ro.boot.hardware=cutf_cvm"}
        };
        for (String[] tc : cases) {
            SignalSnapshot snap = cleanEmulatorSnapshot();
            snap.seedSystemPropertyForTest(tc[0], SignalResult.success(tc[1]));
            DetectionResult res = new EmulatorDetector(null, snap).call();
            assertEquals("Expected MEDIUM for " + tc[0], RiskLevel.MEDIUM, res.getRiskLevel());
            assertTrue("Missing detail " + tc[2] + " in " + res.getDetails(),
                    res.getDetails().contains(tc[2]));
            assertTrue(res.getEvidenceItems().stream().anyMatch(
                    i -> "emu_prop".equals(i.getCode())
                            && "emulator".equals(i.getEvidenceFamily())
                            && i.getRank() == EvidenceItem.Rank.STRONG));
        }

        // 2. Anti-FP: single AVF marker (virtiofs alone or crosvm alone) MUST stay SAFE.
        SignalSnapshot singleAvf = cleanEmulatorSnapshot();
        singleAvf.seedTextFileForTest("/proc/mounts",
                SignalResult.success("virtiofs /mnt/shared virtiofs rw 0 0\n"));
        DetectionResult singleRes = new EmulatorDetector(null, singleAvf).call();
        assertEquals(RiskLevel.SAFE, singleRes.getRiskLevel());
        assertTrue(singleRes.getDetails().isEmpty());

        // 3. Joint AVF markers (authfs + virtiofs/crosvm >= 2 hits) MUST trigger STRONG.
        SignalSnapshot jointAvf = cleanEmulatorSnapshot();
        jointAvf.seedTextFileForTest("/proc/mounts",
                SignalResult.success("authfs /mnt/authfs fuse ro 0 0\nvirtiofs /mnt/apk virtiofs ro 0 0\n"));
        DetectionResult jointRes = new EmulatorDetector(null, jointAvf).call();
        assertEquals(RiskLevel.MEDIUM, jointRes.getRiskLevel());
        assertTrue(jointRes.getDetails().contains("avf_virtualization:authfs+virtiofs"));
        assertTrue(jointRes.getEvidenceItems().stream().anyMatch(
                i -> "avf_virtualization".equals(i.getCode())
                        && "emulator".equals(i.getEvidenceFamily())
                        && i.getRank() == EvidenceItem.Rank.STRONG));

        // 4. Hardware-backed ANGLE-on-Vulkan exemption remains untouched.
        SignalSnapshot angleSnap = cleanEmulatorSnapshot();
        angleSnap.seedGpuIdentityForTest(SignalResult.success(
                new SignalSnapshot.GpuIdentity("Google Inc. (Qualcomm)",
                        "ANGLE (Qualcomm, Adreno (TM) 750, OpenGL ES 3.2)")));
        DetectionResult angleRes = new EmulatorDetector(null, angleSnap).call();
        assertEquals(RiskLevel.SAFE, angleRes.getRiskLevel());
        assertTrue(angleRes.getDetails().isEmpty());
    }

    @Test
    public void emulatorDetectorNativeBridgePostponedTrapsMediaCodecAndAntiFpRules() {
        // 1. Solo sched_yield_low_cv MUST NEVER trigger standalone actionable risk in ANY scene.
        SignalSnapshot soloYieldSnap = cleanEmulatorSnapshot();
        soloYieldSnap.seedVirtualizationTrapsForTest(true, SignalResult.success(
                "status=OK\terrno=0\tpostponed=1\tnative_bridge_hits=0\tsyscall_pack_ran=1"
                        + "\tseccomp_trapped=0\ttiming_ran=1\tclock_ran=0\n"
                        + "kind=sched_yield_low_cv\tcv=0.0110\tmean_ns=1500\tsuspicious=3\tseverity=INFO"));
        EmulatorDetector soloYieldDet = new EmulatorDetector(null, soloYieldSnap);
        DetectionResult soloYieldPost = soloYieldDet.callPostponed(soloYieldDet.call());
        assertEquals(RiskLevel.SAFE, soloYieldPost.getRiskLevel());
        assertEquals(0, soloYieldPost.getScore());
        assertTrue(soloYieldPost.isInformational());
        assertEquals(0, CorrelationEngine.applyScene(soloYieldPost, CollectScene.LOGIN).getScore());
        assertEquals(0, CorrelationEngine.applyScene(soloYieldPost, CollectScene.PAYMENT).getScore());
        assertTrue(soloYieldPost.getEvidenceItems().stream().anyMatch(
                i -> "sched_yield_low_cv".equals(i.getCode())
                        && i.getRank() == EvidenceItem.Rank.INFO));

        // 2. Native Bridge (fast STRONG) + sched_yield_low_cv (postponed corroborator) -> HIGH/8.
        SignalSnapshot nbSnap = cleanEmulatorSnapshot();
        nbSnap.seedVirtualizationTrapsForTest(false, SignalResult.success(
                "status=OK\terrno=0\tpostponed=0\tnative_bridge_hits=1\tsyscall_pack_ran=0"
                        + "\tseccomp_trapped=0\ttiming_ran=0\tclock_ran=0\n"
                        + "kind=native_bridge_maps\tpath=/system/lib64/libhoudini.so"));
        nbSnap.seedVirtualizationTrapsForTest(true, SignalResult.success(
                "status=OK\terrno=0\tpostponed=1\tnative_bridge_hits=1\tsyscall_pack_ran=1"
                        + "\tseccomp_trapped=0\ttiming_ran=1\tclock_ran=0\n"
                        + "kind=native_bridge_maps\tpath=/system/lib64/libhoudini.so\n"
                        + "kind=sched_yield_low_cv\tcv=0.0100\tmean_ns=1400\tsuspicious=3\tseverity=INFO"));
        EmulatorDetector nbDet = new EmulatorDetector(null, nbSnap);
        DetectionResult nbFast = nbDet.call();
        assertEquals(RiskLevel.MEDIUM, nbFast.getRiskLevel());
        assertFalse(nbFast.isInformational());
        assertTrue(nbFast.getDetails().contains("native_bridge:native_bridge_maps:/system/lib64/libhoudini.so"));
        DetectionResult nbPost = nbDet.callPostponed(nbFast);
        assertEquals(RiskLevel.HIGH, nbPost.getRiskLevel());
        assertEquals(8, nbPost.getScore());
        assertFalse(nbPost.isInformational());

        // 3. Zero-SoC-hardware MediaCodec + postponed ARM64 clock drift -> HIGH/8.
        MediaCodecCollector.CodecSummary swOnly = MediaCodecCollector.summarize(List.of(
                new MediaCodecCollector.CodecEntry("c2.android.avc.decoder", false, true, false, List.of("video/avc")),
                new MediaCodecCollector.CodecEntry("OMX.google.aac.decoder", false, true, false, List.of("audio/mp4a-latm"))
        ));
        assertTrue(swOnly.isZeroHardwareOnly());
        MediaCodecCollector.CodecSummary hwPresent = MediaCodecCollector.summarize(List.of(
                new MediaCodecCollector.CodecEntry("c2.qti.avc.decoder", true, false, false, List.of("video/avc")),
                new MediaCodecCollector.CodecEntry("c2.android.aac.decoder", false, true, false, List.of("audio/mp4a-latm"))
        ));
        assertFalse(hwPresent.isZeroHardwareOnly());

        SignalSnapshot clockSnap = cleanEmulatorSnapshot();
        clockSnap.seedMediaCodecSummaryForTest(SignalResult.success(swOnly));
        clockSnap.seedVirtualizationTrapsForTest(true, SignalResult.success(
                "status=OK\terrno=0\tpostponed=1\tnative_bridge_hits=0\tsyscall_pack_ran=1"
                        + "\tseccomp_trapped=0\ttiming_ran=1\tclock_ran=1\n"
                        + "kind=arm64_clock_drift\tfreq=19200000\tcounter_ns=90000000\twall_ns=1000000\tsuspicious=2"));
        EmulatorDetector clockDet = new EmulatorDetector(null, clockSnap);
        DetectionResult clockPost = clockDet.callPostponed(clockDet.call());
        assertEquals(RiskLevel.HIGH, clockPost.getRiskLevel());
        assertTrue(clockPost.getDetails().stream().anyMatch(d -> d.startsWith("zero_hw_codec:")));
        assertTrue(clockPost.getDetails().stream().anyMatch(d -> d.startsWith("arm64_clock_drift:")));
    }

    @Test
    public void sensorNoiseProbeMathAndJointOnlyCorroborationInCloudAndEmulator() {
        // Real MEMS thermal jitter -> NOT zero variance.
        List<float[]> realFrames = List.of(
                new float[]{0.012f, 0.005f, 9.810f},
                new float[]{0.014f, 0.004f, 9.812f},
                new float[]{0.011f, 0.006f, 9.809f},
                new float[]{0.013f, 0.005f, 9.811f},
                new float[]{0.012f, 0.007f, 9.810f},
                new float[]{0.015f, 0.005f, 9.813f},
                new float[]{0.010f, 0.004f, 9.808f},
                new float[]{0.013f, 0.006f, 9.811f}
        );
        SensorNoiseProbe.Result realEval = SensorNoiseProbe.evaluateSamples(realFrames, "accelerometer");
        assertTrue(realEval.isAvailable());
        assertFalse(realEval.isStaticZeroVariance());

        // Insufficient frames (< 8) -> NOT zero variance.
        List<float[]> shortConstant = Collections.nCopies(7, new float[]{0f, 0f, 9.8f});
        assertFalse(SensorNoiseProbe.evaluateSamples(shortConstant, "accelerometer").isStaticZeroVariance());

        // 10 exact constant frames -> staticZeroVariance == true.
        List<float[]> syntheticFrames = Collections.nCopies(10, new float[]{0f, 0f, 9.8f});
        SensorNoiseProbe.Result synthEval = SensorNoiseProbe.evaluateSamples(syntheticFrames, "accelerometer");
        assertTrue(synthEval.isAvailable());
        assertTrue(synthEval.isStaticZeroVariance());
        assertEquals(0.0, synthEval.getStdX(), 0.0);
        assertEquals(0.0, synthEval.getStdY(), 0.0);
        assertEquals(0.0, synthEval.getStdZ(), 0.0);

        SensorNoiseProbe.SensorFrameSampler zeroVarSampler = (ctx, win) -> synthEval;

        // Anti-FP: solo static sensor zero-variance on clean device MUST stay SAFE in BOTH detectors!
        EmulatorDetector cleanEmu = new EmulatorDetector(null, cleanEmulatorSnapshot(), zeroVarSampler);
        DetectionResult cleanEmuPost = cleanEmu.callPostponed(cleanEmu.call());
        assertEquals(RiskLevel.SAFE, cleanEmuPost.getRiskLevel());
        assertTrue(cleanEmuPost.getDetails().isEmpty());

        CloudPhoneDetector cleanCloud = new CloudPhoneDetector(null, cleanCloudSnapshot(), zeroVarSampler);
        DetectionResult cleanCloudPost = cleanCloud.callPostponed(cleanCloud.call());
        assertEquals(RiskLevel.SAFE, cleanCloudPost.getRiskLevel());
        assertTrue(cleanCloudPost.getDetails().isEmpty());

        // Joint corroboration: wired_interface + static sensor zero-variance -> CloudPhone MEDIUM/4 actionable.
        SignalSnapshot cloudJointSnap = cleanCloudSnapshot();
        cloudJointSnap.seedNetworkInterfaceNamesForTest(SignalResult.success(List.of("eth0", "lo")));
        CloudPhoneDetector jointCloud = new CloudPhoneDetector(null, cloudJointSnap, zeroVarSampler);
        DetectionResult cloudFast = jointCloud.call();
        assertEquals(RiskLevel.LOW, cloudFast.getRiskLevel());
        assertTrue(cloudFast.isInformational());
        DetectionResult cloudPost = jointCloud.callPostponed(cloudFast);
        assertEquals(RiskLevel.MEDIUM, cloudPost.getRiskLevel());
        assertEquals(4, cloudPost.getScore());
        assertFalse(cloudPost.isInformational());
        assertTrue(cloudPost.getDetails().contains("sensor_static_zero_var:accelerometer:10"));
        assertTrue(cloudPost.getEvidenceItems().stream().anyMatch(
                i -> "sensor_static_zero_var".equals(i.getCode())
                        && "emulator".equals(i.getEvidenceFamily())));

        // CloudPhone zero-hardware MediaCodec + wired_interface -> MEDIUM/4 + emulator family EvidenceItems.
        SignalSnapshot codecCloudSnap = cleanCloudSnapshot();
        codecCloudSnap.seedNetworkInterfaceNamesForTest(SignalResult.success(List.of("eth0", "lo")));
        codecCloudSnap.seedMediaCodecSummaryForTest(SignalResult.success(
                new MediaCodecCollector.CodecSummary(4, 0, 4, 0)));
        DetectionResult codecCloud = new CloudPhoneDetector(null, codecCloudSnap).call();
        assertEquals(RiskLevel.MEDIUM, codecCloud.getRiskLevel());
        assertEquals(4, codecCloud.getScore());
        assertFalse(codecCloud.isInformational());
        assertTrue(codecCloud.getDetails().stream().anyMatch(d -> d.startsWith("zero_hw_codec:")));
        assertTrue(codecCloud.getEvidenceItems().stream().allMatch(
                i -> "emulator".equals(i.getEvidenceFamily())));
    }

    @Test
    public void multiInstanceDetectorPostponedConsumesSacrificialSyscallPack() {
        MultiInstanceDetector.MultiInstanceEnvironment cleanEnv =
                new MultiInstanceDetector.MultiInstanceEnvironment() {
                    @Override public String getPackageName() { return "com.example.app"; }
                    @Override public int getMyUid() { return 10200; }
                    @Override public String getFilesDirPath() { return "/data/user/0/com.example.app/files"; }
                    @Override public String getDataDirPath() { return "/data/user/0/com.example.app"; }
                    @Override public String getSourceDirPath() { return "/data/app/~~abc==/com.example.app-xyz==/base.apk"; }
                    @Override public int statUid(String path) { return 10200; }
                    @Override public java.util.Map<String, String> inspectDynamicBinderProxies() { return Collections.emptyMap(); }
                };

        // 1. Clean / seccomp-trapped disposable child -> remains SAFE.
        SignalSnapshot cleanSnap = new SignalSnapshot(null);
        cleanSnap.seedSelfMapsForTest(SignalResult.success(Collections.emptyList()));
        cleanSnap.seedVirtualizationTrapsForTest(true, SignalResult.success(
                "status=OK\terrno=0\tpostponed=1\tnative_bridge_hits=0\tsyscall_pack_ran=1"
                        + "\tseccomp_trapped=1\ttiming_ran=1\tclock_ran=0"));
        MultiInstanceDetector cleanDet = MultiInstanceDetector.createForTest(null, cleanSnap, cleanEnv);
        assertTrue(cleanDet.hasPostponedProbes());
        DetectionResult cleanPost = cleanDet.callPostponed(cleanDet.call());
        assertEquals(RiskLevel.SAFE, cleanPost.getRiskLevel());
        assertEquals(0, cleanPost.getScore());

        // 2. Confirmed sacrificial_syscall_mismatch -> actionable MEDIUM/5 under virtual_container.
        SignalSnapshot hookSnap = new SignalSnapshot(null);
        hookSnap.seedSelfMapsForTest(SignalResult.success(Collections.emptyList()));
        hookSnap.seedVirtualizationTrapsForTest(true, SignalResult.success(
                "status=OK\terrno=0\tpostponed=1\tnative_bridge_hits=0\tsyscall_pack_ran=1"
                        + "\tseccomp_trapped=0\ttiming_ran=1\tclock_ran=0\n"
                        + "kind=sacrificial_syscall_mismatch\tsyscall=statx\tmismatches=3\tlibc_errno=2\traw_errno=1"));
        MultiInstanceDetector hookDet = MultiInstanceDetector.createForTest(null, hookSnap, cleanEnv);
        DetectionResult fast = hookDet.call();
        assertEquals(RiskLevel.SAFE, fast.getRiskLevel());
        DetectionResult post = hookDet.callPostponed(fast);
        assertEquals(RiskLevel.MEDIUM, post.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, post.getStatus());
        assertEquals(5, post.getScore());
        assertFalse(post.isInformational());
        assertTrue(post.getDetails().contains("sacrificial_syscall_mismatch:statx:mismatches=3"));
        assertTrue(post.getEvidenceItems().stream().anyMatch(
                i -> "sacrificial_syscall_mismatch".equals(i.getCode())
                        && i.getPrimarySource() == EvidenceItem.SourceLayer.NATIVE
                        && "virtual_container".equals(i.getEvidenceFamily())
                        && i.getRank() == EvidenceItem.Rank.STRONG));
        assertEquals(Collections.singleton("virtual_container"),
                EvidenceFamily.families(post.getDetails(), post.getEvidenceItems()));
    }

    // ==================== CloudPhoneDetector ====================

    @Test
    public void cloudPhoneDetectorTruePositiveStrongAndWeakTiers() {
        SignalSnapshot gpuSnap = cleanCloudSnapshot();
        gpuSnap.seedGpuIdentityForTest(SignalResult.success(
                new SignalSnapshot.GpuIdentity("Mesa/X.org", "virgl")));
        DetectionResult gpuResult = new CloudPhoneDetector(null, gpuSnap).call();
        assertEquals("cloud_phone", gpuResult.getDetectorName());
        assertEquals(RiskLevel.HIGH, gpuResult.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, gpuResult.getStatus());
        assertFalse(gpuResult.isInformational());

        SignalSnapshot propSnap = cleanCloudSnapshot();
        propSnap.seedSystemPropertyForTest(
                DetectionLists.CLOUD_PHONE_PROPERTIES[0], SignalResult.success("redfinger"));
        DetectionResult propResult = new CloudPhoneDetector(null, propSnap).call();
        assertEquals(RiskLevel.HIGH, propResult.getRiskLevel());

        SignalSnapshot ethSnap = cleanCloudSnapshot();
        ethSnap.seedNetworkInterfaceNamesForTest(SignalResult.success(List.of("eth0", "lo")));
        DetectionResult ethResult = new CloudPhoneDetector(null, ethSnap).call();
        assertEquals(RiskLevel.LOW, ethResult.getRiskLevel());
        assertTrue(ethResult.isInformational());
        assertTrue(ethResult.getDetails().contains("wired_interface:eth0"));
    }

    @Test
    public void cloudPhoneDetectorFalsePositiveGuardPartialAndTotalFailure() {
        DetectionResult clean = new CloudPhoneDetector(null, cleanCloudSnapshot()).call();
        assertEquals(RiskLevel.SAFE, clean.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, clean.getStatus());
        // With null Context, package/battery/camera/sensor checks fail -> PARTIAL coverage.
        assertEquals(DetectionExecutionStatus.PARTIAL, clean.getExecutionStatus());

        SignalSnapshot allFail = new SignalSnapshot(null);
        for (String prop : DetectionLists.CLOUD_PHONE_PROPERTIES) {
            allFail.seedSystemPropertyForTest(prop, SignalResult.unavailable("native_unavailable"));
        }
        allFail.seedGpuIdentityForTest(SignalResult.unavailable("egl_unavailable"));
        allFail.seedNetworkInterfaceNamesForTest(SignalResult.unavailable("no_interfaces"));

        DetectionResult totalFail = new CloudPhoneDetector(null, allFail).call();
        assertEquals(DetectionExecutionStatus.UNAVAILABLE, totalFail.getExecutionStatus());
        assertEquals(RiskLevel.UNKNOWN, totalFail.getRiskLevel());
    }

    // ==================== AdbDetector ====================

    @Test
    public void adbDetectorTruePositiveUsbAndWifiModes() throws Exception {
        SignalSnapshot usbSnap = new SignalSnapshot(null);
        usbSnap.seedAdbStateForTest(SignalResult.success(
                makeAdbSnapshot(true, false, List.of("settings_adb_enabled"), 4, Collections.emptyList())));
        DetectionResult usb = new AdbDetector(null, usbSnap).call();
        assertEquals("adb", usb.getDetectorName());
        assertEquals(RiskLevel.LOW, usb.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, usb.getStatus());
        assertEquals(2, usb.getScore());
        assertTrue(usb.isInformational());

        SignalSnapshot wifiSnap = new SignalSnapshot(null);
        wifiSnap.seedAdbStateForTest(SignalResult.success(
                makeAdbSnapshot(true, true, List.of("adb_tcp_port:5555"), 4, Collections.emptyList())));
        DetectionResult wifi = new AdbDetector(null, wifiSnap).call();
        assertEquals(RiskLevel.MEDIUM, wifi.getRiskLevel());
        assertEquals(4, wifi.getScore());
        assertTrue(wifi.isInformational());
    }

    @Test
    public void adbDetectorFalsePositivePartialAndTotalFailure() throws Exception {
        SignalSnapshot cleanSnap = new SignalSnapshot(null);
        cleanSnap.seedAdbStateForTest(SignalResult.success(
                makeAdbSnapshot(false, false, Collections.emptyList(), 4, Collections.emptyList())));
        DetectionResult clean = new AdbDetector(null, cleanSnap).call();
        assertEquals(RiskLevel.SAFE, clean.getRiskLevel());
        assertEquals(DetectionExecutionStatus.SAFE, clean.getExecutionStatus());

        SignalSnapshot partialSnap = new SignalSnapshot(null);
        partialSnap.seedAdbStateForTest(SignalResult.success(
                makeAdbSnapshot(false, false, Collections.emptyList(), 2,
                        List.of("settings_adb:SecurityException"))));
        DetectionResult partial = new AdbDetector(null, partialSnap).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, partial.getExecutionStatus());
        assertEquals(1, partial.getChecksFailed());

        SignalSnapshot failSnap = new SignalSnapshot(null);
        failSnap.seedAdbStateForTest(SignalResult.error("SecurityException"));
        DetectionResult totalFail = new AdbDetector(null, failSnap).call();
        assertEquals(DetectionExecutionStatus.ERROR, totalFail.getExecutionStatus());
        assertEquals(RiskLevel.UNKNOWN, totalFail.getRiskLevel());
    }

    @Test
    public void adbInspectorConditionalDebounceZeroSleepOnCleanAndDetectsHiddenContradictionHigh7() {
        SignalSnapshot cleanSignals = new SignalSnapshot(null);
        cleanSignals.seedSystemPropertyForTest("service.adb.tcp.port", SignalResult.empty(""));
        cleanSignals.seedSystemPropertyForTest("persist.adb.tcp.port", SignalResult.empty(""));
        cleanSignals.seedProcessesForTest(SignalResult.success(Collections.emptyList()));

        // 1. Clean consistent device -> ZERO sleep, SAFE, no contradiction.
        AtomicInteger cleanSleeps = new AtomicInteger(0);
        AdbInspector.Snapshot cleanSnap = AdbInspector.collectWithAdapter(
                null, cleanSignals, new AdbInspector.ProtocolProbeAdapter() {
                    @Override
                    public SignalResult<String> readNativeAdbProtocol() {
                        return SignalResult.success(
                                "status=OK\terrno=0\tadbd_socket=absent\tjdwp_control=not_observed\tinit_svc_adbd=stopped");
                    }
                    @Override public Integer readSettingsAdbEnabled(android.content.Context c) { return 0; }
                    @Override public Integer readSettingsAdbWifiEnabled(android.content.Context c) { return 0; }
                    @Override public void sleepMs(long millis) { cleanSleeps.incrementAndGet(); }
                });
        assertEquals("Clean device MUST perform zero debounce sleep", 0, cleanSleeps.get());
        assertFalse(cleanSnap.isDebounced());
        assertFalse(cleanSnap.isEnabled());
        assertFalse(cleanSnap.isHiddenAdbdContradiction());

        // 2. Transient transition (sample 1 contradiction resolves in sample 2) -> debounce eliminates FP.
        AtomicInteger transientCalls = new AtomicInteger(0);
        AtomicInteger transientSleeps = new AtomicInteger(0);
        AdbInspector.Snapshot transientSnap = AdbInspector.collectWithAdapter(
                null, cleanSignals, new AdbInspector.ProtocolProbeAdapter() {
                    @Override
                    public SignalResult<String> readNativeAdbProtocol() {
                        int n = transientCalls.incrementAndGet();
                        return SignalResult.success(n == 1
                                ? "status=OK\terrno=0\tadbd_socket=present_denied\tjdwp_control=observed\tinit_svc_adbd=stopped"
                                : "status=OK\terrno=0\tadbd_socket=absent\tjdwp_control=not_observed\tinit_svc_adbd=stopped");
                    }
                    @Override public Integer readSettingsAdbEnabled(android.content.Context c) { return 0; }
                    @Override public Integer readSettingsAdbWifiEnabled(android.content.Context c) { return 0; }
                    @Override public void sleepMs(long millis) { transientSleeps.incrementAndGet(); }
                });
        assertEquals(1, transientSleeps.get());
        assertTrue(transientSnap.isDebounced());
        assertFalse(transientSnap.isHiddenAdbdContradiction());
        assertFalse(transientSnap.isEnabled());

        // 3. Persistent hidden-adbd contradiction (init.svc.adbd=stopped while /dev/socket/adbd EACCES
        //    + @jdwp-control live across both samples) -> HIGH/DANGER/7 actionable in ALL scenes.
        AtomicInteger hiddenSleeps = new AtomicInteger(0);
        AdbInspector.Snapshot hiddenSnap = AdbInspector.collectWithAdapter(
                null, cleanSignals, new AdbInspector.ProtocolProbeAdapter() {
                    @Override
                    public SignalResult<String> readNativeAdbProtocol() {
                        return SignalResult.success(
                                "status=OK\terrno=0\tadbd_socket=present_denied\tjdwp_control=observed\tinit_svc_adbd=stopped");
                    }
                    @Override public Integer readSettingsAdbEnabled(android.content.Context c) { return 0; }
                    @Override public Integer readSettingsAdbWifiEnabled(android.content.Context c) { return 0; }
                    @Override public void sleepMs(long millis) { hiddenSleeps.incrementAndGet(); }
                });
        assertEquals(1, hiddenSleeps.get());
        assertTrue(hiddenSnap.isHiddenAdbdContradiction());
        assertTrue(hiddenSnap.getDetails().contains("adbd_contradiction:init_svc_adbd_stopped"));
        assertTrue(hiddenSnap.getDetails().contains("adbd_hidden_socket:present_denied"));
        assertTrue(hiddenSnap.getDetails().contains("adbd_hidden_jdwp_control"));

        SignalSnapshot detectorSnap = new SignalSnapshot(null);
        detectorSnap.seedAdbStateForTest(SignalResult.success(hiddenSnap));
        DetectionResult res = new AdbDetector(null, detectorSnap).call();
        assertEquals(RiskLevel.HIGH, res.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, res.getStatus());
        assertEquals(7, res.getScore());
        assertFalse(res.isInformational());
        assertTrue(res.getEvidenceItems().stream().anyMatch(
                i -> "adbd_hidden_jdwp_control".equals(i.getCode())
                        && "adb".equals(i.getEvidenceFamily())
                        && i.getRank() == EvidenceItem.Rank.STRONG));
        // Actionable in STANDARD, LOGIN, PAYMENT, DIAGNOSTIC alike.
        assertFalse(CorrelationEngine.applyScene(res, CollectScene.STANDARD).isInformational());
        assertFalse(CorrelationEngine.applyScene(res, CollectScene.LOGIN).isInformational());
        assertFalse(CorrelationEngine.applyScene(res, CollectScene.PAYMENT).isInformational());
    }

    // ==================== CustomRomDetector ====================

    @Test
    public void customRomDetectorTruePositiveCommunityRomAndFingerprintMismatch() {
        SignalSnapshot lineageSnap = cleanCustomRomSnapshot();
        lineageSnap.seedSystemPropertyForTest("ro.lineage.version", SignalResult.success("21.0"));
        DetectionResult lineage = new CustomRomDetector(null, lineageSnap).call();
        assertEquals("custom_rom", lineage.getDetectorName());
        assertEquals(RiskLevel.LOW, lineage.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, lineage.getStatus());
        assertTrue(lineage.isInformational());
        assertTrue(lineage.getDetails().contains("community_rom:LineageOS=21.0"));

        SignalSnapshot mismatchSnap = cleanCustomRomSnapshot();
        mismatchSnap.seedBuildPropFingerprintForTest(
                SignalResult.success("google/panther/panther:14/AP2A/999:user/release-keys"));
        DetectionResult mismatch = new CustomRomDetector(null, mismatchSnap).call();
        assertEquals(RiskLevel.LOW, mismatch.getRiskLevel());
        assertTrue(mismatch.getDetails().contains("prop_mismatch:fingerprint"));
    }

    @Test
    public void customRomDetectorFalsePositivePartialAndTotalFailure() {
        DetectionResult clean = new CustomRomDetector(null, cleanCustomRomSnapshot()).call();
        assertEquals(RiskLevel.SAFE, clean.getRiskLevel());
        assertEquals(DetectionExecutionStatus.SAFE, clean.getExecutionStatus());

        SignalSnapshot partialSnap = cleanCustomRomSnapshot();
        partialSnap.seedSystemPropertyForTest("ro.cm.version", SignalResult.error("EACCES"));
        DetectionResult partial = new CustomRomDetector(null, partialSnap).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, partial.getExecutionStatus());
        assertEquals(1, partial.getChecksFailed());

        SignalSnapshot failSnap = new SignalSnapshot(null);
        failSnap.seedSystemPropertyForTest(
                "ro.build.fingerprint", SignalResult.unavailable("native_unavailable"));
        DetectionResult totalFail = new CustomRomDetector(null, failSnap).call();
        assertEquals(DetectionExecutionStatus.UNAVAILABLE, totalFail.getExecutionStatus());
        assertEquals(RiskLevel.UNKNOWN, totalFail.getRiskLevel());
    }

    @Test
    public void customRomDetectorNativeProbesPixelSuppressionHarmonyOsAndEvidenceItems() {
        // 1. Native libstagefright.so symbol + framework-res.apk multi-device mapping emit custom_rom EvidenceItems
        //    and remain strictly LOW/1 informational in standard scenes.
        SignalSnapshot nativeRomSnap = cleanCustomRomSnapshot();
        nativeRomSnap.seedCustomRomProbeForTest(SignalResult.success(
                "status=OK\terrno=0\tstagefright_checked=1\tstagefright_hits=1\tframework_res_devs=2\n"
                        + "kind=stagefright_symbol\tpath=/system/lib64/libstagefright.so\tsource=both\n"
                        + "kind=framework_res_multi_dev\tdev_count=2\tdevs=fe:01,fd:00"));
        DetectionResult nativeRom = new CustomRomDetector(null, nativeRomSnap).call();
        assertEquals(RiskLevel.LOW, nativeRom.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, nativeRom.getStatus());
        assertEquals(1, nativeRom.getScore());
        assertTrue(nativeRom.isInformational());
        assertTrue(nativeRom.getDetails().contains("stagefright_custom_symbol:/system/lib64/libstagefright.so"));
        assertTrue(nativeRom.getDetails().contains("framework_res_multi_dev:2"));
        assertEquals(2, nativeRom.getEvidenceItems().size());
        assertTrue(nativeRom.getEvidenceItems().stream().allMatch(
                i -> "custom_rom".equals(i.getEvidenceFamily()) && i.getRank() == EvidenceItem.Rank.WEAK));

        // 2. Authentic google/Pixel* device suppresses PixelExperience false positive.
        SignalSnapshot pixelSnap = cleanCustomRomSnapshot();
        pixelSnap.seedSystemPropertyForTest("ro.product.brand", SignalResult.success("google"));
        pixelSnap.seedSystemPropertyForTest("ro.product.model", SignalResult.success("Pixel 8 Pro"));
        pixelSnap.seedSystemPropertyForTest("ro.pixelexperience.version", SignalResult.success("14.0"));
        DetectionResult pixelResult = new CustomRomDetector(null, pixelSnap).call();
        assertEquals(RiskLevel.SAFE, pixelResult.getRiskLevel());
        assertTrue(pixelResult.getDetails().isEmpty());

        // Non-Pixel device with PixelExperience property MUST still be detected.
        SignalSnapshot nonPixelSnap = cleanCustomRomSnapshot();
        nonPixelSnap.seedSystemPropertyForTest("ro.product.brand", SignalResult.success("Xiaomi"));
        nonPixelSnap.seedSystemPropertyForTest("ro.product.model", SignalResult.success("2304FPN6DC"));
        nonPixelSnap.seedSystemPropertyForTest("ro.pixelexperience.version", SignalResult.success("14.0"));
        DetectionResult nonPixelResult = new CustomRomDetector(null, nonPixelSnap).call();
        assertEquals(RiskLevel.LOW, nonPixelResult.getRiskLevel());
        assertTrue(nonPixelResult.getDetails().contains("community_rom:PixelExperience=14.0"));
        assertTrue(nonPixelResult.getEvidenceItems().stream().anyMatch(
                i -> "custom_rom".equals(i.getEvidenceFamily()) && "community_rom".equals(i.getCode())));

        // 3. HarmonyOS recognition via guarded reflection never throws and suppresses non-standard
        //    system false positives (build.prop fingerprint / framework-res multi-dev).
        assertEquals("", CustomRomDetector.queryHarmonyOsBrand());
        SignalSnapshot harmonySnap = cleanCustomRomSnapshot();
        harmonySnap.seedBuildPropFingerprintForTest(
                SignalResult.success("HUAWEI/ALN-AL00/HWALN:12/HUAWEIALN-AL00/104.0.0:user/release-keys"));
        harmonySnap.seedCustomRomProbeForTest(SignalResult.success(
                "status=OK\terrno=0\tstagefright_checked=1\tstagefright_hits=0\tframework_res_devs=2\n"
                        + "kind=framework_res_multi_dev\tdev_count=2\tdevs=fe:01,fe:02"));
        DetectionResult harmonyResult = new CustomRomDetector(null, harmonySnap, () -> "harmony").call();
        assertEquals(RiskLevel.SAFE, harmonyResult.getRiskLevel());
        assertTrue(harmonyResult.getDetails().isEmpty());
    }

    private static SignalSnapshot cleanEmulatorSnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedSystemPropertyForTest("ro.kernel.qemu", SignalResult.success("0"));
        snapshot.seedSystemPropertyForTest("ro.boot.qemu", SignalResult.success("0"));
        snapshot.seedSystemPropertyForTest("ro.hardware.virtual", SignalResult.empty(""));
        snapshot.seedSystemPropertyForTest("ro.build.characteristics", SignalResult.success("default"));
        snapshot.seedCpuInfoForTest(SignalResult.success(
                "Hardware : Qualcomm Technologies, Inc SM8550"));
        snapshot.seedDiskSizeDataForTest(SignalResult.success(128L * 1024 * 1024 * 1024));
        snapshot.seedKernelInfoForTest(SignalResult.success("Linux 5.15.104-android14 aarch64"));
        snapshot.seedScreenMetricsForTest(SignalResult.success(
                new SignalSnapshot.ScreenMetrics(1080, 2400, 400f, 400f, 420)));
        snapshot.seedContainerSignalsForTest(SignalResult.success(Collections.emptyList()));
        snapshot.seedGpuIdentityForTest(SignalResult.success(
                new SignalSnapshot.GpuIdentity("Qualcomm", "Adreno (TM) 740")));
        return snapshot;
    }

    private static SignalSnapshot cleanCloudSnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        for (String prop : DetectionLists.CLOUD_PHONE_PROPERTIES) {
            snapshot.seedSystemPropertyForTest(prop, SignalResult.empty(""));
        }
        snapshot.seedGpuIdentityForTest(SignalResult.success(
                new SignalSnapshot.GpuIdentity("Qualcomm", "Adreno (TM) 740")));
        snapshot.seedNetworkInterfaceNamesForTest(SignalResult.success(List.of("wlan0", "lo")));
        return snapshot;
    }

    private static SignalSnapshot cleanCustomRomSnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        String fp = "google/cheetah/cheetah:14/AP2A.240805.005/12025142:user/release-keys";
        snapshot.seedSystemPropertyForTest("ro.build.fingerprint", SignalResult.success(fp));
        String[] romProps = {
                "ro.lineage.version", "ro.cm.version", "ro.mokee.version",
                "ro.rr.version", "ro.pixelexperience.version", "ro.modversion"
        };
        for (String p : romProps) {
            snapshot.seedSystemPropertyForTest(p, SignalResult.empty(""));
        }
        snapshot.seedBuildPropFingerprintForTest(SignalResult.success(fp));
        return snapshot;
    }

    @SuppressWarnings("unchecked")
    private static AdbInspector.Snapshot makeAdbSnapshot(boolean enabled,
                                                         boolean wifiEnabled,
                                                         List<String> details,
                                                         int checksSucceeded,
                                                         List<String> failureReasons) throws Exception {
        AdbInspector.Snapshot snap = new AdbInspector.Snapshot();
        setField(snap, "enabled", enabled);
        setField(snap, "wifiEnabled", wifiEnabled);
        setField(snap, "checksSucceeded", checksSucceeded);
        setField(snap, "checksAttempted", checksSucceeded + failureReasons.size());
        ((List<String>) getField(snap, "details")).addAll(details);
        ((List<String>) getField(snap, "failureReasons")).addAll(failureReasons);
        return snap;
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    private static Object getField(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }
}
