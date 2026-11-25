package com.wsttxm.riskenginesdk;

import android.media.MediaDrm;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.ConsistencyDetector;
import com.wsttxm.riskenginesdk.detector.probe.consistency.WidevineParityProbe;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for P3-4: {@link WidevineParityProbe} and {@link ConsistencyDetector#detectPostponed}
 * Widevine Java vs NDK AMediaDrm parity integration.
 */
public class WidevineParityProbeTest {

    @Test
    public void alignedL1DeviceWithHwSecureAllSessionProducesZeroFindings() {
        WidevineParityProbe.JavaWidevineReader javaReader = () ->
                new WidevineParityProbe.JavaWidevineSnapshot(
                        true, true, "L1", "21258", true,
                        MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL, null);
        WidevineParityProbe.NdkWidevineReader ndkReader = () ->
                SignalResult.success(
                        "status=OK\terrno=0\tsupported=1\tsec_status=0\tsecurity_level=L1\tsys_status=0\tsystem_id=21258");

        WidevineParityProbe.ProbeResult res = WidevineParityProbe.probe(javaReader, ndkReader, 500L);
        assertTrue(res.isUsable());
        assertFalse(res.hasFindings());
        assertTrue(res.getEvidenceItems().isEmpty());
    }

    @Test
    public void javaVsNdkSecurityLevelAndSystemIdMismatchTriggersStrongHwSpoofInPostponed() {
        WidevineParityProbe.JavaWidevineReader hookedJava = () ->
                new WidevineParityProbe.JavaWidevineSnapshot(
                        true, true, "L1", "11111", true,
                        MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL, null);
        ConsistencyDetector.NativeConsistencySource ndkSource = stubNative(
                SignalResult.success(
                        "status=OK\terrno=0\tsupported=1\tsec_status=0\tsecurity_level=L3\tsys_status=0\tsystem_id=22222"));

        ConsistencyDetector detector = new ConsistencyDetector(
                null, cleanSnapshot(), ndkSource, false, hookedJava);
        DetectionResult fast = detector.call();
        assertEquals(RiskLevel.SAFE, fast.getRiskLevel());

        DetectionResult post = detector.callPostponed(fast);
        assertEquals(RiskLevel.HIGH, post.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, post.getStatus());
        assertFalse(post.isInformational());
        assertTrue(post.getDetails().contains("widevine_java_ndk_mismatch:securityLevel"));
        assertTrue(post.getDetails().contains("widevine_java_ndk_mismatch:systemId"));
        assertTrue(post.getEvidenceItems().stream().anyMatch(
                i -> "hw_spoof".equals(i.getEvidenceFamily())
                        && "widevine_java_ndk_mismatch".equals(i.getCode())
                        && i.getRank() == EvidenceItem.Rank.STRONG));
    }

    @Test
    public void l1SentinelSystemIdAndHwSecureAllDowngradeEmitHwSpoofMediumEvidence() {
        WidevineParityProbe.JavaWidevineReader degradedJava = () ->
                new WidevineParityProbe.JavaWidevineSnapshot(
                        true, true, "L1", WidevineParityProbe.SENTINEL_SYSTEM_ID, true,
                        MediaDrm.SECURITY_LEVEL_SW_SECURE_CRYPTO, null);
        ConsistencyDetector.NativeConsistencySource ndkSource = stubNative(
                SignalResult.success(
                        "status=OK\terrno=0\tsupported=1\tsec_status=0\tsecurity_level=L1\tsys_status=0\tsystem_id="
                                + WidevineParityProbe.SENTINEL_SYSTEM_ID));

        ConsistencyDetector detector = new ConsistencyDetector(
                null, cleanSnapshot(), ndkSource, false, degradedJava);
        DetectionResult fast = detector.call();
        DetectionResult post = detector.callPostponed(fast);

        assertEquals(RiskLevel.MEDIUM, post.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, post.getStatus());
        assertFalse(post.isInformational());
        assertTrue(post.getDetails().contains("widevine_l1_sentinel_system_id"));
        assertTrue(post.getDetails().contains("widevine_hw_secure_all_downgrade"));
        assertTrue(post.getEvidenceItems().stream().anyMatch(
                i -> "hw_spoof".equals(i.getEvidenceFamily())
                        && "widevine_l1_sentinel_system_id".equals(i.getCode())));
        assertTrue(post.getEvidenceItems().stream().anyMatch(
                i -> "hw_spoof".equals(i.getEvidenceFamily())
                        && "widevine_hw_secure_all_downgrade".equals(i.getCode())));
    }

    @Test
    public void unavailableOrUnsupportedWidevineDegradesCleanlyWithZeroFp() {
        WidevineParityProbe.JavaWidevineReader unsupportedJava = () ->
                WidevineParityProbe.JavaWidevineSnapshot.unsupported("widevine_unsupported");
        WidevineParityProbe.NdkWidevineReader unsupportedNdk = () ->
                SignalResult.success("status=UNSUPPORTED\terrno=0\treason=mediandk_dlopen_failed");

        WidevineParityProbe.ProbeResult res = WidevineParityProbe.probe(unsupportedJava, unsupportedNdk, 500L);
        assertEquals(SignalResult.Status.UNAVAILABLE, res.getStatus());
        assertFalse(res.isUsable());
        assertFalse(res.hasFindings());

        // Exception inside Java reader must never crash or cause FP
        WidevineParityProbe.JavaWidevineReader throwingJava = () -> {
            throw new LinkageError("simulated_drm_linkage_error");
        };
        ConsistencyDetector detector = new ConsistencyDetector(
                null, cleanSnapshot(), stubNative(SignalResult.unavailable("native_unavailable")),
                false, throwingJava);
        DetectionResult fast = detector.call();
        DetectionResult post = detector.callPostponed(fast);
        assertEquals(RiskLevel.SAFE, post.getRiskLevel());
        assertTrue(post.getDetails().isEmpty());
    }

    @Test
    public void l3DeviceWithSentinelOrNormalSystemIdDoesNotFalsePositive() {
        // L3 device does not advertise L1, so sentinel systemId=2147483647 or SW session must NOT trigger L1 findings
        WidevineParityProbe.JavaWidevineReader l3Java = () ->
                new WidevineParityProbe.JavaWidevineSnapshot(
                        true, true, "L3", WidevineParityProbe.SENTINEL_SYSTEM_ID, false,
                        MediaDrm.SECURITY_LEVEL_SW_SECURE_CRYPTO, null);
        WidevineParityProbe.NdkWidevineReader l3Ndk = () ->
                SignalResult.success(
                        "status=OK\terrno=0\tsupported=1\tsec_status=0\tsecurity_level=L3\tsys_status=0\tsystem_id="
                                + WidevineParityProbe.SENTINEL_SYSTEM_ID);

        WidevineParityProbe.ProbeResult res = WidevineParityProbe.probe(l3Java, l3Ndk, 500L);
        assertTrue(res.isUsable());
        assertFalse(res.hasFindings());
    }

    private static ConsistencyDetector.NativeConsistencySource stubNative(
            SignalResult<String> widevineNdk) {
        return new ConsistencyDetector.NativeConsistencySource() {
            @Override public SignalResult<String> getHardwareCpuIdentity() { return SignalResult.unavailable("unused"); }
            @Override public SignalResult<String> getKernelConsistency() { return SignalResult.unavailable("unused"); }
            @Override public SignalResult<String> getPifProperties() { return SignalResult.unavailable("unused"); }
            @Override public String getJavaOsVersion() { return ""; }
            @Override public SignalResult<String> getWidevineNdkProbe() { return widevineNdk; }
        };
    }

    private static SignalSnapshot cleanSnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        String sysFp = "google/cheetah/cheetah:14/AP2A.240805.005/12025142:user/release-keys";
        snapshot.seedSystemPropertyForTest("ro.build.fingerprint", SignalResult.success(sysFp));
        snapshot.seedSystemPropertyForTest("ro.system.build.fingerprint", SignalResult.success(sysFp));
        snapshot.seedSystemPropertyForTest("ro.vendor.build.fingerprint", SignalResult.success(sysFp));
        snapshot.seedSystemPropertyForTest("ro.boot.flash.locked", SignalResult.success("1"));
        snapshot.seedSystemPropertyForTest("ro.boot.verifiedbootstate", SignalResult.success("green"));
        snapshot.seedProcCmdlineBootPropsForTest(SignalResult.success(Map.of(
                "androidboot.flash.locked", "1",
                "androidboot.verifiedbootstate", "green")));
        snapshot.seedBionicPropForensicsForTest(SignalResult.unavailable("unused"));
        return snapshot;
    }
}
