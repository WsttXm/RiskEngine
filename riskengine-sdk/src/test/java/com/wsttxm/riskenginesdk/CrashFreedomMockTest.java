package com.wsttxm.riskenginesdk;

import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;

import com.wsttxm.riskenginesdk.attestation.AttestationCapability;
import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.CollectorRegistry;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.core.SignedEnvelopeSigner;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.DetectorRegistry;
import com.wsttxm.riskenginesdk.detector.probe.consistency.WidevineParityProbe;
import com.wsttxm.riskenginesdk.detector.probe.hook.LsposedProbe;
import com.wsttxm.riskenginesdk.detector.probe.hook.SelfIntegrityProbe;
import com.wsttxm.riskenginesdk.detector.probe.hook.ZygiskProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.GrantDomainSplitProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.Keystore2DeepProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.TeeNativeProbe;
import com.wsttxm.riskenginesdk.detector.probe.tee.VintfHalAndErrorPathProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaCrossUserProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaOrderedBroadcastProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaPermissionServiceProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaUidVisibilityProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThanoxIpcProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThreatAppPackageProbe;
import com.wsttxm.riskenginesdk.detector.probe.virtualization.SensorNoiseProbe;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;
import com.wsttxm.riskenginesdk.process.MountViewNormalizer;
import com.wsttxm.riskenginesdk.process.RiskIsolatedProbeService;
import com.wsttxm.riskenginesdk.util.AdbInspector;

import org.junit.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Pure-JVM crash-freedom test suite inspired by fingerprintjs-android.
 * Injects hostile failures (SecurityException, RuntimeException, UnsatisfiedLinkError,
 * OutOfMemoryError) into all 16 concrete detectors (BOTH fast {@code call()} and Stage 3
 * {@code callPostponed()} paths), all collectors, {@link RiskIsolatedProbeService},
 * {@link IsolatedProbeClient}, all Phase 2 probes, and {@link SignalSnapshot}, asserting
 * zero uncaught exceptions.
 */
public class CrashFreedomMockTest {

    private static final List<Supplier<Throwable>> FAULT_SUPPLIERS = Arrays.asList(
            () -> new SecurityException("injected_security_denial"),
            () -> new RuntimeException("injected_runtime_failure"),
            () -> new UnsatisfiedLinkError("injected_missing_native_symbol"),
            () -> new OutOfMemoryError("injected_oom")
    );

    @Test
    public void baseDetectorCatchesAllFourHostileFaultTypesInFastAndPostponedPasses() {
        for (Supplier<Throwable> fault : FAULT_SUPPLIERS) {
            BaseDetector throwing = new BaseDetector(null) {
                @Override public String getName() { return "fault_detector"; }
                @Override public boolean hasPostponedProbes() { return true; }
                @Override protected DetectionResult detect() {
                    sneakyThrow(fault.get());
                    return safe();
                }
                @Override public DetectionResult detectPostponed(DetectionResult priorResult) {
                    sneakyThrow(fault.get());
                    return priorResult;
                }
            };
            DetectionResult fast = throwing.call();
            assertNotNull(fast);
            assertEquals(DetectionExecutionStatus.ERROR, fast.getExecutionStatus());
            assertEquals(RiskLevel.UNKNOWN, fast.getRiskLevel());

            DetectionResult postponed = throwing.callPostponed(fast);
            assertNotNull(postponed);
            assertEquals(fast, postponed);
        }
    }

    @Test
    public void baseCollectorCatchesAllFourHostileFaultTypesWithoutCrashing() {
        for (Supplier<Throwable> fault : FAULT_SUPPLIERS) {
            BaseCollector throwing = new BaseCollector(null) {
                @Override public String getName() { return "fault_collector"; }
                @Override protected void collect(CollectorResult result) {
                    sneakyThrow(fault.get());
                }
            };
            CollectorResult result = throwing.call();
            assertNotNull(result);
            assertEquals(CollectorResult.Status.ERROR, result.getStatus());
        }
    }

    @Test
    public void allSixteenDetectorsSurviveHostileFaultsAcrossFastAndPostponedPaths() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .expectedPackageName("com.example.wallet")
                .expectedSigningCertSha256Base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .enableIsolatedProcessProbe(true)
                .enableTeeAttestation(true)
                .enableThreatAppDetection(true)
                .build();

        Set<String> expectedPostponed = new LinkedHashSet<>(Arrays.asList(
                "consistency", "root", "mount_analysis", "hook_framework",
                "emulator", "cloud_phone", "multi_instance"
        ));

        for (Supplier<Throwable> fault : FAULT_SUPPLIERS) {
            Context hostileContext = new HostileFaultContext(fault);
            SignalSnapshot snapshot = new SignalSnapshot(hostileContext);
            List<BaseDetector> detectors = new DetectorRegistry(
                    hostileContext, config, snapshot).getDetectors();
            assertEquals("Expected all 16 converged top-level detectors", 16, detectors.size());

            Set<String> actualPostponed = new LinkedHashSet<>();
            boolean sawTeeIntegrity = false;
            boolean sawThreatApps = false;
            for (BaseDetector detector : detectors) {
                if ("tee_integrity".equals(detector.getName())) {
                    sawTeeIntegrity = true;
                    assertEquals(ScanTier.POSTPONED, detector.getScanTier());
                }
                if ("threat_apps".equals(detector.getName())) {
                    sawThreatApps = true;
                    assertEquals(ScanTier.POSTPONED, detector.getScanTier());
                }
                DetectionResult fast = detector.call();
                assertNotNull("Detector returned null on fast pass: " + detector.getName(), fast);
                assertNotNull(fast.getRiskLevel());
                assertNotNull(fast.getStatus());
                assertNotNull(fast.getExecutionStatus());
                assertNotNull(fast.getScanTier());

                if (detector.hasPostponedProbes()) {
                    actualPostponed.add(detector.getName());
                }
                DetectionResult postponed = detector.callPostponed(fast);
                assertNotNull("Detector returned null on postponed pass: " + detector.getName(),
                        postponed);
                assertNotNull(postponed.getRiskLevel());
                assertNotNull(postponed.getStatus());
                assertNotNull(postponed.getExecutionStatus());
            }
            assertTrue("Expected tee_integrity as 15th converged domain", sawTeeIntegrity);
            assertTrue("Expected threat_apps as 16th converged domain", sawThreatApps);
            assertEquals("Expected all 7 dual-pass postponed-capable domains",
                    expectedPostponed, actualPostponed);

            // Phase 4 threat/HMA probes directly under hostile context & faults
            assertNotNull(new ThreatAppPackageProbe(hostileContext).probe(ThreatAppPolicy.DEFAULT));
            assertNotNull(new HmaUidVisibilityProbe(hostileContext).probe());
            assertNotNull(new HmaCrossUserProbe(hostileContext).probe(Collections.singletonList("me.weishu.kernelsu")));
            assertNotNull(new HmaOrderedBroadcastProbe(hostileContext).probe(Collections.singletonList("me.weishu.kernelsu")));
            assertNotNull(new HmaPermissionServiceProbe(hostileContext).probe());
            assertNotNull(new ThanoxIpcProbe(() -> {
                sneakyThrow(fault.get());
                return null;
            }).probe());
        }
    }

    @Test
    public void phaseThreeAttestationGrantSplitProbesAndSignedEnvelopeSurviveHostileFaults() {
        byte[] challenge = new byte[32];
        Arrays.fill(challenge, (byte) 0x3C);
        RiskReport cleanReport = new RiskReport(
                new DeviceFingerprint(), Collections.<DetectionResult>emptyList(), CollectScene.PAYMENT);

        for (final Supplier<Throwable> fault : FAULT_SUPPLIERS) {
            Context hostileContext = new HostileFaultContext(fault);
            SignalSnapshot snapshot = new SignalSnapshot(hostileContext);

            // 1. AttestationCapability under hostile KeyAttestationBackend
            AttestationCapability capability = new AttestationCapability(
                    new AttestationCapability.KeyAttestationBackend() {
                        @Override
                        public List<X509Certificate> generateAttestationChain(
                                String alias, byte[] ch, boolean strongBox) {
                            sneakyThrow(fault.get());
                            return Collections.emptyList();
                        }

                        @Override
                        public void deleteAlias(String alias) {
                            sneakyThrow(fault.get());
                        }
                    },
                    null, null, null, null);
            AttestationCapability.AttestationSnapshot attSnap = capability.collect();
            assertNotNull(attSnap);

            // 2. GrantDomainSplitProbe & IsolatedProbeClient under hostile context
            assertNotNull(GrantDomainSplitProbe.run(snapshot, true));
            assertNotNull(GrantDomainSplitProbe.run(snapshot, false));
            assertNotNull(GrantDomainSplitProbe.run(null, true));
            assertNotNull(IsolatedProbeClient.probeGrantDomainChain(hostileContext, true));

            // 3. TeeNativeProbe, Keystore2DeepProbe, VintfHalAndErrorPathProbe & WidevineParityProbe
            assertNotNull(TeeNativeProbe.run(snapshot, null, false));
            assertNotNull(TeeNativeProbe.run(
                    new TeeNativeProbe.NativeTeeAdapter() {
                        @Override
                        public SignalResult<String> getTeeBinderProbe(boolean includeHoneypotTiming) {
                            sneakyThrow(fault.get());
                            return SignalResult.unavailable("unreachable");
                        }

                        @Override
                        public SignalResult<String> inspectLeafDer(byte[] leafDer) {
                            sneakyThrow(fault.get());
                            return SignalResult.unavailable("unreachable");
                        }
                    },
                    new byte[]{0x30, 0x00},
                    true));
            assertNotNull(Keystore2DeepProbe.run(hostileContext, attSnap));
            assertNotNull(VintfHalAndErrorPathProbe.run(attSnap));
            assertNotNull(WidevineParityProbe.probe());
            assertNotNull(WidevineParityProbe.probe(
                    () -> {
                        sneakyThrow(fault.get());
                        return null;
                    },
                    () -> {
                        sneakyThrow(fault.get());
                        return null;
                    },
                    50L));

            // 4. SignedRiskEnvelope (PERSISTENT_KEY + FRESH_ATTESTATION) degrades cleanly to SOFTWARE_FALLBACK
            SignedEnvelopeSigner signer = new SignedEnvelopeSigner(
                    new SignedEnvelopeSigner.EnvelopeKeyBackend() {
                        @Override
                        public SignedEnvelopeSigner.SigningKeyHandle loadExistingKey(String alias) {
                            sneakyThrow(fault.get());
                            return null;
                        }

                        @Override
                        public SignedEnvelopeSigner.SigningKeyHandle generateSigningKey(
                                String alias, byte[] ch, boolean strongBox) {
                            sneakyThrow(fault.get());
                            return null;
                        }

                        @Override
                        public byte[] signEcdsaSha256(PrivateKey privateKey, byte[] payloadBytes) {
                            sneakyThrow(fault.get());
                            return new byte[0];
                        }

                        @Override
                        public void deleteAlias(String alias) {
                            sneakyThrow(fault.get());
                        }
                    },
                    () -> 1234L);

            SignedRiskEnvelope persistent = signer.sign(
                    hostileContext, cleanReport, challenge, EnvelopeMode.PERSISTENT_KEY);
            assertNotNull(persistent);
            assertEquals(SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK,
                    persistent.getAttestationMode());

            SignedRiskEnvelope fresh = signer.sign(
                    hostileContext, cleanReport, challenge, EnvelopeMode.FRESH_ATTESTATION);
            assertNotNull(fresh);
            assertEquals(SignedRiskEnvelope.AttestationMode.SOFTWARE_FALLBACK,
                    fresh.getAttestationMode());
        }
    }

    @Test
    public void allCollectorsSurviveHostileContextFaultsWithZeroUncaughtExceptions() {
        RiskEngineConfig diagnosticConfig = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.DIAGNOSTIC)
                .build();

        for (Supplier<Throwable> fault : FAULT_SUPPLIERS) {
            Context hostileContext = new HostileFaultContext(fault);
            SignalSnapshot snapshot = new SignalSnapshot(hostileContext);
            List<BaseCollector> collectors = new CollectorRegistry(
                    hostileContext, diagnosticConfig, snapshot).getCollectors();
            assertTrue("Expected >= 20 collectors", collectors.size() >= 20);

            for (BaseCollector collector : collectors) {
                CollectorResult result = collector.call();
                assertNotNull("Collector returned null under fault: " + collector.getName(), result);
                assertNotNull(result.getStatus());
            }
        }
    }

    @Test
    public void isolatedProbeServiceAndClientSurviveHostileContextAndMalformedInput() {
        // Non-isolated JVM environment MUST fail closed (return null Binder) without throwing.
        RiskIsolatedProbeService service = new RiskIsolatedProbeService();
        assertNull(service.onBind(null));

        for (Supplier<Throwable> fault : FAULT_SUPPLIERS) {
            Context hostileContext = new HostileFaultContext(fault);
            SignalSnapshot snapshot = new SignalSnapshot(hostileContext);
            SignalResult<IsolatedProbeClient.IsolatedMountReport> enabledRes =
                    IsolatedProbeClient.probeMountView(hostileContext, snapshot, true);
            assertNotNull(enabledRes);
            SignalResult<IsolatedProbeClient.IsolatedMountReport> disabledRes =
                    IsolatedProbeClient.probeMountView(hostileContext, snapshot, false);
            assertNotNull(disabledRes);
            assertEquals(SignalResult.Status.UNAVAILABLE, disabledRes.getStatus());
        }
        assertNotNull(IsolatedProbeClient.probeMountView(null, new SignalSnapshot(null), true));

        // MountViewNormalizer handles null / empty / malformed lines without throwing.
        assertNotNull(MountViewNormalizer.diffViews(null, null));
        assertNotNull(MountViewNormalizer.diffViews(
                Collections.singletonList("malformed-line-without-separator"),
                Collections.singletonList("36 35 98:0 / /system ro - ext4 /dev/block/dm-0 ro")));
    }

    @Test
    public void phaseTwoProbesAndSignalSnapshotSurviveHostileFaultsWithoutUncaughtExceptions() {
        for (Supplier<Throwable> fault : FAULT_SUPPLIERS) {
            Context hostileContext = new HostileFaultContext(fault);
            SignalSnapshot snapshot = new SignalSnapshot(hostileContext);

            // Phase 1 + Phase 2 SignalSnapshot slots
            assertNotNull(snapshot.getAdbState());
            assertNotNull(snapshot.getScreenMetrics());
            assertNotNull(snapshot.getNetworkInterfaceNames());
            assertNotNull(snapshot.getContainerSignals());
            assertNotNull(snapshot.getGpuIdentity());
            assertNotNull(snapshot.getNativeApkSigningInfo());
            assertNotNull(snapshot.getBionicPropForensics());
            assertNotNull(snapshot.getCustomRomProbe());
            assertNotNull(snapshot.getKernelSidechannelEvidence(false));
            assertNotNull(snapshot.getKernelSidechannelEvidence(true));
            assertNotNull(snapshot.getSelinuxAuditEvidence());
            assertNotNull(snapshot.getZygiskAtexitProbe());
            assertNotNull(snapshot.getVirtualizationTraps(false));
            assertNotNull(snapshot.getVirtualizationTraps(true));
            assertNotNull(snapshot.getMediaCodecSummary());
            assertNotNull(snapshot.getIsolatedMountReport(false));
            assertNotNull(snapshot.getIsolatedMountReport(true));

            // Phase 2 standalone probes
            assertNotNull(ZygiskProbe.probe(() -> {
                sneakyThrow(fault.get());
                return SignalResult.unavailable("unreachable");
            }));
            assertNotNull(ZygiskProbe.parsePayload(null));
            assertNotNull(ZygiskProbe.parsePayload("malformed"));

            assertNotNull(LsposedProbe.probe(hostileContext, snapshot));
            assertNotNull(LsposedProbe.probe(null, null));

            assertNotNull(SensorNoiseProbe.sample(hostileContext));
            assertNotNull(SensorNoiseProbe.sample(null));
            assertNotNull(SensorNoiseProbe.sample(hostileContext, 50L, (ctx, win) -> {
                sneakyThrow(fault.get());
                return SensorNoiseProbe.Result.unavailable("unreachable");
            }));
            assertNotNull(SensorNoiseProbe.evaluateSamples(null, "accelerometer"));

            assertNotNull(SelfIntegrityProbe.parseNativeHookPayload(null));
            assertNotNull(SelfIntegrityProbe.parseNativeHookPayload("status=ERROR\terrno=13"));

            assertNotNull(AdbInspector.collectUncached(hostileContext, snapshot));
        }
    }

    private static final class HostileFaultContext extends ContextWrapper {
        private final Supplier<Throwable> fault;

        HostileFaultContext(Supplier<Throwable> fault) {
            super(null);
            this.fault = fault;
        }

        private <T> T fail() {
            sneakyThrow(fault.get());
            return null;
        }

        @Override public Context getApplicationContext() { return this; }
        @Override public PackageManager getPackageManager() { return fail(); }
        @Override public Object getSystemService(String name) { return fail(); }
        @Override public ContentResolver getContentResolver() { return fail(); }
        @Override public ApplicationInfo getApplicationInfo() { return fail(); }
        @Override public Resources getResources() { return fail(); }
        @Override public ClassLoader getClassLoader() { return fail(); }
        @Override public String getPackageName() { return fail(); }
        @Override public int checkSelfPermission(String permission) { return fail(); }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) { return fail(); }
        @Override public File getFilesDir() { return fail(); }
        @Override public File getDataDir() { return fail(); }
        @Override public Context createDeviceProtectedStorageContext() { return fail(); }
        @Override public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) {
            return fail();
        }
        @Override public boolean bindService(Intent service, ServiceConnection conn, int flags) {
            return fail();
        }
        @Override public void unbindService(ServiceConnection conn) {
            fail();
        }
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void sneakyThrow(Throwable t) throws E {
        throw (E) t;
    }
}
