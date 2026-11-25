package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.ApplicationInfo;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.DebugDetector;
import com.wsttxm.riskenginesdk.detector.HookFrameworkDetector;
import com.wsttxm.riskenginesdk.detector.probe.hook.LsposedProbe;
import com.wsttxm.riskenginesdk.detector.probe.hook.ZygiskProbe;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class HookAndDebugDetectorTest {

    // ==================== HookFrameworkDetector ====================

    @Test
    public void hookFrameworkDetectorTruePositiveOnFridaMapsWithEvidenceItem() {
        SignalSnapshot snapshot = cleanHookSnapshot();
        snapshot.seedSelfMapsForTest(SignalResult.success(List.of(
                "7a000000-7a050000 r-xp 00000000 fd:01 1234 /data/local/tmp/libfrida-agent.so")));

        DetectionResult result = new HookFrameworkDetector(null, snapshot).call();
        assertEquals("hook_framework", result.getDetectorName());
        assertEquals(RiskLevel.HIGH, result.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, result.getStatus());
        assertTrue(result.getDetails().contains("frida_maps:/data/local/tmp/libfrida-agent.so"));
        assertTrue(result.getEvidenceItems().stream().anyMatch(
                item -> "frida_maps".equals(item.getCode())
                        && item.getPrimarySource() == EvidenceItem.SourceLayer.JAVA
                        && "/data/local/tmp/libfrida-agent.so".equals(item.getLocation())
                        && item.getRank() == EvidenceItem.Rank.STRONG));
    }

    @Test
    public void hookFrameworkDetectorWeakSignalOnLoopbackPortOnly() {
        SignalSnapshot snapshot = cleanHookSnapshot();
        snapshot.seedLoopbackListeningPortsForTest(SignalResult.success(Set.of(27042)));

        DetectionResult result = new HookFrameworkDetector(null, snapshot).call();
        assertEquals(RiskLevel.LOW, result.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, result.getStatus());
        assertTrue(result.isInformational());
        assertTrue(result.getDetails().contains("frida_port_open:27042"));
    }

    @Test
    public void hookFrameworkDetectorFalsePositiveGuardOnCleanSignals() {
        DetectionResult result = new HookFrameworkDetector(null, cleanHookSnapshot()).call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertTrue(result.getDetails().isEmpty());
    }

    @Test
    public void hookFrameworkDetectorPartialAndTotalFailureSemantics() {
        SignalSnapshot partialSnap = cleanHookSnapshot();
        partialSnap.seedSelfMapsForTest(SignalResult.error("IOException"));
        DetectionResult partial = new HookFrameworkDetector(null, partialSnap).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, partial.getExecutionStatus());
        assertTrue(partial.getChecksFailed() >= 1);

        SignalSnapshot failSnap = new SignalSnapshot(null);
        failSnap.seedSelfMapsForTest(SignalResult.error("EACCES"));
        failSnap.seedLoopbackListeningPortsForTest(SignalResult.error("EACCES"));
        failSnap.seedProcessesForTest(SignalResult.error("EACCES"));
        DetectionResult totalFail = new HookFrameworkDetector(null, failSnap).call();
        assertNotEquals(DetectionExecutionStatus.SAFE, totalFail.getExecutionStatus());
        assertTrue(totalFail.getChecksFailed() >= 3);
    }

    @Test
    public void hookFrameworkDetectorRunsZygiskLsposedAndExtraDbusOnlyInPostponedPass() {
        SignalSnapshot snap = cleanHookSnapshot();
        snap.seedZygiskAtexitProbeForTest(SignalResult.success(
                "status=OK\terrno=0\tstate=COLLECTED\tentries=64\tnull_entries=0\tanchored_gaps=0\tanon_callbacks=1\n"
                        + "kind=atexit_anon_callback\tindex=12\towner=/memfd:zygisk"));

        AtomicInteger postponedCalls = new AtomicInteger(0);
        HookFrameworkDetector detector = new HookFrameworkDetector(
                null, snap, new HookFrameworkDetector.PostponedProbeAdapter() {
            @Override
            public ZygiskProbe.ProbeResult runZygiskProbe(SignalSnapshot s) {
                postponedCalls.incrementAndGet();
                return ZygiskProbe.probe(s::getZygiskAtexitProbe);
            }

            @Override
            public LsposedProbe.ProbeResult runLsposedProbe(Context ctx, SignalSnapshot s) {
                postponedCalls.incrementAndGet();
                return LsposedProbe.probe(ctx, s, new LsposedProbe.Environment() {
                    @Override public android.os.IBinder getServiceBinder(String serviceName) {
                        return "activity".equals(serviceName) ? new android.os.Binder() : null;
                    }
                    @Override public boolean transactMagic(android.os.IBinder b, String svc) { return true; }
                    @Override public Set<String> getGrantedPermissions(Context c) { return Collections.emptySet(); }
                    @Override public String readProcSelfStatus(SignalSnapshot ss) { return null; }
                    @Override public StackTraceElement[] captureProtectedApiExceptionStack(Context c) { return new StackTraceElement[0]; }
                    @Override public java.util.Map<Thread, StackTraceElement[]> getAllStackTraces() { return Collections.emptyMap(); }
                    @Override public Thread.UncaughtExceptionHandler getDefaultUncaughtExceptionHandler() { return null; }
                });
            }

            @Override
            public boolean probeExtraFridaDbusPort(int port) {
                postponedCalls.incrementAndGet();
                return port == 27043;
            }
        });

        assertEquals(ScanTier.CRITICAL, detector.getScanTier());
        assertTrue(detector.hasPostponedProbes());

        // CRITICAL fast pass MUST NOT invoke ZygiskProbe, LsposedProbe, or extra D-Bus ports.
        DetectionResult fast = detector.call();
        assertEquals(0, postponedCalls.get());
        assertEquals(RiskLevel.SAFE, fast.getRiskLevel());
        assertTrue(fast.getDetails().isEmpty());

        // Stage 3 postponed pass consolidates all 3 into structured EvidenceItems and escalates to DEADLY/10.
        DetectionResult postponed = detector.callPostponed(fast);
        assertTrue(postponedCalls.get() >= 5);
        assertEquals(RiskLevel.DEADLY, postponed.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, postponed.getStatus());
        assertEquals(10, postponed.getScore());
        assertFalse(postponed.isInformational());
        assertTrue(postponed.getDetails().contains("zygisk_atexit_anon:12"));
        assertTrue(postponed.getDetails().contains("lsposed_binder_activity_bridge"));
        assertTrue(postponed.getDetails().contains("frida_dbus_port:27043"));
        assertTrue(postponed.getEvidenceItems().stream().anyMatch(
                i -> "hook_integrity".equals(i.getEvidenceFamily()) && "zygisk_atexit_anon".equals(i.getCode())));
        assertTrue(postponed.getEvidenceItems().stream().anyMatch(
                i -> "xposed".equals(i.getEvidenceFamily()) && "lsposed_binder_activity_bridge".equals(i.getCode())));
        assertTrue(postponed.getEvidenceItems().stream().anyMatch(
                i -> "frida".equals(i.getEvidenceFamily()) && "frida_dbus_port".equals(i.getCode())));
    }

    // ==================== DebugDetector ====================

    @Test
    public void debugDetectorTruePositiveOnDebuggerMapsAndDebuggableFlag() {
        SignalSnapshot mapsSnap = cleanDebugSnapshot();
        mapsSnap.seedSelfMapsForTest(SignalResult.success(List.of(
                "700000-710000 r-xp 0000 00:00 0 /data/local/tmp/android_server")));
        DetectionResult mapsResult = new DebugDetector(appInfoContext(0), mapsSnap).call();
        assertEquals("debug", mapsResult.getDetectorName());
        assertEquals(RiskLevel.MEDIUM, mapsResult.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, mapsResult.getStatus());
        assertFalse(mapsResult.isInformational());
        assertTrue(mapsResult.getDetails().contains(
                "maps_exec_path:android_server:/data/local/tmp/android_server"));

        DetectionResult debuggableResult = new DebugDetector(
                appInfoContext(ApplicationInfo.FLAG_DEBUGGABLE), cleanDebugSnapshot()).call();
        assertEquals(ScanTier.CRITICAL, debuggableResult.getScanTier());
        assertEquals(RiskLevel.LOW, debuggableResult.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, debuggableResult.getStatus());
        assertTrue(debuggableResult.isInformational());
        assertTrue(debuggableResult.getDetails().contains("debuggable_flag"));
        assertTrue(CorrelationEngine.applyScene(debuggableResult, CollectScene.STANDARD)
                .isInformational());
        assertTrue(CorrelationEngine.applyScene(debuggableResult, CollectScene.LOGIN)
                .isInformational());
        assertTrue(CorrelationEngine.applyScene(debuggableResult, CollectScene.PAYMENT)
                .isInformational());
        assertTrue(CorrelationEngine.applyScene(debuggableResult, CollectScene.DIAGNOSTIC)
                .isInformational());
        assertTrue(debuggableResult.getEvidenceItems().stream().anyMatch(
                item -> "debuggable_flag".equals(item.getCode())
                        && "debugger".equals(item.getEvidenceFamily())));
    }

    @Test
    public void debugDetectorRestrictedNativeFrameDoesNotTriggerFalsePositive() {
        String restrictedFrame = "status=RESTRICTED\terrno=13\ttracer_pid=0";
        DebugDetector detector = DebugDetector.createForTest(
                appInfoContext(0),
                cleanDebugSnapshot(),
                new DebugDetector.DebugEnvironment() {
                    @Override public SignalResult<String> getNativeDebugEvidence() {
                        return SignalResult.success(restrictedFrame);
                    }
                    @Override public SignalResult<Integer> getNativeTracerPid() {
                        return SignalResult.success(0);
                    }
                    @Override public boolean isDebuggerConnected() { return false; }
                    @Override public boolean isWaitingForDebugger() { return false; }
                });
        DetectionResult result = detector.call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertTrue(result.getDetails().isEmpty());
    }

    @Test
    public void debugDetectorParsesNativeDualPathTracerStatWchanAndJdwpEvidenceItems() {
        String strongFrame = "status=OK\terrno=0\ttracer_pid=4321\n"
                + "code=tracer_pid\tvalue=4321\tloc=/proc/1234/task/1234/status\n"
                + "code=tracer_pid_mismatch\tvalue=self\\=0,alt\\=4321\tloc=/proc/1234/task/1234/status\n"
                + "code=stat_tracing_stop\tvalue=1235\tloc=/proc/self/task/1235/stat\n"
                + "code=wchan_ptrace_stop\tvalue=1235\tloc=/proc/self/task/1235/wchan";

        DebugDetector strongDetector = DebugDetector.createForTest(
                appInfoContext(0),
                cleanDebugSnapshot(),
                new DebugDetector.DebugEnvironment() {
                    @Override public SignalResult<String> getNativeDebugEvidence() {
                        return SignalResult.success(strongFrame);
                    }
                    @Override public SignalResult<Integer> getNativeTracerPid() {
                        return SignalResult.success(0);
                    }
                    @Override public boolean isDebuggerConnected() { return false; }
                    @Override public boolean isWaitingForDebugger() { return false; }
                });
        DetectionResult strongResult = strongDetector.call();
        assertEquals(ScanTier.CRITICAL, strongResult.getScanTier());
        assertEquals(RiskLevel.HIGH, strongResult.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, strongResult.getStatus());
        assertEquals(8, strongResult.getScore());
        assertFalse(strongResult.isInformational());
        assertTrue(strongResult.getDetails().contains("tracer_pid:4321"));
        assertTrue(strongResult.getDetails().contains("tracer_pid_mismatch:self=0,alt=4321"));
        assertTrue(strongResult.getDetails().contains("stat_tracing_stop:1235"));
        assertTrue(strongResult.getDetails().contains("wchan_ptrace_stop:1235"));
        assertTrue(strongResult.getEvidenceItems().stream().anyMatch(
                item -> "stat_tracing_stop".equals(item.getCode())
                        && "debugger".equals(item.getEvidenceFamily())
                        && item.getRank() == EvidenceItem.Rank.STRONG));
        assertTrue(strongResult.getEvidenceItems().stream().anyMatch(
                item -> "wchan_ptrace_stop".equals(item.getCode())
                        && "debugger".equals(item.getEvidenceFamily())
                        && item.getRank() == EvidenceItem.Rank.STRONG));

        String jdwpFrame = "status=OK\terrno=0\ttracer_pid=0\n"
                + "code=jdwp_thread\tvalue=ADB connection\tloc=/proc/self/task/1240/comm\n"
                + "code=jdwp_socket\tvalue=@jdwp-control\tloc=/proc/net/unix";
        DebugDetector jdwpDetector = DebugDetector.createForTest(
                appInfoContext(0),
                cleanDebugSnapshot(),
                new DebugDetector.DebugEnvironment() {
                    @Override public SignalResult<String> getNativeDebugEvidence() {
                        return SignalResult.success(jdwpFrame);
                    }
                    @Override public SignalResult<Integer> getNativeTracerPid() {
                        return SignalResult.success(0);
                    }
                    @Override public boolean isDebuggerConnected() { return false; }
                    @Override public boolean isWaitingForDebugger() { return false; }
                });
        DetectionResult jdwpResult = jdwpDetector.call();
        assertEquals(RiskLevel.MEDIUM, jdwpResult.getRiskLevel());
        assertEquals(4, jdwpResult.getScore());
        assertFalse(jdwpResult.isInformational());
        assertTrue(jdwpResult.getDetails().contains("jdwp_thread:ADB connection"));
        assertTrue(jdwpResult.getDetails().contains("jdwp_socket:@jdwp-control"));
        assertTrue(jdwpResult.getEvidenceItems().stream().anyMatch(
                item -> "jdwp_thread".equals(item.getCode())
                        && "debugger".equals(item.getEvidenceFamily())
                        && item.getRank() == EvidenceItem.Rank.MEDIUM));

        // On FLAG_DEBUGGABLE builds with no active debugger attached, idle ADB-JDWP stays informational.
        DebugDetector debuggableJdwpDetector = DebugDetector.createForTest(
                appInfoContext(ApplicationInfo.FLAG_DEBUGGABLE),
                cleanDebugSnapshot(),
                new DebugDetector.DebugEnvironment() {
                    @Override public SignalResult<String> getNativeDebugEvidence() {
                        return SignalResult.success(jdwpFrame);
                    }
                    @Override public SignalResult<Integer> getNativeTracerPid() {
                        return SignalResult.success(0);
                    }
                    @Override public boolean isDebuggerConnected() { return false; }
                    @Override public boolean isWaitingForDebugger() { return false; }
                });
        DetectionResult debuggableJdwp = debuggableJdwpDetector.call();
        assertEquals(RiskLevel.LOW, debuggableJdwp.getRiskLevel());
        assertEquals(1, debuggableJdwp.getScore());
        assertTrue(debuggableJdwp.isInformational());
        assertTrue(debuggableJdwp.getEvidenceItems().stream().anyMatch(
                item -> "jdwp_thread".equals(item.getCode())
                        && item.getRank() == EvidenceItem.Rank.INFO));

        // Active debugger connection on FLAG_DEBUGGABLE build MUST still score MEDIUM/4 actionable.
        DebugDetector activeDebuggableDetector = DebugDetector.createForTest(
                appInfoContext(ApplicationInfo.FLAG_DEBUGGABLE),
                cleanDebugSnapshot(),
                new DebugDetector.DebugEnvironment() {
                    @Override public SignalResult<String> getNativeDebugEvidence() {
                        return SignalResult.success(jdwpFrame);
                    }
                    @Override public SignalResult<Integer> getNativeTracerPid() {
                        return SignalResult.success(0);
                    }
                    @Override public boolean isDebuggerConnected() { return true; }
                    @Override public boolean isWaitingForDebugger() { return false; }
                });
        DetectionResult activeDebuggable = activeDebuggableDetector.call();
        assertEquals(RiskLevel.MEDIUM, activeDebuggable.getRiskLevel());
        assertEquals(4, activeDebuggable.getScore());
        assertFalse(activeDebuggable.isInformational());
    }

    @Test
    public void debugDetectorWeakSignalOnIdaPortOnly() {
        SignalSnapshot snap = cleanDebugSnapshot();
        snap.seedLoopbackListeningPortsForTest(SignalResult.success(Set.of(23946)));

        DetectionResult result = new DebugDetector(appInfoContext(0), snap).call();
        assertEquals(RiskLevel.LOW, result.getRiskLevel());
        assertTrue(result.isInformational());
        assertTrue(result.getDetails().contains("ida_port_open:23946"));
    }

    @Test
    public void debugDetectorFalsePositiveGuardOnCleanSignals() {
        DetectionResult result = new DebugDetector(
                appInfoContext(0), cleanDebugSnapshot()).call();
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertTrue(result.getDetails().isEmpty());
    }

    @Test
    public void debugDetectorPartialAndTotalFailureSemantics() {
        SignalSnapshot partialSnap = cleanDebugSnapshot();
        partialSnap.seedSelfMapsForTest(SignalResult.error("EACCES"));
        DetectionResult partial = new DebugDetector(appInfoContext(0), partialSnap).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, partial.getExecutionStatus());
        assertTrue(partial.getChecksFailed() >= 1);

        SignalSnapshot failSnap = new SignalSnapshot(null);
        failSnap.seedSelfMapsForTest(SignalResult.error("EACCES"));
        failSnap.seedLoopbackListeningPortsForTest(SignalResult.error("EACCES"));
        DetectionResult failed = new DebugDetector(null, failSnap).call();
        assertNotEquals(DetectionExecutionStatus.SAFE, failed.getExecutionStatus());
        if (failed.getExecutionStatus() == DetectionExecutionStatus.UNAVAILABLE) {
            assertEquals(RiskLevel.UNKNOWN, failed.getRiskLevel());
            assertEquals(0, failed.getChecksSucceeded());
        } else {
            assertEquals(DetectionExecutionStatus.PARTIAL, failed.getExecutionStatus());
            assertTrue(failed.getChecksFailed() >= 3);
        }
    }

    private static SignalSnapshot cleanHookSnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedSelfMapsForTest(SignalResult.success(List.of(
                "700000-710000 r-xp 0000 00:00 10 /system/lib64/libc.so")));
        snapshot.seedLoopbackListeningPortsForTest(SignalResult.success(Collections.emptySet()));
        snapshot.seedProcessesForTest(SignalResult.success(Collections.emptyList()));
        return snapshot;
    }

    private static SignalSnapshot cleanDebugSnapshot() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        snapshot.seedSelfMapsForTest(SignalResult.success(List.of(
                "700000-710000 r-xp 0000 00:00 10 /system/lib64/libc.so")));
        snapshot.seedLoopbackListeningPortsForTest(SignalResult.success(Collections.emptySet()));
        return snapshot;
    }

    private static Context appInfoContext(int flags) {
        ApplicationInfo info = new ApplicationInfo();
        info.flags = flags;
        return new ContextWrapper(null) {
            @Override
            public Context getApplicationContext() {
                return this;
            }

            @Override
            public ApplicationInfo getApplicationInfo() {
                return info;
            }
        };
    }
}
