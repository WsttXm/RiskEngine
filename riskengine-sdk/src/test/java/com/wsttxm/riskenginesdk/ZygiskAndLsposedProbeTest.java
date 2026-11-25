package com.wsttxm.riskenginesdk;

import android.Manifest;
import android.content.Context;
import android.os.Binder;
import android.os.IBinder;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.hook.LsposedProbe;
import com.wsttxm.riskenginesdk.detector.probe.hook.ZygiskProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ZygiskAndLsposedProbeTest {

    // ==================== ZygiskProbe ====================

    @Test
    public void zygiskProbeCleanPayloadEmitsZeroFindings() {
        String cleanWire = "status=OK\terrno=0\tstate=COLLECTED\tentries=64\tnull_entries=1"
                + "\tanchored_gaps=0\tanon_callbacks=0";
        ZygiskProbe.ProbeResult result = ZygiskProbe.parsePayload(cleanWire);
        assertTrue(result.isUsable());
        assertEquals("COLLECTED", result.getState());
        assertEquals(64, result.getEntryCount());
        assertEquals(1, result.getNullEntryCount());
        assertFalse(result.hasFindings());
        assertTrue(result.getStrongTokens().isEmpty());
        assertTrue(result.getMediumTokens().isEmpty());
        assertTrue(result.getEvidenceItems().isEmpty());
    }

    @Test
    public void zygiskProbeDetectsAnonymousExecutableCallbackAndRuntimeDriftAsStrong() {
        String wire = "status=OK\terrno=0\tstate=COLLECTED\tentries=80\tnull_entries=0"
                + "\tanchored_gaps=0\tanon_callbacks=1\n"
                + "kind=atexit_anon_callback\tindex=27\towner=/memfd:zygisk_loader\n"
                + "kind=atexit_runtime_drift\tatexit_owner=/data/local/tmp/libhook.so\tfinalize_owner=/apex/com.android.runtime/lib64/bionic/libc.so";
        ZygiskProbe.ProbeResult result = ZygiskProbe.parsePayload(wire);
        assertTrue(result.isUsable());
        assertTrue(result.hasFindings());
        assertEquals(1, result.getAnonCallbackCount());
        assertTrue(result.getStrongTokens().contains("zygisk_atexit_anon:27"));
        assertTrue(result.getStrongTokens().contains("zygisk_atexit_drift"));
        assertEquals(2, result.getEvidenceItems().size());
        EvidenceItem item = result.getEvidenceItems().get(0);
        assertEquals("zygisk_atexit_anon", item.getCode());
        assertEquals("/memfd:zygisk_loader", item.getLocation());
        assertEquals("hook_integrity", item.getEvidenceFamily());
        assertEquals(EvidenceItem.SourceLayer.NATIVE, item.getPrimarySource());
        assertEquals(EvidenceItem.Rank.STRONG, item.getRank());
    }

    @Test
    public void zygiskProbeDetectsThreeOrMoreContiguousHolesAndIgnoresSmallRuns() {
        String wire = "status=OK\terrno=0\tstate=COLLECTED\tentries=96\tnull_entries=5"
                + "\tanchored_gaps=1\tanon_callbacks=0\n"
                + "kind=atexit_hole_run\tstart=10\tend=11\tcount=2\n"
                + "kind=atexit_hole_run\tstart=32\tend=35\tcount=4";
        ZygiskProbe.ProbeResult result = ZygiskProbe.parsePayload(wire);
        assertTrue(result.isUsable());
        assertTrue(result.hasFindings());
        assertTrue(result.getStrongTokens().isEmpty());
        assertEquals(1, result.getMediumTokens().size());
        assertTrue(result.getMediumTokens().contains("zygisk_atexit_holes:4@32"));
        assertEquals(1, result.getEvidenceItems().size());
        EvidenceItem item = result.getEvidenceItems().get(0);
        assertEquals("zygisk_atexit_holes", item.getCode());
        assertEquals("atexit[32..35]", item.getLocation());
        assertEquals("holes=4", item.getValue());
        assertEquals("hook_integrity", item.getEvidenceFamily());
        assertEquals(EvidenceItem.Rank.MEDIUM, item.getRank());
    }

    @Test
    public void zygiskProbeHandlesSymbolUnavailableRestrictedBusyAndMalformedGracefully() {
        String unsupported = "status=UNSUPPORTED\terrno=0\tstate=UNSUPPORTED\tentries=0"
                + "\tnull_entries=0\tanchored_gaps=0\tanon_callbacks=0";
        ZygiskProbe.ProbeResult symMissing = ZygiskProbe.parsePayload(unsupported);
        assertFalse(symMissing.isUsable());
        assertEquals(NativePayloadCodec.Status.UNSUPPORTED, symMissing.getStatus());
        assertEquals("UNSUPPORTED", symMissing.getState());
        assertFalse(symMissing.hasFindings());

        String restricted = "status=RESTRICTED\terrno=13\tstate=UNAVAILABLE\tentries=0";
        ZygiskProbe.ProbeResult denied = ZygiskProbe.parsePayload(restricted);
        assertFalse(denied.isUsable());
        assertEquals(NativePayloadCodec.Status.RESTRICTED, denied.getStatus());
        assertFalse(denied.hasFindings());

        String busy = "status=UNSUPPORTED\terrno=16\tstate=BUSY\tentries=0"
                + "\tnull_entries=0\tanchored_gaps=0\tanon_callbacks=0";
        ZygiskProbe.ProbeResult contended = ZygiskProbe.parsePayload(busy);
        assertFalse(contended.isUsable());
        assertEquals("BUSY", contended.getState());
        assertEquals(16, contended.getErrno());
        assertFalse(contended.hasFindings());

        ZygiskProbe.ProbeResult malformed = ZygiskProbe.parsePayload("not_a_valid_frame");
        assertFalse(malformed.isUsable());
        assertTrue(malformed.isMalformed());
        assertFalse(malformed.hasFindings());

        ZygiskProbe.ProbeResult nativeAbsent = ZygiskProbe.probe(
                () -> SignalResult.unavailable("native_library_unavailable"));
        assertFalse(nativeAbsent.isUsable());
        assertFalse(nativeAbsent.hasFindings());
    }

    // ==================== LsposedProbe ====================

    @Test
    public void lsposedProbeCleanEnvironmentEmitsZeroFindings() {
        LsposedProbe.ProbeResult result = LsposedProbe.probe(null, null, new LsposedProbe.Environment() {
            @Override public IBinder getServiceBinder(String serviceName) { return new Binder(); }
            @Override public boolean transactMagic(IBinder binder, String serviceName) { return false; }
            @Override public Set<String> getGrantedPermissions(Context context) {
                return Set.of(Manifest.permission.INTERNET);
            }
            @Override public String readProcSelfStatus(SignalSnapshot signals) {
                return "Name:\tapp\nGroups:\t3003 9997 20123 50123\n";
            }
            @Override public StackTraceElement[] captureProtectedApiExceptionStack(Context context) {
                return new StackTraceElement[]{
                        new StackTraceElement("android.app.ApplicationPackageManager", "getPackageInfo", "ApplicationPackageManager.java", 200)
                };
            }
            @Override public Map<Thread, StackTraceElement[]> getAllStackTraces() {
                return Collections.singletonMap(Thread.currentThread(), new StackTraceElement[]{
                        new StackTraceElement("com.example.App", "run", "App.java", 10)
                });
            }
            @Override public Thread.UncaughtExceptionHandler getDefaultUncaughtExceptionHandler() {
                return new ThreadGroup("clean");
            }
        });
        assertFalse(result.hasFindings());
        assertTrue(result.getSubProbesRun() >= 5);
    }

    @Test
    public void lsposedProbeDetectsBinderMagicZygoteGidMismatchStacksAndUncaughtHandler() {
        final Thread.UncaughtExceptionHandler fakeLspHandler = new LsposedFakeUncaughtHandler();
        LsposedProbe.ProbeResult result = LsposedProbe.probe(null, null, new LsposedProbe.Environment() {
            @Override public IBinder getServiceBinder(String serviceName) { return new Binder(); }
            @Override public boolean transactMagic(IBinder binder, String serviceName) {
                if ("activity".equals(serviceName)) {
                    return true;
                }
                throw new SecurityException("Blocked by LSPosed bridge");
            }
            @Override public Set<String> getGrantedPermissions(Context context) {
                return Set.of(Manifest.permission.INTERNET);
            }
            @Override public String readProcSelfStatus(SignalSnapshot signals) {
                // Granted INTERNET but missing INET_GID 3003 -> Zygote permission filtering anomaly.
                return "Name:\tapp\nGroups:\t9997 20123\n";
            }
            @Override public StackTraceElement[] captureProtectedApiExceptionStack(Context context) {
                return new StackTraceElement[]{
                        new StackTraceElement("LSPHooker_", "hook", "LSP", 1)
                };
            }
            @Override public Map<Thread, StackTraceElement[]> getAllStackTraces() {
                return Collections.singletonMap(Thread.currentThread(), new StackTraceElement[]{
                        new StackTraceElement("de.robv.android.xposed.XposedBridge", "handleHookedMethod", "XposedBridge.java", 42)
                });
            }
            @Override public Thread.UncaughtExceptionHandler getDefaultUncaughtExceptionHandler() {
                return fakeLspHandler;
            }
        });

        assertTrue(result.hasFindings());
        assertTrue(result.getStrongTokens().contains("lsposed_binder_activity_bridge"));
        assertTrue(result.getStrongTokens().contains("lsposed_binder_serial_exception"));
        assertTrue(result.getStrongTokens().contains("lsposed_zygote_gid_mismatch:internet"));
        assertTrue(result.getStrongTokens().stream().anyMatch(t -> t.startsWith("lsposed_protected_api_stack:")));
        assertTrue(result.getStrongTokens().stream().anyMatch(t -> t.startsWith("lsposed_all_threads_stack:")));
        assertTrue(result.getMediumTokens().stream().anyMatch(t -> t.startsWith("lsposed_uncaught_handler:")));
        assertTrue(result.getEvidenceItems().stream()
                .allMatch(i -> "xposed".equals(i.getEvidenceFamily())));
    }

    private static final class LsposedFakeUncaughtHandler implements Thread.UncaughtExceptionHandler {
        @Override
        public void uncaughtException(Thread t, Throwable e) {
            // Test stub whose class name matches LSPosed framework token.
        }
    }
}
