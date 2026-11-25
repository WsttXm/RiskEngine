package com.wsttxm.riskenginesdk;

import android.app.Activity;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeMonitorDispatcher;
import com.wsttxm.riskenginesdk.core.AppLifecycleObserver;
import com.wsttxm.riskenginesdk.core.HookEvidenceClassifier;
import com.wsttxm.riskenginesdk.detector.ScreenAndFraudDetector;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.ThreatEvent;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.junit.Assert.*;

public class PeriodicMonitorAndLifecycleTest {

    @Before
    @After
    public void cleanup() {
        NativeMonitorDispatcher.clearListeners();
        ScreenAndFraudDetector.resetRuntimeStateForTest();
    }

    @Test
    public void nativeMonitorDispatcherRoutesMonitorTokensToThreatEventsAndIsolatesFaultyListeners() {
        List<ThreatEvent> received = new ArrayList<>();
        NativeMonitorDispatcher.addListener(event -> {
            throw new RuntimeException("faulty host listener must not break native upcall");
        });
        NativeMonitorDispatcher.addListener(received::add);

        NativeMonitorDispatcher.onNativeThreatDetected("late_text_mismatch", "periodic_monitor");
        NativeMonitorDispatcher.onNativeThreatDetected("late_frida_fd", "periodic_monitor");
        NativeMonitorDispatcher.onNativeThreatDetected("late_tracer_attached", "periodic_monitor");
        NativeMonitorDispatcher.onNativeThreatDetected("", "periodic_monitor");

        assertEquals(3, received.size());

        ThreatEvent textEvent = received.get(0);
        assertEquals("hook_framework", textEvent.getDetectorName());
        assertEquals(RiskLevel.DEADLY, textEvent.getRiskLevel());
        assertEquals(10, textEvent.getScore());
        assertTrue(textEvent.isRuntimeTamper());
        assertTrue(textEvent.getEvidenceFamilies().contains("hook_integrity"));

        ThreatEvent fdEvent = received.get(1);
        assertEquals("hook_framework", fdEvent.getDetectorName());
        assertEquals(RiskLevel.HIGH, fdEvent.getRiskLevel());
        assertEquals(8, fdEvent.getScore());
        assertTrue(fdEvent.getEvidenceFamilies().contains("frida"));

        ThreatEvent tracerEvent = received.get(2);
        assertEquals("debug", tracerEvent.getDetectorName());
        assertEquals(RiskLevel.HIGH, tracerEvent.getRiskLevel());
        assertEquals(8, tracerEvent.getScore());
        assertTrue(tracerEvent.getEvidenceFamilies().contains("debugger"));
    }

    @Test
    public void appLifecycleObserverTracksForegroundBackgroundAndIgnoresConfigChanges() {
        List<Boolean> transitions = new ArrayList<>();
        AppLifecycleObserver observer = new AppLifecycleObserver(
                transitions::add, new FakeScreenHookRegistrar());

        Activity activity1 = new TestActivity(false);
        Activity rotatingActivity = new TestActivity(true);

        observer.onActivityStarted(activity1);
        assertFalse(observer.isInBackground());
        assertTrue(transitions.isEmpty());

        // Stop due to configuration change (rotation) must NOT signal background
        observer.onActivityStopped(rotatingActivity);
        assertFalse(observer.isInBackground());
        assertTrue(transitions.isEmpty());

        // Start recreated activity after rotation
        observer.onActivityStarted(activity1);
        assertFalse(observer.isInBackground());
        assertTrue(transitions.isEmpty());

        // True background transition
        observer.onActivityStopped(activity1);
        assertTrue(observer.isInBackground());
        assertEquals(List.of(Boolean.TRUE), transitions);

        // Foreground resume
        observer.onActivityStarted(activity1);
        assertFalse(observer.isInBackground());
        assertEquals(List.of(Boolean.TRUE, Boolean.FALSE), transitions);
    }

    @Test
    public void appLifecycleObserverGatesScreenHooksByPermissionAndFeedsScreenAndFraudDetector() {
        FakeScreenHookRegistrar registrar = new FakeScreenHookRegistrar();
        registrar.grantedPermissions.add("android.permission.DETECT_SCREEN_CAPTURE");
        registrar.grantedPermissions.add("android.permission.DETECT_SCREEN_RECORDING");

        List<ThreatEvent> screenEvents = new ArrayList<>();
        AppLifecycleObserver observer = new AppLifecycleObserver(bg -> {}, registrar);
        observer.setScreenEventListener(screenEvents::add);

        Activity activity = new TestActivity(false);
        observer.onActivityStarted(activity);
        assertEquals(1, registrar.captureRegisterCount.get());
        assertEquals(1, registrar.recordingRegisterCount.get());

        // Simulate API 34 screen capture callback
        registrar.lastCaptureCallback.run();
        assertTrue(ScreenAndFraudDetector.getLastScreenCaptureWallMs() > 0L);

        // Simulate API 35 screen recording start & stop
        registrar.lastRecordingCallback.accept(true);
        assertTrue(ScreenAndFraudDetector.isScreenRecordingActive());
        registrar.lastRecordingCallback.accept(false);
        assertFalse(ScreenAndFraudDetector.isScreenRecordingActive());

        assertEquals(2, screenEvents.size());
        assertEquals("screen_and_fraud", screenEvents.get(0).getDetectorName());
        assertTrue(screenEvents.get(0).getDetails().contains("screen_capture_observed"));
        assertTrue(screenEvents.get(1).getDetails().contains("screen_recording_active"));

        // Stop detaches both callbacks cleanly
        observer.onActivityStopped(activity);
        assertEquals(1, registrar.captureUnregisterCount.get());
        assertEquals(1, registrar.recordingUnregisterCount.get());
    }

    @Test
    public void appLifecycleObserverSkipsHooksWithoutPermissionAndCatchesSecurityExceptions() {
        FakeScreenHookRegistrar deniedRegistrar = new FakeScreenHookRegistrar();
        // No permissions granted -> zero register attempts
        AppLifecycleObserver observer1 = new AppLifecycleObserver(bg -> {}, deniedRegistrar);
        Activity activity = new TestActivity(false);
        observer1.onActivityStarted(activity);
        assertEquals(0, deniedRegistrar.captureRegisterCount.get());
        assertEquals(0, deniedRegistrar.recordingRegisterCount.get());

        // Even if platform throws SecurityException or LinkageError, observer never crashes
        FakeScreenHookRegistrar throwingRegistrar = new FakeScreenHookRegistrar() {
            @Override
            public boolean hasPermission(Activity a, String permission) {
                return true;
            }
            @Override
            public Object registerScreenCaptureCallback(Activity a, Runnable onCaptured) {
                throw new SecurityException("missing DETECT_SCREEN_CAPTURE");
            }
            @Override
            public Object registerScreenRecordingCallback(Activity a,
                                                          Consumer<Boolean> onRecordingChanged) {
                throw new NoSuchMethodError("pre-API-35");
            }
        };
        AppLifecycleObserver observer2 = new AppLifecycleObserver(bg -> {}, throwingRegistrar);
        observer2.onActivityStarted(activity);
        observer2.onActivityStopped(activity);
        assertFalse(ScreenAndFraudDetector.isScreenRecordingActive());
    }

    @Test
    public void hookEvidenceClassifierRanksLateFridaFdAsStrong() {
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("late_frida_fd"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("late_text_mismatch"));
    }

    private static final class TestActivity extends Activity {
        private final boolean changing;

        TestActivity(boolean changing) {
            this.changing = changing;
        }

        @Override
        public boolean isChangingConfigurations() {
            return changing;
        }
    }

    private static class FakeScreenHookRegistrar
            implements AppLifecycleObserver.ScreenHookRegistrar {
        final Set<String> grantedPermissions = new HashSet<>();
        final AtomicInteger captureRegisterCount = new AtomicInteger();
        final AtomicInteger captureUnregisterCount = new AtomicInteger();
        final AtomicInteger recordingRegisterCount = new AtomicInteger();
        final AtomicInteger recordingUnregisterCount = new AtomicInteger();
        Runnable lastCaptureCallback;
        Consumer<Boolean> lastRecordingCallback;

        @Override
        public boolean hasPermission(Activity activity, String permission) {
            return grantedPermissions.contains(permission);
        }

        @Override
        public Object registerScreenCaptureCallback(Activity activity, Runnable onCaptured) {
            captureRegisterCount.incrementAndGet();
            lastCaptureCallback = onCaptured;
            return new Object();
        }

        @Override
        public void unregisterScreenCaptureCallback(Activity activity, Object handle) {
            captureUnregisterCount.incrementAndGet();
        }

        @Override
        public Object registerScreenRecordingCallback(Activity activity,
                                                      Consumer<Boolean> onRecordingChanged) {
            recordingRegisterCount.incrementAndGet();
            lastRecordingCallback = onRecordingChanged;
            return new Object();
        }

        @Override
        public void unregisterScreenRecordingCallback(Activity activity, Object handle) {
            recordingUnregisterCount.incrementAndGet();
        }
    }
}
