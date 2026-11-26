package com.wsttxm.riskenginesdk.core;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.detector.ScreenAndFraudDetector;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Zero-dependency foreground/background & API 34/35 screen capture/recording lifecycle observer
 * built solely on platform {@link Application.ActivityLifecycleCallbacks}.
 *
 * <p>Never requires {@code androidx.lifecycle} or forced manifest permissions:
 * <ul>
 *   <li>Drives {@link NativeCollectorBridge#setMonitorBackground(boolean)} for 120s background
 *       backoff and immediate &gt;10s foreground-resume rechecks while ignoring configuration
 *       changes (e.g. screen rotation).</li>
 *   <li>Opportunistically attaches API 34 {@code Activity.ScreenCaptureCallback} and API 35
 *       {@code WindowManager.addScreenRecordingCallback} ONLY when the host holds the respective
 *       runtime permission, wrapped in {@code try/catch(SecurityException | LinkageError)}, and
 *       propagates state into {@link ScreenAndFraudDetector} and optional event listeners.</li>
 * </ul>
 */
public final class AppLifecycleObserver implements Application.ActivityLifecycleCallbacks {

    private static final String PERMISSION_DETECT_SCREEN_CAPTURE =
            "android.permission.DETECT_SCREEN_CAPTURE";
    private static final String PERMISSION_DETECT_SCREEN_RECORDING =
            "android.permission.DETECT_SCREEN_RECORDING";
    private static final int SCREEN_RECORDING_STATE_VISIBLE = 1;

    /** Callback receiving foreground/background transitions (injectable for pure-JVM tests). */
    public interface BackgroundStateSink {
        void onBackgroundChanged(boolean isBackground);
    }

    /** Callback receiving real-time screen capture or screen recording threat events. */
    public interface ScreenEventListener {
        void onScreenEvent(ThreatEvent event);
    }

    /** Abstraction over API 34/35 Activity/WindowManager registration for JVM testing. */
    public interface ScreenHookRegistrar {
        boolean hasPermission(Activity activity, String permission);
        Object registerScreenCaptureCallback(Activity activity, Runnable onCaptured);
        void unregisterScreenCaptureCallback(Activity activity, Object handle);
        Object registerScreenRecordingCallback(Activity activity, Consumer<Boolean> onRecordingChanged);
        void unregisterScreenRecordingCallback(Activity activity, Object handle);
    }

    private final BackgroundStateSink backgroundSink;
    private final ScreenHookRegistrar hookRegistrar;
    private final Object lock = new Object();
    private final AtomicBoolean registered = new AtomicBoolean(false);
    private final Map<Activity, Object> captureHandles = new IdentityHashMap<>();
    private final Map<Activity, Object> recordingHandles = new IdentityHashMap<>();

    private volatile ScreenEventListener screenEventListener;
    private Application registeredApp;
    private int startedCount = 0;
    private boolean changingConfig = false;
    private boolean background = false;

    public AppLifecycleObserver() {
        this(NativeCollectorBridge::setMonitorBackground, new AndroidScreenHookRegistrar());
    }

    /** Internal/test constructor with injectable sinks and hook registrar. */
    public AppLifecycleObserver(BackgroundStateSink backgroundSink,
                                ScreenHookRegistrar hookRegistrar) {
        this.backgroundSink = backgroundSink != null
                ? backgroundSink
                : NativeCollectorBridge::setMonitorBackground;
        this.hookRegistrar = hookRegistrar != null
                ? hookRegistrar
                : new AndroidScreenHookRegistrar();
    }

    public void setScreenEventListener(ScreenEventListener listener) {
        this.screenEventListener = listener;
    }

    public boolean isInBackground() {
        synchronized (lock) {
            return background;
        }
    }

    public boolean register(Context context) {
        if (context == null) return false;
        Context appCtx = context.getApplicationContext();
        if (!(appCtx instanceof Application)) {
            return false;
        }
        return register((Application) appCtx);
    }

    public boolean register(Application application) {
        if (application == null) return false;
        if (!registered.compareAndSet(false, true)) {
            return false;
        }
        synchronized (lock) {
            this.registeredApp = application;
        }
        try {
            application.registerActivityLifecycleCallbacks(this);
            return true;
        } catch (Exception | LinkageError e) {
            registered.set(false);
            synchronized (lock) {
                this.registeredApp = null;
            }
            CLog.w("AppLifecycleObserver registration failed: " + e.getMessage());
            return false;
        }
    }

    public void unregister() {
        if (!registered.compareAndSet(true, false)) {
            return;
        }
        Application app;
        Map<Activity, Object> capturesToClean;
        Map<Activity, Object> recordingsToClean;
        synchronized (lock) {
            app = this.registeredApp;
            this.registeredApp = null;
            this.startedCount = 0;
            this.changingConfig = false;
            this.background = false;
            capturesToClean = new IdentityHashMap<>(captureHandles);
            recordingsToClean = new IdentityHashMap<>(recordingHandles);
            captureHandles.clear();
            recordingHandles.clear();
        }
        for (Map.Entry<Activity, Object> entry : capturesToClean.entrySet()) {
            safeUnregisterCapture(entry.getKey(), entry.getValue());
        }
        for (Map.Entry<Activity, Object> entry : recordingsToClean.entrySet()) {
            safeUnregisterRecording(entry.getKey(), entry.getValue());
        }
        if (app != null) {
            try {
                app.unregisterActivityLifecycleCallbacks(this);
            } catch (Exception | LinkageError e) {
                CLog.w("AppLifecycleObserver unregister failed: " + e.getMessage());
            }
        }
    }

    @Override
    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {}

    @Override
    public void onActivityStarted(Activity activity) {
        boolean becameForeground = false;
        synchronized (lock) {
            boolean wasZero = (startedCount == 0);
            startedCount++;
            if (wasZero && !changingConfig) {
                if (background) {
                    background = false;
                    becameForeground = true;
                }
            }
            changingConfig = false;
        }
        if (becameForeground) {
            notifyBackgroundSink(false);
        }
        attachScreenHooks(activity);
    }

    @Override
    public void onActivityResumed(Activity activity) {}

    @Override
    public void onActivityPaused(Activity activity) {}

    @Override
    public void onActivityStopped(Activity activity) {
        detachScreenHooks(activity);
        boolean becameBackground = false;
        boolean isChanging = false;
        if (activity != null) {
            try {
                isChanging = activity.isChangingConfigurations();
            } catch (Exception | LinkageError ignored) {
                isChanging = false;
            }
        }
        synchronized (lock) {
            changingConfig = isChanging;
            if (startedCount > 0) {
                startedCount--;
            }
            if (startedCount == 0 && !isChanging && !background) {
                background = true;
                becameBackground = true;
            }
        }
        if (becameBackground) {
            notifyBackgroundSink(true);
        }
    }

    @Override
    public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}

    @Override
    public void onActivityDestroyed(Activity activity) {
        detachScreenHooks(activity);
    }

    /** Internal/package hook invoked when API 34 screen capture callback fires. */
    void handleScreenCaptureObserved() {
        ScreenAndFraudDetector.notifyScreenCaptureObserved();
        ScreenEventListener listener = screenEventListener;
        if (listener == null) return;
        EvidenceItem item = new EvidenceItem(
                "screen_capture_observed",
                EvidenceItem.SourceLayer.JAVA,
                "Activity.ScreenCaptureCallback",
                "captured",
                "screen_control",
                EvidenceItem.Rank.WEAK
        );
        ThreatEvent event = new ThreatEvent(
                "screen_and_fraud",
                RiskLevel.LOW,
                ScanTier.FAST,
                1,
                "screen_capture_observed",
                Collections.singletonList("screen_capture_observed"),
                Collections.singletonList(item),
                Collections.singleton("screen_control"),
                true,
                System.currentTimeMillis()
        );
        try {
            listener.onScreenEvent(event);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("ScreenEventListener failed on screen capture", e);
        }
    }

    /** Internal/package hook invoked when API 35 screen recording state changes. */
    void handleScreenRecordingStateChanged(boolean recordingActive) {
        ScreenAndFraudDetector.setScreenRecordingActive(recordingActive);
        if (!recordingActive) {
            return;
        }
        ScreenEventListener listener = screenEventListener;
        if (listener == null) return;
        EvidenceItem item = new EvidenceItem(
                "screen_recording_active",
                EvidenceItem.SourceLayer.JAVA,
                "WindowManager",
                "recording=true",
                "screen_control",
                EvidenceItem.Rank.STRONG
        );
        ThreatEvent event = new ThreatEvent(
                "screen_and_fraud",
                RiskLevel.MEDIUM,
                ScanTier.FAST,
                5,
                "screen_recording_active",
                Collections.singletonList("screen_recording_active"),
                Collections.singletonList(item),
                Collections.singleton("screen_control"),
                true,
                System.currentTimeMillis()
        );
        try {
            listener.onScreenEvent(event);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("ScreenEventListener failed on screen recording", e);
        }
    }

    private void attachScreenHooks(Activity activity) {
        if (activity == null) return;
        // API 34+ ScreenCaptureCallback (strictly gated on runtime permission + catch)
        try {
            if (hookRegistrar.hasPermission(activity, PERMISSION_DETECT_SCREEN_CAPTURE)) {
                Object handle = hookRegistrar.registerScreenCaptureCallback(
                        activity, this::handleScreenCaptureObserved);
                if (handle != null) {
                    Object previous;
                    synchronized (lock) {
                        previous = captureHandles.put(activity, handle);
                    }
                    if (previous != null) {
                        safeUnregisterCapture(activity, previous);
                    }
                }
            }
        } catch (SecurityException | LinkageError e) {
            CLog.w("ScreenCaptureCallback unavailable: " + e.getMessage());
        } catch (Exception e) {
            CLog.w("ScreenCaptureCallback registration failed: " + e.getMessage());
        }

        // API 35+ WindowManager.addScreenRecordingCallback (strictly gated on runtime permission)
        try {
            if (hookRegistrar.hasPermission(activity, PERMISSION_DETECT_SCREEN_RECORDING)) {
                Object handle = hookRegistrar.registerScreenRecordingCallback(
                        activity, this::handleScreenRecordingStateChanged);
                if (handle != null) {
                    Object previous;
                    synchronized (lock) {
                        previous = recordingHandles.put(activity, handle);
                    }
                    if (previous != null) {
                        safeUnregisterRecording(activity, previous);
                    }
                }
            }
        } catch (SecurityException | LinkageError e) {
            CLog.w("ScreenRecordingCallback unavailable: " + e.getMessage());
        } catch (Exception e) {
            CLog.w("ScreenRecordingCallback registration failed: " + e.getMessage());
        }
    }

    private void detachScreenHooks(Activity activity) {
        if (activity == null) return;
        Object captureHandle;
        Object recordingHandle;
        synchronized (lock) {
            captureHandle = captureHandles.remove(activity);
            recordingHandle = recordingHandles.remove(activity);
        }
        if (captureHandle != null) {
            safeUnregisterCapture(activity, captureHandle);
        }
        if (recordingHandle != null) {
            safeUnregisterRecording(activity, recordingHandle);
        }
    }

    private void safeUnregisterCapture(Activity activity, Object handle) {
        try {
            hookRegistrar.unregisterScreenCaptureCallback(activity, handle);
        } catch (Exception | LinkageError ignored) {
            // Best-effort cleanup
        }
    }

    private void safeUnregisterRecording(Activity activity, Object handle) {
        try {
            hookRegistrar.unregisterScreenRecordingCallback(activity, handle);
        } catch (Exception | LinkageError ignored) {
            // Best-effort cleanup
        }
    }

    private void notifyBackgroundSink(boolean isBackground) {
        try {
            backgroundSink.onBackgroundChanged(isBackground);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("AppLifecycleObserver background sink failed", e);
        }
    }

    private static final class AndroidScreenHookRegistrar implements ScreenHookRegistrar {
        private static final Executor DIRECT_EXECUTOR = Runnable::run;

        @Override
        public boolean hasPermission(Activity activity, String permission) {
            if (activity == null || permission == null) return false;
            try {
                return activity.checkSelfPermission(permission)
                        == PackageManager.PERMISSION_GRANTED;
            } catch (Exception | LinkageError e) {
                return false;
            }
        }

        @SuppressLint("MissingPermission")
        @Override
        public Object registerScreenCaptureCallback(Activity activity, Runnable onCaptured) {
            if (activity == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                return null;
            }
            Activity.ScreenCaptureCallback callback = onCaptured::run;
            activity.registerScreenCaptureCallback(DIRECT_EXECUTOR, callback);
            return callback;
        }

        @SuppressLint("MissingPermission")
        @Override
        public void unregisterScreenCaptureCallback(Activity activity, Object handle) {
            if (activity == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                return;
            }
            if (!(handle instanceof Activity.ScreenCaptureCallback)) {
                return;
            }
            activity.unregisterScreenCaptureCallback((Activity.ScreenCaptureCallback) handle);
        }

        @SuppressLint("MissingPermission")
        @Override
        public Object registerScreenRecordingCallback(Activity activity,
                                                      Consumer<Boolean> onRecordingChanged) {
            if (activity == null || Build.VERSION.SDK_INT < 35) {
                return null;
            }
            WindowManager wm = activity.getWindowManager();
            if (wm == null) return null;
            Consumer<Integer> listener = state ->
                    onRecordingChanged.accept(state != null && state == SCREEN_RECORDING_STATE_VISIBLE);
            int initialState = wm.addScreenRecordingCallback(DIRECT_EXECUTOR, listener);
            onRecordingChanged.accept(initialState == SCREEN_RECORDING_STATE_VISIBLE);
            return listener;
        }

        @SuppressLint("MissingPermission")
        @SuppressWarnings("unchecked")
        @Override
        public void unregisterScreenRecordingCallback(Activity activity, Object handle) {
            if (activity == null || Build.VERSION.SDK_INT < 35) {
                return;
            }
            if (!(handle instanceof Consumer)) {
                return;
            }
            WindowManager wm = activity.getWindowManager();
            if (wm == null) return;
            wm.removeScreenRecordingCallback((Consumer<Integer>) handle);
        }
    }
}
