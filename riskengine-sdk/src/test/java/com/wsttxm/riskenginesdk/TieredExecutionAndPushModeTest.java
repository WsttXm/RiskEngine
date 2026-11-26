package com.wsttxm.riskenginesdk;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeMonitorDispatcher;
import com.wsttxm.riskenginesdk.core.AppLifecycleObserver;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.model.TierReport;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.Assert.*;

public class TieredExecutionAndPushModeTest {

    private RiskEngine engine;

    @Before
    public void setUp() {
        engine = RiskEngine.getInstance();
        RiskEngine.shutdown();
        engine.setNativeHooksForTest(null);
        NativeMonitorDispatcher.clearListeners();
    }

    @After
    public void tearDown() {
        RiskEngine.shutdown();
        engine.setNativeHooksForTest(null);
        NativeMonitorDispatcher.clearListeners();
    }

    @Test
    public void initPerformsZeroSyncIoAndAsyncInitAppliesAntiDumpableAndPeriodicMonitorConfig()
            throws Exception {
        AtomicInteger syncSharedPrefsCalls = new AtomicInteger();
        AtomicInteger syncLoadCallsOnCallerThread = new AtomicInteger();
        final Thread callerThread = Thread.currentThread();

        CountDownLatch nativeInitDone = new CountDownLatch(1);
        AtomicBoolean antiDumpableApplied = new AtomicBoolean(false);
        AtomicInteger monitorStartCount = new AtomicInteger();

        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override
            public boolean ensureNativeLoaded() {
                if (Thread.currentThread() == callerThread) {
                    syncLoadCallsOnCallerThread.incrementAndGet();
                }
                return true;
            }

            @Override
            public void setAntiDumpable(boolean enable) {
                antiDumpableApplied.set(enable);
            }

            @Override
            public void startMonitor() {
                monitorStartCount.incrementAndGet();
                nativeInitDone.countDown();
            }

            @Override
            public void stopMonitor() {}
        });

        Context guardContext = new ContextWrapper(null) {
            @Override public Context getApplicationContext() { return this; }
            @Override
            public SharedPreferences getSharedPreferences(String name, int mode) {
                if (Thread.currentThread() == callerThread) {
                    syncSharedPrefsCalls.incrementAndGet();
                }
                return null;
            }
            @Override
            public Context createDeviceProtectedStorageContext() {
                if (Thread.currentThread() == callerThread) {
                    syncSharedPrefsCalls.incrementAndGet();
                }
                return this;
            }
        };

        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .enableAntiDumpable(true)
                .enablePeriodicMonitor(true)
                .build();

        RiskEngine.init(guardContext, config);

        // Zero synchronous SharedPreferences/Keystore/loadLibrary on caller thread
        assertEquals(0, syncSharedPrefsCalls.get());
        assertEquals(0, syncLoadCallsOnCallerThread.get());
        assertTrue(RiskEngine.isInitialized());

        // Background worker applies native hooks asynchronously
        assertTrue("Async init did not complete in time",
                nativeInitDone.await(3, TimeUnit.SECONDS));
        assertTrue(antiDumpableApplied.get());
        assertEquals(1, monitorStartCount.get());
    }

    @Test
    public void asyncInitRespectsEnablePeriodicMonitorFalse() throws Exception {
        CountDownLatch loadDone = new CountDownLatch(1);
        AtomicInteger monitorStartCount = new AtomicInteger();
        AtomicInteger antiDumpableCalls = new AtomicInteger();

        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override
            public boolean ensureNativeLoaded() {
                loadDone.countDown();
                return true;
            }
            @Override
            public void setAntiDumpable(boolean enable) {
                antiDumpableCalls.incrementAndGet();
            }
            @Override
            public void startMonitor() {
                monitorStartCount.incrementAndGet();
            }
            @Override public void stopMonitor() {}
        });

        Context ctx = new ContextWrapper(null) {
            @Override public Context getApplicationContext() { return this; }
        };
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .enableAntiDumpable(false)
                .enablePeriodicMonitor(false)
                .build();

        RiskEngine.init(ctx, config);
        assertTrue(loadDone.await(3, TimeUnit.SECONDS));
        // Give worker a brief window to finish post-load branch
        Thread.sleep(50);
        assertEquals(0, antiDumpableCalls.get());
        assertEquals(0, monitorStartCount.get());
    }

    @Test
    public void startMonitoringDispatchesTiersInStrictOrderAndRoutesPushEventsUntilStop()
            throws Exception {
        AtomicReference<Runnable> captureTrigger = new AtomicReference<>();
        AtomicReference<Consumer<Boolean>> recordingTrigger = new AtomicReference<>();
        AppLifecycleObserver.ScreenHookRegistrar fakeRegistrar =
                new AppLifecycleObserver.ScreenHookRegistrar() {
                    @Override public boolean hasPermission(Activity a, String p) { return true; }
                    @Override
                    public Object registerScreenCaptureCallback(Activity a, Runnable onCaptured) {
                        captureTrigger.set(onCaptured);
                        return new Object();
                    }
                    @Override public void unregisterScreenCaptureCallback(Activity a, Object h) {}
                    @Override
                    public Object registerScreenRecordingCallback(Activity a, Consumer<Boolean> cb) {
                        recordingTrigger.set(cb);
                        return new Object();
                    }
                    @Override public void unregisterScreenRecordingCallback(Activity a, Object h) {}
                };
        AppLifecycleObserver observer = new AppLifecycleObserver(bg -> {}, fakeRegistrar);

        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override public boolean ensureNativeLoaded() { return false; }
            @Override public void setAntiDumpable(boolean enable) {}
            @Override public void startMonitor() {}
            @Override public void stopMonitor() {}
        });

        Context ctx = new ContextWrapper(null) {
            @Override public Context getApplicationContext() { return this; }
        };
        engine.doInit(ctx, new RiskEngineConfig.Builder().enablePeriodicMonitor(false).build(),
                observer);

        List<String> stageOrder = new CopyOnWriteArrayList<>();
        List<ThreatEvent> allThreats = new CopyOnWriteArrayList<>();
        List<ThreatEvent> runtimeThreats = new CopyOnWriteArrayList<>();
        AtomicReference<DevicePosture> evaluatedPosture = new AtomicReference<>();
        CountDownLatch allStagesDone = new CountDownLatch(1);

        ThreatListener threatListener = new ThreatListener() {
            @Override public void onThreatDetected(ThreatEvent event) {
                allThreats.add(event);
            }
            @Override public void onRuntimeTamperDetected(ThreatEvent event) {
                runtimeThreats.add(event);
            }
        };
        DeviceStateListener deviceStateListener = new DeviceStateListener() {
            @Override
            public void onDeviceStateEvaluated(DevicePosture posture) {
                evaluatedPosture.set(posture);
            }
        };
        ExecutionStateListener executionListener = new ExecutionStateListener() {
            @Override public void onCriticalChecksFinished(TierReport report) {
                assertEquals(ScanTier.CRITICAL, report.getTier());
                stageOrder.add("CRITICAL");
            }
            @Override public void onFastChecksFinished(TierReport report) {
                assertEquals(ScanTier.FAST, report.getTier());
                stageOrder.add("FAST");
            }
            @Override public void onPostponedChecksFinished(RiskReport fullReport) {
                assertNotNull(fullReport);
                stageOrder.add("POSTPONED");
                allStagesDone.countDown();
            }
        };

        List<BaseDetector> testDetectors = Arrays.asList(
                stubDetector("debug", ScanTier.CRITICAL, RiskLevel.HIGH, 8, false, "tracer_pid:999"),
                stubDetector("network_risk", ScanTier.FAST, RiskLevel.LOW, 2, true, "vpn_active:tun0"),
                stubDetector("postponed_stub", ScanTier.POSTPONED, RiskLevel.MEDIUM, 4, false, "postponed_hit")
        );
        List<BaseCollector> testCollectors = Collections.singletonList(new BaseCollector(null) {
            @Override public String getName() { return "security_posture"; }
            @Override protected void collect(CollectorResult result) {
                result.addValue("device_secure", "true");
                result.addValue("storage_encryption", "ACTIVE_PER_USER");
            }
        });

        engine.doStartMonitoring(
                threatListener, deviceStateListener, executionListener,
                testDetectors, testCollectors);

        assertTrue("Tiered stages did not complete in time",
                allStagesDone.await(5, TimeUnit.SECONDS));
        assertEquals(Arrays.asList("CRITICAL", "FAST", "POSTPONED"), stageOrder);
        assertNotNull(evaluatedPosture.get());
        assertEquals(Boolean.TRUE, evaluatedPosture.get().getSystemVpn());
        assertTrue(allThreats.stream().anyMatch(e -> "debug".equals(e.getDetectorName())));
        assertTrue(allThreats.stream().anyMatch(e -> "postponed_stub".equals(e.getDetectorName())));

        // Verify live native periodic monitor push reaches ThreatListener
        NativeMonitorDispatcher.onNativeThreatDetected("late_frida_fd", "periodic_monitor");
        assertTrue(runtimeThreats.stream().anyMatch(
                e -> e.getDetails().contains("late_frida_fd") && e.isRuntimeTamper()));

        // Verify AppLifecycleObserver screen capture & recording callbacks reach ThreatListener
        observer.onActivityStarted(new Activity());
        assertNotNull(captureTrigger.get());
        assertNotNull(recordingTrigger.get());
        captureTrigger.get().run();
        recordingTrigger.get().accept(true);
        assertTrue(runtimeThreats.stream().anyMatch(
                e -> e.getDetails().contains("screen_capture_observed")));
        assertTrue(runtimeThreats.stream().anyMatch(
                e -> e.getDetails().contains("screen_recording_active")));

        // After stopMonitoring(), subsequent native/screen push events are completely suppressed
        int countBeforeStop = runtimeThreats.size();
        RiskEngine.stopMonitoring();
        NativeMonitorDispatcher.onNativeThreatDetected("late_text_mismatch", "periodic_monitor");
        captureTrigger.get().run();
        recordingTrigger.get().accept(true);
        assertEquals(countBeforeStop, runtimeThreats.size());
    }

    @Test
    public void staleAsyncStartMonitorCompensatesWithStopWhenShutdownRaces() throws Exception {
        CountDownLatch enteredStartMonitor = new CountDownLatch(1);
        CountDownLatch releaseStartMonitor = new CountDownLatch(1);
        CountDownLatch compensatingStopDone = new CountDownLatch(1);
        AtomicInteger startCalls = new AtomicInteger();
        AtomicInteger stopCalls = new AtomicInteger();

        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override public boolean ensureNativeLoaded() { return true; }
            @Override public void setAntiDumpable(boolean enable) {}
            @Override public void startMonitor() {
                startCalls.incrementAndGet();
                enteredStartMonitor.countDown();
                try {
                    releaseStartMonitor.await(3, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
            @Override public void stopMonitor() {
                if (stopCalls.incrementAndGet() >= 2) {
                    compensatingStopDone.countDown();
                }
            }
        });

        Context ctx = new ContextWrapper(null) {
            @Override public Context getApplicationContext() { return this; }
        };
        RiskEngine.init(ctx, new RiskEngineConfig.Builder().enablePeriodicMonitor(true).build());
        assertTrue(enteredStartMonitor.await(3, TimeUnit.SECONDS));

        // Shutdown races while async startMonitor() is still in flight
        RiskEngine.shutdown();
        releaseStartMonitor.countDown();

        assertTrue("Expected compensating stopMonitor() after stale async start",
                compensatingStopDone.await(3, TimeUnit.SECONDS));
        assertEquals(1, startCalls.get());
        assertTrue(stopCalls.get() >= 2);
    }

    @Test
    public void bridgeStopAndBackgroundNoOpWithoutLoadingNativeLibrary() {
        boolean loadedBefore = NativeCollectorBridge.isNativeLoaded();
        NativeCollectorBridge.stopMonitor();
        NativeCollectorBridge.setMonitorBackground(true);
        NativeCollectorBridge.setMonitorBackground(false);
        assertEquals(loadedBefore, NativeCollectorBridge.isNativeLoaded());
    }

    @Test
    public void consumerProguardRulesKeepPhase1ApisAndDispatcherButNeverObfuscationSentinel()
            throws Exception {
        String rules = new String(
                Files.readAllBytes(Path.of("consumer-rules.pro")), StandardCharsets.UTF_8);

        assertTrue(rules.contains("com.wsttxm.riskenginesdk.ScanTier"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.FingerprintVersion"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.FingerprintStability"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.FingerprintHasher"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.ThreatListener"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.DeviceStateListener"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.ExecutionStateListener"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.RiskWindowGuard"));
        assertTrue(rules.contains("com.wsttxm.riskenginesdk.collector.native_layer.NativeMonitorDispatcher"));
        assertTrue(rules.contains("onNativeThreatDetected(java.lang.String, java.lang.String)"));

        // Verify no -keep directive matches ObfuscationSentinel
        for (String line : rules.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("#")) continue;
            assertFalse("consumer-rules.pro must NOT keep ObfuscationSentinel: " + trimmed,
                    trimmed.contains("ObfuscationSentinel"));
        }
    }

    @Test
    public void configEnableIsolatedProcessProbeDefaultsTrueAndCanBeDisabled() {
        RiskEngineConfig defaultCfg = new RiskEngineConfig.Builder().build();
        assertTrue(defaultCfg.isEnableIsolatedProcessProbe());

        RiskEngineConfig disabledCfg = new RiskEngineConfig.Builder()
                .enableIsolatedProcessProbe(false)
                .build();
        assertFalse(disabledCfg.isEnableIsolatedProcessProbe());
    }

    @Test
    public void baseDetectorDefaultPostponedHooksAreBackwardCompatible() {
        BaseDetector legacy = stubDetector(
                "legacy_fast", ScanTier.FAST, RiskLevel.SAFE, 0, false, "clean");
        assertFalse(legacy.hasPostponedProbes());
        DetectionResult prior = legacy.call();
        assertSame(prior, legacy.detectPostponed(prior));
        assertSame(prior, legacy.callPostponed(prior));
    }

    @Test
    public void startMonitoringRunsFastPassFirstThenReplacesWithPostponedProbesAndDispatchesNewThreat()
            throws Exception {
        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override public boolean ensureNativeLoaded() { return false; }
            @Override public void setAntiDumpable(boolean enable) {}
            @Override public void startMonitor() {}
            @Override public void stopMonitor() {}
        });
        Context ctx = new ContextWrapper(null) {
            @Override public Context getApplicationContext() { return this; }
        };
        engine.doInit(ctx, new RiskEngineConfig.Builder().enablePeriodicMonitor(false).build(),
                new AppLifecycleObserver(bg -> {}, null));

        List<String> events = new CopyOnWriteArrayList<>();
        List<ThreatEvent> threats = new CopyOnWriteArrayList<>();
        AtomicReference<TierReport> capturedFastReport = new AtomicReference<>();
        AtomicReference<RiskReport> capturedFinalReport = new AtomicReference<>();
        CountDownLatch allDone = new CountDownLatch(1);

        BaseDetector dualPassRoot = new BaseDetector(null) {
            @Override public String getName() { return "root"; }
            @Override public ScanTier getScanTier() { return ScanTier.FAST; }
            @Override public boolean hasPostponedProbes() { return true; }
            @Override protected DetectionResult detect() {
                events.add("FAST_PASS_RUN");
                return safe();
            }
            @Override public DetectionResult detectPostponed(DetectionResult priorResult) {
                assertNotNull(priorResult);
                assertEquals(RiskLevel.SAFE, priorResult.getRiskLevel());
                events.add("POSTPONED_PROBE_RUN");
                EvidenceItem item = new EvidenceItem(
                        "ksu_supercall", EvidenceItem.SourceLayer.NATIVE,
                        "root", "ksu_supercall:ioctl", "root_fw", EvidenceItem.Rank.STRONG);
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 9, 10, false,
                        Collections.singletonList("ksu_supercall:ioctl"), "ksu_supercall:ioctl")
                        .withEvidenceItems(Collections.singletonList(item));
            }
        };

        BaseDetector critStub = stubDetector(
                "debug", ScanTier.CRITICAL, RiskLevel.SAFE, 0, false, "clean");

        engine.doStartMonitoring(
                new ThreatListener() {
                    @Override public void onThreatDetected(ThreatEvent event) {
                        threats.add(event);
                    }
                    @Override public void onRuntimeTamperDetected(ThreatEvent event) {}
                },
                new DeviceStateListener() {},
                new ExecutionStateListener() {
                    @Override public void onCriticalChecksFinished(TierReport report) {
                        events.add("CRITICAL_DONE");
                    }
                    @Override public void onFastChecksFinished(TierReport report) {
                        capturedFastReport.set(report);
                        events.add("FAST_DONE");
                    }
                    @Override public void onPostponedChecksFinished(RiskReport fullReport) {
                        capturedFinalReport.set(fullReport);
                        events.add("POSTPONED_DONE");
                        allDone.countDown();
                    }
                },
                Arrays.asList(critStub, dualPassRoot),
                Collections.emptyList());

        assertTrue("Dual-pass monitoring did not complete in time",
                allDone.await(5, TimeUnit.SECONDS));

        // Fast pass completed and delivered onFastChecksFinished BEFORE detectPostponed ran
        assertEquals(
                Arrays.asList("CRITICAL_DONE", "FAST_PASS_RUN", "FAST_DONE",
                        "POSTPONED_PROBE_RUN", "POSTPONED_DONE"),
                events);

        // FAST TierReport saw the clean fast-pass result without blocking on Stage 3
        DetectionResult fastRoot = capturedFastReport.get().getDetections().stream()
                .filter(d -> "root".equals(d.getDetectorName()))
                .findFirst().orElse(null);
        assertNotNull(fastRoot);
        assertEquals(RiskLevel.SAFE, fastRoot.getRiskLevel());

        // Final aggregated report replaced the prior result in-place (no duplicate "root" entry)
        List<DetectionResult> finalRoots = new ArrayList<>();
        for (DetectionResult d : capturedFinalReport.get().getDetections()) {
            if ("root".equals(d.getDetectorName())) {
                finalRoots.add(d);
            }
        }
        assertEquals(1, finalRoots.size());
        assertEquals(RiskLevel.HIGH, finalRoots.get(0).getRiskLevel());
        assertEquals(9, finalRoots.get(0).getScore());
        assertTrue(finalRoots.get(0).getDetails().contains("ksu_supercall:ioctl"));

        // ThreatListener received the newly discovered Stage 3 threat
        assertTrue(threats.stream().anyMatch(
                t -> "root".equals(t.getDetectorName())
                        && t.getDetails().contains("ksu_supercall:ioctl")));
    }

    @Test
    public void collectSyncMergesPostponedProbesAndFallsBackCleanlyOnTimeoutOrException() {
        engine.setNativeHooksForTest(new RiskEngine.NativeRuntimeHooks() {
            @Override public boolean ensureNativeLoaded() { return false; }
            @Override public void setAntiDumpable(boolean enable) {}
            @Override public void startMonitor() {}
            @Override public void stopMonitor() {}
        });
        Context ctx = new ContextWrapper(null) {
            @Override public Context getApplicationContext() { return this; }
        };
        engine.doInit(ctx, new RiskEngineConfig.Builder()
                        .enablePeriodicMonitor(false)
                        .collectTimeout(4_000)
                        .build(),
                new AppLifecycleObserver(bg -> {}, null));

        BaseDetector mergedDetector = new BaseDetector(null) {
            @Override public String getName() { return "mount_analysis"; }
            @Override public ScanTier getScanTier() { return ScanTier.FAST; }
            @Override public boolean hasPostponedProbes() { return true; }
            @Override protected DetectionResult detect() { return safe(); }
            @Override public DetectionResult detectPostponed(DetectionResult priorResult) {
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        Collections.singletonList("isolated_mount_diff:/data/adb"),
                        "isolated_mount_diff:/data/adb");
            }
        };

        BaseDetector timeoutDetector = new BaseDetector(null) {
            @Override public String getName() { return "root"; }
            @Override public ScanTier getScanTier() { return ScanTier.FAST; }
            @Override public boolean hasPostponedProbes() { return true; }
            @Override public long getPostponedTimeoutMs() { return 80; }
            @Override protected DetectionResult detect() {
                return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                        Collections.singletonList("fast_root_hit"), "fast_root_hit");
            }
            @Override public DetectionResult detectPostponed(DetectionResult priorResult) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 9, 10, false,
                        Collections.singletonList("late_timeout_hit"), "late_timeout_hit");
            }
        };

        BaseDetector throwingDetector = new BaseDetector(null) {
            @Override public String getName() { return "consistency"; }
            @Override public ScanTier getScanTier() { return ScanTier.FAST; }
            @Override public boolean hasPostponedProbes() { return true; }
            @Override protected DetectionResult detect() {
                return result(RiskLevel.LOW, DetectionStatus.WARNING, 2, 10, true,
                        Collections.singletonList("fast_consistency_note"), "fast_consistency_note");
            }
            @Override public DetectionResult detectPostponed(DetectionResult priorResult) {
                throw new IllegalStateException("simulated postponed failure");
            }
        };

        RiskReport report = engine.doCollectSync(
                System.nanoTime(), -1L, CollectScene.STANDARD,
                Arrays.asList(mergedDetector, timeoutDetector, throwingDetector),
                Collections.emptyList());

        assertNotNull(report);
        DetectionResult mountResult = report.getDetections().stream()
                .filter(d -> "mount_analysis".equals(d.getDetectorName()))
                .findFirst().orElse(null);
        DetectionResult rootResult = report.getDetections().stream()
                .filter(d -> "root".equals(d.getDetectorName()))
                .findFirst().orElse(null);
        DetectionResult consistencyResult = report.getDetections().stream()
                .filter(d -> "consistency".equals(d.getDetectorName()))
                .findFirst().orElse(null);

        assertNotNull(mountResult);
        assertEquals(RiskLevel.HIGH, mountResult.getRiskLevel());
        assertTrue(mountResult.getDetails().contains("isolated_mount_diff:/data/adb"));

        // Timed-out postponed probe cleanly preserved fast-pass result
        assertNotNull(rootResult);
        assertEquals(RiskLevel.MEDIUM, rootResult.getRiskLevel());
        assertEquals(4, rootResult.getScore());
        assertTrue(rootResult.getDetails().contains("fast_root_hit"));

        // Throwing postponed probe cleanly preserved fast-pass result (zero crash)
        assertNotNull(consistencyResult);
        assertEquals(RiskLevel.LOW, consistencyResult.getRiskLevel());
        assertTrue(consistencyResult.getDetails().contains("fast_consistency_note"));
    }

    private static BaseDetector stubDetector(String name,
                                             ScanTier tier,
                                             RiskLevel level,
                                             int score,
                                             boolean informational,
                                             String token) {
        return new BaseDetector(null) {
            @Override public String getName() { return name; }
            @Override public ScanTier getScanTier() { return tier; }
            @Override protected DetectionResult detect() {
                List<String> details = Collections.singletonList(token);
                EvidenceItem item = new EvidenceItem(
                        token.contains(":") ? token.substring(0, token.indexOf(':')) : token,
                        EvidenceItem.SourceLayer.JAVA,
                        name,
                        token,
                        "test_family",
                        EvidenceItem.Rank.STRONG);
                return new DetectionResult(
                        name,
                        level,
                        level == RiskLevel.SAFE ? DetectionStatus.NORMAL : DetectionStatus.WARNING,
                        score,
                        10,
                        informational,
                        details,
                        token
                ).withEvidenceItems(Collections.singletonList(item)).withScanTier(tier);
            }
        };
    }
}
