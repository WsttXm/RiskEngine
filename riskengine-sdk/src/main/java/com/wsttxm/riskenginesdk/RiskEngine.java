package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.os.Looper;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.CollectorRegistry;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeMonitorDispatcher;
import com.wsttxm.riskenginesdk.core.AppLifecycleObserver;
import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.FingerprintStore;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.core.SignedEnvelopeSigner;
import com.wsttxm.riskenginesdk.core.TaskScheduler;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.DetectorRegistry;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.model.TierReport;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.RiskReportJsonSerializer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

public final class RiskEngine {
    private static volatile RiskEngine instance;

    private final Object lifecycleLock = new Object();
    private final Object storeInitLock = new Object();

    private Context appContext;
    private RiskEngineConfig config;
    private TaskScheduler taskScheduler;
    private FingerprintStore fingerprintStore;
    private DataAggregator dataAggregator;
    private ReentrantLock collectionLock;
    private AppLifecycleObserver appLifecycleObserver;
    private NativeMonitorDispatcher.MonitorEventListener monitorBridgeListener;
    private volatile boolean initialized;
    private final AtomicLong lifecycleGeneration = new AtomicLong(0L);
    private final AtomicLong monitoringGeneration = new AtomicLong(0L);

    // Injectable native lifecycle hooks and envelope signer for deterministic pure-JVM unit tests.
    private volatile NativeRuntimeHooks nativeHooks = DEFAULT_NATIVE_HOOKS;
    private volatile SignedEnvelopeSigner envelopeSigner = new SignedEnvelopeSigner();

    private static final NativeRuntimeHooks DEFAULT_NATIVE_HOOKS = new NativeRuntimeHooks() {
        @Override public boolean ensureNativeLoaded() {
            return NativeCollectorBridge.ensureNativeLoaded();
        }
        @Override public void setAntiDumpable(boolean enable) {
            NativeCollectorBridge.setAntiDumpableResult(enable);
        }
        @Override public void startMonitor() {
            NativeCollectorBridge.startMonitor();
        }
        @Override public void stopMonitor() {
            NativeCollectorBridge.stopMonitor();
        }
    };

    private RiskEngine() {}

    public static RiskEngine getInstance() {
        if (instance == null) {
            synchronized (RiskEngine.class) {
                if (instance == null) {
                    instance = new RiskEngine();
                }
            }
        }
        return instance;
    }

    /**
     * Initializes the SDK asynchronously without blocking the caller thread.
     *
     * <p>Performs zero synchronous SharedPreferences, AndroidKeyStore, or
     * {@code System.loadLibrary} I/O on the calling thread; native library loading,
     * optional {@code PR_SET_DUMPABLE(0)}, periodic monitor startup, and FingerprintStore
     * warm-up run on a background worker thread.
     */
    public static void init(Context context, RiskEngineConfig config) {
        getInstance().doInit(context, config, null);
    }

    /** Atomically initializes the singleton once. Returns true when this call initialized it. */
    public static boolean initIfNeeded(Context context, RiskEngineConfig config) {
        RiskEngine engine = getInstance();
        synchronized (engine.lifecycleLock) {
            if (engine.initialized) {
                return false;
            }
            engine.doInit(context, config, null);
            return true;
        }
    }

    void doInit(Context context, RiskEngineConfig requestedConfig, AppLifecycleObserver observerOverride) {
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        if (requestedConfig == null) {
            throw new IllegalArgumentException("config must not be null");
        }

        long initGeneration;
        TaskScheduler scheduler;
        AppLifecycleObserver lifecycleObserver;
        Context resolvedAppContext;
        synchronized (lifecycleLock) {
            if (initialized) {
                throw new IllegalStateException(
                        "RiskEngine already initialized; call shutdown before reinitializing");
            }

            Context application = context.getApplicationContext();
            resolvedAppContext = application != null ? application : context;
            appContext = resolvedAppContext;
            config = requestedConfig;
            CLog.setEnabled(config.isDebugLog());
            scheduler = new TaskScheduler();
            taskScheduler = scheduler;
            // Defer FingerprintStore / Keystore / SharedPreferences creation off the caller thread.
            fingerprintStore = null;
            dataAggregator = null;
            collectionLock = new ReentrantLock(true);
            lifecycleObserver = observerOverride != null
                    ? observerOverride
                    : new AppLifecycleObserver();
            // Pure in-memory Application.ActivityLifecycleCallbacks registration inside
            // lifecycleLock prevents a concurrent shutdown() from racing ahead of register().
            lifecycleObserver.register(resolvedAppContext);
            appLifecycleObserver = lifecycleObserver;
            initGeneration = lifecycleGeneration.incrementAndGet();
            initialized = true;
        }

        // Offload native library loading, PR_SET_DUMPABLE(0), periodic monitor start, and
        // FingerprintStore / DirectBoot warm-up to a background worker thread (< 5ms main-thread init).
        final NativeRuntimeHooks hooks = this.nativeHooks;
        final SignedEnvelopeSigner signer = this.envelopeSigner;
        try {
            scheduler.submitBackground(() -> runAsyncInit(
                    initGeneration, resolvedAppContext, requestedConfig, hooks, signer));
        } catch (RejectedExecutionException e) {
            CLog.w("Async init task rejected (engine shutting down): " + e.getMessage());
        }
        CLog.i("RiskEngine initialized (async warm-up scheduled)");
    }

    private void runAsyncInit(long expectedGeneration,
                              Context resolvedAppContext,
                              RiskEngineConfig cfg,
                              NativeRuntimeHooks hooks,
                              SignedEnvelopeSigner signer) {
        if (!isGenerationActive(expectedGeneration)) {
            return;
        }
        try {
            boolean nativeOk = hooks.ensureNativeLoaded();
            if (!isGenerationActive(expectedGeneration)) {
                return;
            }
            if (nativeOk) {
                if (cfg.isEnableAntiDumpable() && isGenerationActive(expectedGeneration)) {
                    hooks.setAntiDumpable(true);
                }
                if (cfg.isEnablePeriodicMonitor()) {
                    startMonitorGuarded(expectedGeneration, -1L, hooks);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Async native init failed", e);
        }

        if (!isGenerationActive(expectedGeneration)) {
            return;
        }
        try {
            ensureStoreAndAggregator(expectedGeneration, resolvedAppContext, cfg);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Async FingerprintStore warm-up failed", e);
        }

        if (cfg.isEnableTeeAttestation() && signer != null && isGenerationActive(expectedGeneration)) {
            try {
                signer.warmUpPersistentKeyIfPossible();
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                CLog.w("Async envelope key warm-up failed: " + e.getMessage());
            }
        }
    }

    /**
     * Starts the native monitor only if {@code expectedGeneration} is still active, and
     * performs a lock-free compensating {@code stopMonitor()} if {@code shutdown()} or a
     * re-init with {@code enablePeriodicMonitor(false)} raced while {@code startMonitor()} ran.
     */
    private void startMonitorGuarded(long expectedGeneration,
                                     long expectedMonGen,
                                     NativeRuntimeHooks hooks) {
        if (!isGenerationActive(expectedGeneration)) {
            return;
        }
        if (expectedMonGen >= 0 && monitoringGeneration.get() != expectedMonGen) {
            return;
        }
        hooks.startMonitor();

        boolean needsCompensatingStop;
        long postStartGen;
        synchronized (lifecycleLock) {
            postStartGen = lifecycleGeneration.get();
            needsCompensatingStop = postStartGen != expectedGeneration
                    && (!initialized || (config != null && !config.isEnablePeriodicMonitor()));
        }
        if (needsCompensatingStop) {
            hooks.stopMonitor();
            boolean shouldRestart;
            synchronized (lifecycleLock) {
                shouldRestart = lifecycleGeneration.get() != postStartGen
                        && initialized
                        && (config == null || config.isEnablePeriodicMonitor());
            }
            if (shouldRestart) {
                hooks.startMonitor();
            }
        }
    }

    private boolean isGenerationActive(long expectedGeneration) {
        return initialized && lifecycleGeneration.get() == expectedGeneration;
    }

    private DataAggregator ensureStoreAndAggregator(long expectedGeneration,
                                                    Context ctx,
                                                    RiskEngineConfig cfg) {
        synchronized (lifecycleLock) {
            if (dataAggregator != null && lifecycleGeneration.get() == expectedGeneration) {
                return dataAggregator;
            }
        }
        synchronized (storeInitLock) {
            synchronized (lifecycleLock) {
                if (dataAggregator != null && lifecycleGeneration.get() == expectedGeneration) {
                    return dataAggregator;
                }
                if (!initialized || lifecycleGeneration.get() != expectedGeneration) {
                    return new DataAggregator(null, cfg);
                }
            }
            FingerprintStore createdStore = ctx == null ? null : new FingerprintStore(ctx);
            DataAggregator createdAggregator = new DataAggregator(createdStore, cfg);
            synchronized (lifecycleLock) {
                if (initialized && lifecycleGeneration.get() == expectedGeneration) {
                    if (fingerprintStore == null) {
                        fingerprintStore = createdStore;
                    }
                    if (dataAggregator == null) {
                        dataAggregator = createdAggregator;
                    }
                    return dataAggregator;
                }
            }
            return createdAggregator;
        }
    }

    /**
     * Starts Push-Pull monitoring: executes tiered scans in strict
     * {@code CRITICAL -> FAST -> POSTPONED} order delivering progressive callbacks,
     * and subscribes {@code threatListener} to real-time native periodic monitor and
     * API 34/35 screen capture/recording events until {@link #stopMonitoring()} or
     * {@link #shutdown()}.
     */
    public static void startMonitoring(ThreatListener threatListener,
                                       DeviceStateListener deviceStateListener,
                                       ExecutionStateListener executionStateListener) {
        getInstance().doStartMonitoring(
                threatListener, deviceStateListener, executionStateListener, null, null);
    }

    /** Stops push-mode callbacks and unsubscribes runtime tamper & screen listeners. */
    public static void stopMonitoring() {
        getInstance().doStopMonitoring();
    }

    void doStartMonitoring(ThreatListener threatListener,
                           DeviceStateListener deviceStateListener,
                           ExecutionStateListener executionStateListener,
                           List<BaseDetector> overrideDetectors,
                           List<BaseCollector> overrideCollectors) {
        EngineSnapshot snapshot;
        final long engineGen;
        final long monGen;

        synchronized (lifecycleLock) {
            if (!initialized || taskScheduler == null) {
                throw new IllegalStateException("RiskEngine not initialized");
            }
            engineGen = lifecycleGeneration.get();
            monGen = monitoringGeneration.incrementAndGet();
            snapshot = new EngineSnapshot(
                    appContext, config, taskScheduler, dataAggregator,
                    collectionLock, engineGen);

            NativeMonitorDispatcher.MonitorEventListener newNativeListener = event -> {
                if (!isMonitoringActive(engineGen, monGen) || event == null) {
                    return;
                }
                dispatchRuntimeTamper(threatListener, event);
            };
            AppLifecycleObserver.ScreenEventListener newScreenListener = event -> {
                if (!isMonitoringActive(engineGen, monGen) || event == null) {
                    return;
                }
                dispatchRuntimeTamper(threatListener, event);
            };

            // Atomically swap static dispatcher & screen listeners under lifecycleLock
            // (all O(1) in-memory operations) so concurrent start/stop/shutdown never leak
            // stale listeners or overwrite a newer session's screen callback.
            if (monitorBridgeListener != null) {
                NativeMonitorDispatcher.removeListener(monitorBridgeListener);
            }
            monitorBridgeListener = newNativeListener;
            NativeMonitorDispatcher.addListener(newNativeListener);
            if (appLifecycleObserver != null) {
                appLifecycleObserver.setScreenEventListener(newScreenListener);
            }
        }

        final NativeRuntimeHooks hooks = this.nativeHooks;
        if (snapshot.config.isEnablePeriodicMonitor()) {
            try {
                snapshot.scheduler.submitBackground(() -> {
                    if (isMonitoringActive(engineGen, monGen) && hooks.ensureNativeLoaded()) {
                        startMonitorGuarded(engineGen, monGen, hooks);
                    }
                });
            } catch (RejectedExecutionException ignored) {
                // Scheduler shutting down
            }
        }

        try {
            snapshot.scheduler.submit(() -> {
                runTieredMonitoringScan(
                        snapshot, monGen, threatListener, deviceStateListener,
                        executionStateListener, overrideDetectors, overrideCollectors);
                return null;
            });
        } catch (RejectedExecutionException e) {
            CLog.w("Monitoring scan rejected: " + e.getMessage());
        }
    }

    private void doStopMonitoring() {
        synchronized (lifecycleLock) {
            monitoringGeneration.incrementAndGet();
            if (monitorBridgeListener != null) {
                NativeMonitorDispatcher.removeListener(monitorBridgeListener);
                monitorBridgeListener = null;
            }
            if (appLifecycleObserver != null) {
                appLifecycleObserver.setScreenEventListener(null);
            }
        }
    }

    private boolean isMonitoringActive(long engineGen, long monGen) {
        return initialized
                && lifecycleGeneration.get() == engineGen
                && monitoringGeneration.get() == monGen;
    }

    private void runTieredMonitoringScan(EngineSnapshot snapshot,
                                         long monGen,
                                         ThreatListener threatListener,
                                         DeviceStateListener deviceStateListener,
                                         ExecutionStateListener executionStateListener,
                                         List<BaseDetector> overrideDetectors,
                                         List<BaseCollector> overrideCollectors) {
        if (!isMonitoringActive(snapshot.generation, monGen)) {
            return;
        }
        long scanStartNanos = System.nanoTime();
        long deadlineNanos = scanStartNanos
                + TimeUnit.MILLISECONDS.toNanos(snapshot.config.getCollectTimeoutMs());
        RiskPolicy policy = snapshot.config.getRiskPolicy();

        if (!acquireCollectionLockSilent(snapshot, monGen, deadlineNanos)) {
            return;
        }
        try {
            if (!isMonitoringActive(snapshot.generation, monGen)) {
                return;
            }
            SignalSnapshot signals = new SignalSnapshot(snapshot.appContext);
            List<BaseDetector> allDetectors = overrideDetectors != null
                    ? overrideDetectors
                    : new DetectorRegistry(snapshot.appContext, snapshot.config, signals)
                            .getDetectors();
            List<BaseCollector> allCollectors = overrideCollectors != null
                    ? overrideCollectors
                    : new CollectorRegistry(snapshot.appContext, snapshot.config, signals)
                            .getCollectors();

            List<BaseDetector> criticalDetectors = filterByTier(allDetectors, ScanTier.CRITICAL);
            List<BaseDetector> fastDetectors = filterByTier(allDetectors, ScanTier.FAST);
            List<BaseDetector> postponedDetectors = filterByTier(allDetectors, ScanTier.POSTPONED);

            TaskScheduler.TierBudgets budgets = TaskScheduler.computeTierBudgets(
                    Math.max(1L, remainingMillis(deadlineNanos)));
            List<DetectionResult> accumulatedDetections = new ArrayList<>(allDetectors.size());

            // Stage 1: CRITICAL tier
            long critStart = System.nanoTime();
            List<DetectionResult> critResults = executeDetectorTier(
                    snapshot.scheduler, criticalDetectors,
                    Math.min(budgets.getCriticalBudgetMs(), remainingMillis(deadlineNanos)));
            List<DetectionResult> policyCritResults = CorrelationEngine.applyPolicy(critResults, policy);
            accumulatedDetections.addAll(critResults);
            if (!isMonitoringActive(snapshot.generation, monGen)) {
                return;
            }
            dispatchTierThreats(threatListener, policyCritResults);
            TierReport criticalReport = new TierReport(
                    ScanTier.CRITICAL,
                    policyCritResults,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - critStart),
                    System.currentTimeMillis(),
                    policy);
            dispatchCriticalFinished(executionStateListener, criticalReport);

            // Stage 2: FAST tier
            if (!isMonitoringActive(snapshot.generation, monGen)) {
                return;
            }
            long fastStart = System.nanoTime();
            List<DetectionResult> fastResults = executeDetectorTier(
                    snapshot.scheduler, fastDetectors,
                    Math.min(budgets.getFastBudgetMs(), remainingMillis(deadlineNanos)));
            List<DetectionResult> policyFastResults = CorrelationEngine.applyPolicy(fastResults, policy);
            accumulatedDetections.addAll(fastResults);
            if (!isMonitoringActive(snapshot.generation, monGen)) {
                return;
            }
            dispatchTierThreats(threatListener, policyFastResults);
            TierReport fastReport = new TierReport(
                    ScanTier.FAST,
                    policyFastResults,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - fastStart),
                    System.currentTimeMillis(),
                    policy);
            dispatchFastFinished(executionStateListener, fastReport);

            // Stage 3: POSTPONED detectors + dual-pass postponed probes + Collectors + full aggregation
            if (!isMonitoringActive(snapshot.generation, monGen)) {
                return;
            }
            List<BaseDetector> dualPassDetectors = filterPostponedProbeDetectors(
                    criticalDetectors, fastDetectors);
            long stage3Remaining = remainingMillis(deadlineNanos);
            if (!postponedDetectors.isEmpty() || !dualPassDetectors.isEmpty()) {
                long postponedBudget = stage3Remaining <= 0L
                        ? 0L
                        : Math.max(1L, stage3Remaining / 2L);
                long postponedDeadlineNanos = System.nanoTime()
                        + TimeUnit.MILLISECONDS.toNanos(postponedBudget);
                if (!postponedDetectors.isEmpty()) {
                    long tierBudget = Math.min(
                            remainingMillis(postponedDeadlineNanos),
                            remainingMillis(deadlineNanos));
                    List<DetectionResult> postponedResults = executeDetectorTier(
                            snapshot.scheduler, postponedDetectors, tierBudget);
                    accumulatedDetections.addAll(postponedResults);
                    if (!isMonitoringActive(snapshot.generation, monGen)) {
                        return;
                    }
                    dispatchTierThreats(threatListener,
                            CorrelationEngine.applyPolicy(postponedResults, policy));
                }
                if (!dualPassDetectors.isEmpty()) {
                    long probeBudget = Math.min(
                            remainingMillis(postponedDeadlineNanos),
                            remainingMillis(deadlineNanos));
                    List<PostponedMergeOutcome> mergedOutcomes = executePostponedProbes(
                            snapshot.scheduler, dualPassDetectors,
                            accumulatedDetections, probeBudget);
                    if (!isMonitoringActive(snapshot.generation, monGen)) {
                        return;
                    }
                    dispatchPostponedMergedThreats(threatListener, mergedOutcomes, policy);
                }
            }

            List<CollectorResult> collectorResults = executeCollectorsSafe(
                    snapshot.scheduler, allCollectors, remainingMillis(deadlineNanos));
            if (!isMonitoringActive(snapshot.generation, monGen)) {
                return;
            }

            DataAggregator aggregator = resolveAggregator(snapshot);
            RiskReport fullReport = aggregator.aggregate(
                    collectorResults, accumulatedDetections, policy);
            if (!isMonitoringActive(snapshot.generation, monGen)) {
                return;
            }

            // Notify synthetic correlation/continuity threats produced during aggregation
            for (DetectionResult d : fullReport.getDetections()) {
                String n = d.getDetectorName();
                if (("signal_correlation".equals(n)
                        || "fingerprint_continuity".equals(n)
                        || "multi_source_validation".equals(n))
                        && !d.isInformational() && d.getScore() > 0) {
                    dispatchThreatDetected(threatListener,
                            ThreatEvent.fromDetectionResult(d, false));
                }
            }

            dispatchDevicePosture(deviceStateListener, fullReport.getDevicePosture());
            dispatchPostponedFinished(executionStateListener, fullReport);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Tiered monitoring scan failed", e);
        } finally {
            snapshot.collectionLock.unlock();
        }
    }

    private boolean acquireCollectionLockSilent(EngineSnapshot snapshot,
                                                long monGen,
                                                long deadlineNanos) {
        try {
            while (isMonitoringActive(snapshot.generation, monGen)) {
                long remainingNanos = deadlineNanos - System.nanoTime();
                if (remainingNanos <= 0) {
                    return snapshot.collectionLock.tryLock();
                }
                long waitNanos = Math.min(remainingNanos, TimeUnit.MILLISECONDS.toNanos(100));
                if (snapshot.collectionLock.tryLock(waitNanos, TimeUnit.NANOSECONDS)) {
                    return true;
                }
            }
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public static void collect(RiskEngineCallback callback) {
        getInstance().doCollect(null, callback);
    }

    public static void collect(CollectScene scene, RiskEngineCallback callback) {
        getInstance().doCollect(scene, callback);
    }

    private void doCollect(CollectScene scene, RiskEngineCallback callback) {
        TaskScheduler scheduler;
        long requestGeneration;
        synchronized (lifecycleLock) {
            if (!initialized) {
                notifyError(callback, new IllegalStateException("RiskEngine not initialized"));
                return;
            }
            scheduler = taskScheduler;
            requestGeneration = lifecycleGeneration.get();
        }

        long requestStartNanos = System.nanoTime();
        try {
            scheduler.submit(() -> {
                RiskReport report;
                try {
                    report = doCollectSync(requestStartNanos, requestGeneration, scene);
                } catch (Exception | LinkageError e) {
                    CLog.e("Collection failed", e);
                    notifyError(callback, e);
                    return null;
                }
                if (callback != null) {
                    try {
                        callback.onSuccess(report);
                    } catch (RuntimeException callbackError) {
                        CLog.e("RiskEngine success callback failed", callbackError);
                    }
                }
                return null;
            });
        } catch (RejectedExecutionException e) {
            notifyError(callback, new IllegalStateException(
                    "RiskEngine collection queue is full or shutting down", e));
        }
    }

    public static RiskReport collectSync() {
        return getInstance().doCollectSync(System.nanoTime(), -1, null);
    }

    public static RiskReport collectSync(CollectScene scene) {
        return getInstance().doCollectSync(System.nanoTime(), -1, scene);
    }

    /**
     * Collects a full {@link RiskReport} and issues an offline-verifiable hardware-attested
     * {@link SignedRiskEnvelope} bound to {@code serverChallenge}.
     *
     * <p>Must not be called on the Android main thread. {@code serverChallenge} must be between
     * 16 and 128 bytes (32-byte server-issued random nonce recommended).</p>
     *
     * @param scene           collection scene override, or {@code null} to use configured default
     * @param serverChallenge 16–128 byte server nonce bound into the canonical payload (and X.509
     *                        OID {@code .17} attestation challenge in {@link EnvelopeMode#FRESH_ATTESTATION})
     * @param mode            {@link EnvelopeMode#PERSISTENT_KEY} ({@code <10ms} hot path) or
     *                        {@link EnvelopeMode#FRESH_ATTESTATION} (one-time hardware keypair)
     */
    public static SignedRiskEnvelope collectSignedEnvelopeSync(
            CollectScene scene,
            byte[] serverChallenge,
            EnvelopeMode mode) {
        return getInstance().doCollectSignedEnvelopeSync(scene, serverChallenge, mode, null, null);
    }

    SignedRiskEnvelope doCollectSignedEnvelopeSync(
            CollectScene scene,
            byte[] serverChallenge,
            EnvelopeMode mode,
            List<BaseDetector> overrideDetectors,
            List<BaseCollector> overrideCollectors) {
        Objects.requireNonNull(mode, "mode must not be null");
        SignedEnvelopeSigner.validateChallenge(serverChallenge);
        byte[] challengeCopy = Arrays.copyOf(serverChallenge, serverChallenge.length);
        if (isAndroidMainThread()) {
            throw new IllegalStateException(
                    "Synchronous collection must not run on the Android main thread");
        }
        EngineSnapshot snapshot = snapshotState();
        RiskReport report = doCollectSync(
                System.nanoTime(), snapshot.generation, scene,
                overrideDetectors, overrideCollectors);
        ensureCollectionActive(snapshot);
        return envelopeSigner.sign(snapshot.appContext, report, challengeCopy, mode);
    }

    private RiskReport doCollectSync(long startNanos, long expectedGeneration,
                                     CollectScene sceneOverride) {
        return doCollectSync(startNanos, expectedGeneration, sceneOverride, null, null);
    }

    RiskReport doCollectSync(long startNanos,
                             long expectedGeneration,
                             CollectScene sceneOverride,
                             List<BaseDetector> overrideDetectors,
                             List<BaseCollector> overrideCollectors) {
        if (isAndroidMainThread()) {
            throw new IllegalStateException(
                    "Synchronous collection must not run on the Android main thread");
        }
        EngineSnapshot snapshot = snapshotState();
        if (expectedGeneration >= 0 && snapshot.generation != expectedGeneration) {
            throw new CancellationException("RiskEngine lifecycle changed before collection");
        }
        long deadlineNanos = startNanos
                + TimeUnit.MILLISECONDS.toNanos(snapshot.config.getCollectTimeoutMs());
        RiskPolicy policy = snapshot.config.resolveRiskPolicy(sceneOverride);
        CLog.i("Starting collection...");

        if (!acquireCollectionLock(snapshot, deadlineNanos)) {
            ensureCollectionActive(snapshot);
            return buildTimeoutReport(snapshot, startNanos, policy);
        }
        try {
            ensureCollectionActive(snapshot);

            SignalSnapshot signals = new SignalSnapshot(snapshot.appContext);
            List<BaseDetector> detectors = overrideDetectors != null
                    ? overrideDetectors
                    : new DetectorRegistry(snapshot.appContext, snapshot.config, signals)
                            .getDetectors();
            List<BaseCollector> collectors = overrideCollectors != null
                    ? overrideCollectors
                    : new CollectorRegistry(snapshot.appContext, snapshot.config, signals)
                            .getCollectors();

            // Tier-weighted dynamic budget allocation (retires the rigid 45% collector split).
            TaskScheduler.TierBudgets budgets = TaskScheduler.computeTierBudgets(
                    Math.max(1L, remainingMillis(deadlineNanos)));

            List<DetectionResult> detectionResults = new ArrayList<>(detectors.size());
            List<BaseDetector> critical = filterByTier(detectors, ScanTier.CRITICAL);
            List<BaseDetector> fast = filterByTier(detectors, ScanTier.FAST);
            List<BaseDetector> postponed = filterByTier(detectors, ScanTier.POSTPONED);

            detectionResults.addAll(executeDetectorTier(
                    snapshot.scheduler, critical,
                    Math.min(budgets.getCriticalBudgetMs(), remainingMillis(deadlineNanos))));
            ensureCollectionActive(snapshot);

            detectionResults.addAll(executeDetectorTier(
                    snapshot.scheduler, fast,
                    Math.min(budgets.getFastBudgetMs(), remainingMillis(deadlineNanos))));
            ensureCollectionActive(snapshot);

            List<BaseDetector> dualPassDetectors = filterPostponedProbeDetectors(critical, fast);
            if (!postponed.isEmpty() || !dualPassDetectors.isEmpty()) {
                long stage3Remaining = remainingMillis(deadlineNanos);
                long postponedBudget = stage3Remaining <= 0L
                        ? 0L
                        : Math.max(1L, stage3Remaining / 2L);
                long postponedDeadlineNanos = System.nanoTime()
                        + TimeUnit.MILLISECONDS.toNanos(postponedBudget);
                if (!postponed.isEmpty()) {
                    long tierBudget = Math.min(
                            remainingMillis(postponedDeadlineNanos),
                            remainingMillis(deadlineNanos));
                    detectionResults.addAll(executeDetectorTier(
                            snapshot.scheduler, postponed, tierBudget));
                    ensureCollectionActive(snapshot);
                }
                if (!dualPassDetectors.isEmpty()) {
                    long probeBudget = Math.min(
                            remainingMillis(postponedDeadlineNanos),
                            remainingMillis(deadlineNanos));
                    executePostponedProbes(
                            snapshot.scheduler, dualPassDetectors, detectionResults, probeBudget);
                    ensureCollectionActive(snapshot);
                }
            }

            List<CollectorResult> collectorResults = executeCollectorsSafe(
                    snapshot.scheduler, collectors, remainingMillis(deadlineNanos));
            ensureCollectionActive(snapshot);

            DataAggregator aggregator = resolveAggregator(snapshot);
            RiskReport report = aggregator.aggregate(
                    collectorResults, detectionResults, policy);
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            CLog.i("Collection completed in " + elapsedMs + "ms, risk level: "
                    + report.getOverallRiskLevel());
            return report;
        } finally {
            snapshot.collectionLock.unlock();
        }
    }

    private static boolean isAndroidMainThread() {
        try {
            Looper mainLooper = Looper.getMainLooper();
            return mainLooper != null && Looper.myLooper() == mainLooper;
        } catch (RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    private DataAggregator resolveAggregator(EngineSnapshot snapshot) {
        if (snapshot.dataAggregator != null) {
            return snapshot.dataAggregator;
        }
        return ensureStoreAndAggregator(snapshot.generation, snapshot.appContext, snapshot.config);
    }

    private static List<BaseDetector> filterByTier(List<BaseDetector> detectors, ScanTier tier) {
        List<BaseDetector> filtered = new ArrayList<>();
        for (BaseDetector detector : detectors) {
            if (detector == null) continue;
            ScanTier detectorTier = detector.getScanTier() == null
                    ? ScanTier.FAST : detector.getScanTier();
            if (detectorTier == tier) {
                filtered.add(detector);
            }
        }
        return filtered;
    }

    private static List<BaseDetector> filterPostponedProbeDetectors(
            List<BaseDetector> criticalDetectors,
            List<BaseDetector> fastDetectors) {
        List<BaseDetector> dualPass = new ArrayList<>();
        for (BaseDetector detector : criticalDetectors) {
            if (detector != null && detector.hasPostponedProbes()) {
                dualPass.add(detector);
            }
        }
        for (BaseDetector detector : fastDetectors) {
            if (detector != null && detector.hasPostponedProbes()) {
                dualPass.add(detector);
            }
        }
        return dualPass;
    }

    /**
     * Runs {@link BaseDetector#callPostponed(DetectionResult)} for dual-pass detectors under the
     * Stage 3 POSTPONED budget and replaces their prior fast-pass entries in-place. On timeout,
     * error, or null result, the prior fast-pass result is preserved intact.
     */
    private static List<PostponedMergeOutcome> executePostponedProbes(
            TaskScheduler scheduler,
            List<BaseDetector> dualPassDetectors,
            List<DetectionResult> accumulatedDetections,
            long budgetMs) {
        if (dualPassDetectors.isEmpty() || budgetMs <= 0) {
            return Collections.emptyList();
        }
        Map<String, Integer> indexByName = new HashMap<>(accumulatedDetections.size());
        for (int i = 0; i < accumulatedDetections.size(); i++) {
            DetectionResult existing = accumulatedDetections.get(i);
            if (existing != null && existing.getDetectorName() != null) {
                indexByName.put(existing.getDetectorName(), i);
            }
        }

        List<TaskScheduler.TieredTask<DetectionResult>> tasks =
                new ArrayList<>(dualPassDetectors.size());
        List<DetectionResult> priorResults = new ArrayList<>(dualPassDetectors.size());
        for (BaseDetector detector : dualPassDetectors) {
            Integer idx = indexByName.get(detector.getName());
            DetectionResult prior = (idx != null) ? accumulatedDetections.get(idx) : null;
            priorResults.add(prior);
            tasks.add(new TaskScheduler.TieredTask<>(
                    detector.getName() + "#postponed",
                    ScanTier.POSTPONED,
                    detector.getPostponedTimeoutMs(),
                    () -> detector.callPostponed(prior)));
        }

        List<TaskScheduler.TaskOutcome<DetectionResult>> outcomes =
                scheduler.submitAllWithSafeTimeout(tasks, budgetMs);
        List<PostponedMergeOutcome> merged = new ArrayList<>();
        for (int i = 0; i < outcomes.size(); i++) {
            TaskScheduler.TaskOutcome<DetectionResult> outcome = outcomes.get(i);
            BaseDetector detector = dualPassDetectors.get(i);
            DetectionResult prior = priorResults.get(i);
            if (!outcome.isSuccess() || outcome.getValueOrNull() == null) {
                continue;
            }
            DetectionResult updated = outcome.getValueOrNull().withScanTier(detector.getScanTier());
            Integer idx = indexByName.get(detector.getName());
            if (idx != null) {
                accumulatedDetections.set(idx, updated);
            } else {
                indexByName.put(detector.getName(), accumulatedDetections.size());
                accumulatedDetections.add(updated);
            }
            merged.add(new PostponedMergeOutcome(prior, updated));
        }
        return merged;
    }

    private static void dispatchPostponedMergedThreats(ThreatListener listener,
                                                       List<PostponedMergeOutcome> mergedOutcomes,
                                                       RiskPolicy policy) {
        if (listener == null || mergedOutcomes == null || mergedOutcomes.isEmpty()) {
            return;
        }
        for (PostponedMergeOutcome pair : mergedOutcomes) {
            if (pair == null || pair.updated == null) {
                continue;
            }
            DetectionResult updatedScene = CorrelationEngine.applyPolicy(pair.updated, policy);
            if (updatedScene == null || updatedScene.isInformational()
                    || updatedScene.getScore() <= 0) {
                continue;
            }
            DetectionResult priorScene = pair.prior == null
                    ? null : CorrelationEngine.applyPolicy(pair.prior, policy);
            boolean newlyActionable = priorScene == null
                    || priorScene.isInformational()
                    || priorScene.getScore() <= 0;
            boolean escalated = priorScene != null && (
                    updatedScene.getScore() > priorScene.getScore()
                            || updatedScene.getRiskLevel().ordinal()
                                    > priorScene.getRiskLevel().ordinal()
                            || !updatedScene.getDetails().equals(priorScene.getDetails())
                            || updatedScene.getEvidenceItems().size()
                                    > priorScene.getEvidenceItems().size());
            if (newlyActionable || escalated) {
                dispatchThreatDetected(listener,
                        ThreatEvent.fromDetectionResult(updatedScene, false));
            }
        }
    }

    private static final class PostponedMergeOutcome {
        private final DetectionResult prior;
        private final DetectionResult updated;

        private PostponedMergeOutcome(DetectionResult prior, DetectionResult updated) {
            this.prior = prior;
            this.updated = updated;
        }
    }

    private static List<DetectionResult> executeDetectorTier(TaskScheduler scheduler,
                                                             List<BaseDetector> detectors,
                                                             long budgetMs) {
        if (detectors.isEmpty()) {
            return Collections.emptyList();
        }
        if (budgetMs <= 0) {
            List<DetectionResult> timedOut = new ArrayList<>(detectors.size());
            for (BaseDetector detector : detectors) {
                timedOut.add(DetectionResult.timeout(
                        detector.getName(), "collection_deadline_exceeded")
                        .withScanTier(detector.getScanTier()));
            }
            return timedOut;
        }
        List<TaskScheduler.TieredTask<DetectionResult>> tasks = new ArrayList<>(detectors.size());
        for (BaseDetector detector : detectors) {
            tasks.add(new TaskScheduler.TieredTask<>(
                    detector.getName(), detector.getScanTier(), detector.getTimeoutMs(), detector));
        }
        List<TaskScheduler.TaskOutcome<DetectionResult>> outcomes =
                scheduler.submitAllWithSafeTimeout(tasks, budgetMs);
        List<DetectionResult> results = new ArrayList<>(detectors.size());
        for (int i = 0; i < outcomes.size(); i++) {
            TaskScheduler.TaskOutcome<DetectionResult> outcome = outcomes.get(i);
            BaseDetector detector = detectors.get(i);
            if (outcome.isSuccess() && outcome.getValueOrNull() != null) {
                results.add(outcome.getValueOrNull());
            } else if (outcome.isTimedOut()) {
                results.add(DetectionResult.timeout(
                        detector.getName(), "collection_deadline_exceeded")
                        .withScanTier(detector.getScanTier()));
            } else {
                Throwable err = outcome.getResult() == null ? null : outcome.getResult().getError();
                String reason = err == null ? "execution_failed" : err.getClass().getSimpleName();
                results.add(DetectionResult.error(detector.getName(), reason)
                        .withScanTier(detector.getScanTier()));
            }
        }
        addMissingDetectionResults(detectors, results);
        return results;
    }

    private static List<CollectorResult> executeCollectorsSafe(TaskScheduler scheduler,
                                                               List<BaseCollector> collectors,
                                                               long budgetMs) {
        if (collectors.isEmpty()) {
            return Collections.emptyList();
        }
        List<CollectorResult> results = new ArrayList<>(collectors.size());
        if (budgetMs <= 0) {
            addMissingCollectorResults(collectors, results);
            return results;
        }
        List<TaskScheduler.TieredTask<CollectorResult>> tasks = new ArrayList<>(collectors.size());
        for (BaseCollector collector : collectors) {
            tasks.add(new TaskScheduler.TieredTask<>(
                    collector.getName(), ScanTier.POSTPONED,
                    Math.min(ScanTier.POSTPONED.getDefaultTimeoutMs(), budgetMs), collector));
        }
        List<TaskScheduler.TaskOutcome<CollectorResult>> outcomes =
                scheduler.submitAllWithSafeTimeout(tasks, budgetMs);
        for (int i = 0; i < outcomes.size(); i++) {
            TaskScheduler.TaskOutcome<CollectorResult> outcome = outcomes.get(i);
            BaseCollector collector = collectors.get(i);
            if (outcome.isSuccess() && outcome.getValueOrNull() != null) {
                results.add(outcome.getValueOrNull());
            } else {
                CollectorResult missing = new CollectorResult(collector.getName());
                missing.markError(outcome.isTimedOut() ? "timeout" : "execution_failure");
                results.add(missing);
            }
        }
        addMissingCollectorResults(collectors, results);
        return results;
    }

    private static void dispatchTierThreats(ThreatListener listener,
                                            List<DetectionResult> detections) {
        if (listener == null || detections == null) return;
        for (DetectionResult result : detections) {
            if (result != null && !result.isInformational() && result.getScore() > 0) {
                dispatchThreatDetected(listener, ThreatEvent.fromDetectionResult(result, false));
            }
        }
    }

    private static void dispatchThreatDetected(ThreatListener listener, ThreatEvent event) {
        if (listener == null || event == null) return;
        try {
            listener.onThreatDetected(event);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("ThreatListener.onThreatDetected failed", e);
        }
    }

    private static void dispatchRuntimeTamper(ThreatListener listener, ThreatEvent event) {
        if (listener == null || event == null) return;
        try {
            listener.onRuntimeTamperDetected(event);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("ThreatListener.onRuntimeTamperDetected failed", e);
        }
        dispatchThreatDetected(listener, event);
    }

    private static void dispatchDevicePosture(DeviceStateListener listener, DevicePosture posture) {
        if (listener == null || posture == null) return;
        try {
            listener.onDeviceStateEvaluated(posture);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("DeviceStateListener.onDeviceStateEvaluated failed", e);
        }
    }

    private static void dispatchCriticalFinished(ExecutionStateListener listener,
                                                 TierReport report) {
        if (listener == null || report == null) return;
        try {
            listener.onCriticalChecksFinished(report);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("ExecutionStateListener.onCriticalChecksFinished failed", e);
        }
    }

    private static void dispatchFastFinished(ExecutionStateListener listener,
                                             TierReport report) {
        if (listener == null || report == null) return;
        try {
            listener.onFastChecksFinished(report);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("ExecutionStateListener.onFastChecksFinished failed", e);
        }
    }

    private static void dispatchPostponedFinished(ExecutionStateListener listener,
                                                  RiskReport report) {
        if (listener == null || report == null) return;
        try {
            listener.onPostponedChecksFinished(report);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("ExecutionStateListener.onPostponedChecksFinished failed", e);
        }
    }

    private boolean acquireCollectionLock(EngineSnapshot snapshot, long deadlineNanos) {
        try {
            while (true) {
                ensureCollectionActive(snapshot);
                long remainingNanos = deadlineNanos - System.nanoTime();
                if (remainingNanos <= 0) {
                    return snapshot.collectionLock.tryLock();
                }
                long waitNanos = Math.min(
                        remainingNanos, TimeUnit.MILLISECONDS.toNanos(100));
                if (snapshot.collectionLock.tryLock(
                        waitNanos, TimeUnit.NANOSECONDS)) {
                    return true;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            CancellationException cancellation =
                    new CancellationException("RiskEngine collection cancelled");
            cancellation.initCause(e);
            throw cancellation;
        }
    }

    private RiskReport buildTimeoutReport(EngineSnapshot snapshot, long startNanos,
                                          RiskPolicy policy) {
        SignalSnapshot signals = new SignalSnapshot(snapshot.appContext);
        List<BaseCollector> collectors = new CollectorRegistry(
                snapshot.appContext, snapshot.config, signals).getCollectors();
        List<CollectorResult> collectorResults = new ArrayList<>();
        addMissingCollectorResults(collectors, collectorResults);

        List<BaseDetector> detectors = new DetectorRegistry(
                snapshot.appContext, snapshot.config, signals).getDetectors();
        List<DetectionResult> detectionResults = new ArrayList<>();
        addMissingDetectionResults(detectors, detectionResults);

        RiskReport report = resolveAggregator(snapshot).aggregate(
                collectorResults, detectionResults, policy);
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
        CLog.w("Collection timed out while waiting for the previous collection after "
                + elapsedMs + "ms");
        return report;
    }

    public static void shutdown() {
        RiskEngine engine = getInstance();
        NativeRuntimeHooks hooks = engine.nativeHooks;
        engine.doShutdown(hooks::stopMonitor, hooks::startMonitor);
    }

    /**
     * Resets the persisted immutable fingerprint hardware anchor baseline.
     * Invoke only when the host app confirms a legitimate device replacement
     * or compliance reset.
     */
    public static void resetFingerprintBaseline() {
        getInstance().doResetFingerprintBaseline();
    }

    private void doResetFingerprintBaseline() {
        FingerprintStore store;
        Context ctx;
        long gen;
        synchronized (lifecycleLock) {
            store = fingerprintStore;
            ctx = appContext;
            gen = lifecycleGeneration.get();
        }
        if (store == null && ctx != null && isGenerationActive(gen)) {
            synchronized (storeInitLock) {
                synchronized (lifecycleLock) {
                    if (isGenerationActive(gen) && fingerprintStore != null) {
                        store = fingerprintStore;
                    }
                }
                if (store == null && isGenerationActive(gen)) {
                    FingerprintStore created = new FingerprintStore(ctx);
                    synchronized (lifecycleLock) {
                        if (isGenerationActive(gen)) {
                            if (fingerprintStore == null) {
                                fingerprintStore = created;
                            }
                            store = fingerprintStore;
                        }
                    }
                }
            }
        }
        if (store != null) {
            store.resetBaseline();
            CLog.i("Fingerprint anchor baseline reset");
        } else {
            CLog.w("resetFingerprintBaseline ignored: RiskEngine not initialized");
        }
    }

    void doShutdown(Runnable stopMonitorAction, Runnable restartMonitorAction) {
        TaskScheduler scheduler;
        AppLifecycleObserver observer;
        boolean wasInitialized;
        long stopGeneration;
        synchronized (lifecycleLock) {
            wasInitialized = initialized;
            initialized = false;
            stopGeneration = lifecycleGeneration.incrementAndGet();
            monitoringGeneration.incrementAndGet();
            scheduler = taskScheduler;
            observer = appLifecycleObserver;
            if (monitorBridgeListener != null) {
                NativeMonitorDispatcher.removeListener(monitorBridgeListener);
                monitorBridgeListener = null;
            }
            if (observer != null) {
                observer.setScreenEventListener(null);
            }
            taskScheduler = null;
            fingerprintStore = null;
            dataAggregator = null;
            collectionLock = null;
            appLifecycleObserver = null;
            config = null;
            appContext = null;
        }
        if (observer != null) {
            observer.unregister();
        }
        if (scheduler != null) {
            scheduler.shutdown();
        }
        // Release lifecycleLock BEFORE calling native stop/pthread_join so a slow
        // monitor pass cannot block concurrent lifecycle queries or reinitialization.
        // The atomic lifecycle generation prevents an older shutdown from leaving a
        // concurrently reinitialized engine's monitor stopped.
        if (wasInitialized && stopMonitorAction != null
                && lifecycleGeneration.get() == stopGeneration) {
            stopMonitorAction.run();
            boolean shouldRestart = false;
            synchronized (lifecycleLock) {
                shouldRestart = lifecycleGeneration.get() != stopGeneration
                        && initialized
                        && (config == null || config.isEnablePeriodicMonitor());
            }
            if (shouldRestart && restartMonitorAction != null) {
                restartMonitorAction.run();
            }
        }
        CLog.i("RiskEngine shutdown");
    }

    /** Package-private test helper for injecting native runtime hooks on JVM tests. */
    void setNativeHooksForTest(NativeRuntimeHooks hooks) {
        this.nativeHooks = hooks != null ? hooks : DEFAULT_NATIVE_HOOKS;
    }

    /** Package-private test helper for injecting a deterministic envelope signer on JVM tests. */
    void setEnvelopeSignerForTest(SignedEnvelopeSigner signer) {
        this.envelopeSigner = signer != null ? signer : new SignedEnvelopeSigner();
    }

    /** Package-private test helper for verifying lock-free shutdown and baseline reset on JVM. */
    void initForTest(FingerprintStore store) {
        synchronized (lifecycleLock) {
            this.config = new RiskEngineConfig.Builder().build();
            this.fingerprintStore = store;
            this.dataAggregator = new DataAggregator(store, this.config);
            this.taskScheduler = new TaskScheduler();
            this.collectionLock = new ReentrantLock(true);
            this.lifecycleGeneration.incrementAndGet();
            this.initialized = true;
        }
    }

    /** Package-private test helper to verify lifecycleLock is released before native stop. */
    boolean isLifecycleLockHeldByCurrentThread() {
        return Thread.holdsLock(lifecycleLock);
    }

    long getLifecycleGenerationForTest() {
        return lifecycleGeneration.get();
    }

    /** Collects a fresh report and serializes it. */
    public static String collectReportJson() {
        return RiskReportJsonSerializer.serialize(collectSync());
    }

    /**
     * @deprecated The old name obscures that a full collection is performed.
     * Use {@link #collectReportJson()}.
     */
    @Deprecated
    public static String getReportJson() {
        return collectReportJson();
    }

    /** Serializes an existing report without performing another collection. */
    public static String reportToJson(RiskReport report) {
        if (report == null) {
            throw new IllegalArgumentException("report must not be null");
        }
        return RiskReportJsonSerializer.serialize(report);
    }

    public static boolean isInitialized() {
        return getInstance().initialized;
    }

    private EngineSnapshot snapshotState() {
        synchronized (lifecycleLock) {
            if (!initialized || taskScheduler == null) {
                throw new IllegalStateException("RiskEngine not initialized");
            }
            return new EngineSnapshot(
                    appContext, config, taskScheduler, dataAggregator,
                    collectionLock, lifecycleGeneration.get());
        }
    }

    private static long remainingMillis(long deadlineNanos) {
        long remainingNanos = deadlineNanos - System.nanoTime();
        if (remainingNanos <= 0) {
            return 0;
        }
        return Math.max(1, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
    }

    private void ensureCollectionActive(EngineSnapshot snapshot) {
        if (!initialized
                || lifecycleGeneration.get() != snapshot.generation
                || Thread.currentThread().isInterrupted()) {
            throw new CancellationException("RiskEngine collection cancelled");
        }
    }

    private static void addMissingCollectorResults(List<BaseCollector> expected,
                                                   List<CollectorResult> actual) {
        Set<String> completed = new HashSet<>();
        for (CollectorResult result : actual) {
            completed.add(result.getFieldName());
        }
        for (BaseCollector collector : expected) {
            if (!completed.contains(collector.getName())) {
                CollectorResult missing = new CollectorResult(collector.getName());
                missing.markError("timeout_or_execution_failure");
                actual.add(missing);
            }
        }
    }

    private static void addMissingDetectionResults(List<BaseDetector> expected,
                                                   List<DetectionResult> actual) {
        Set<String> completed = new HashSet<>();
        for (DetectionResult result : actual) {
            completed.add(result.getDetectorName());
        }
        for (BaseDetector detector : expected) {
            if (!completed.contains(detector.getName())) {
                actual.add(DetectionResult.timeout(
                        detector.getName(), "collection_deadline_exceeded")
                        .withScanTier(detector.getScanTier()));
            }
        }
    }

    private static void notifyError(RiskEngineCallback callback, Throwable error) {
        if (callback == null) {
            return;
        }
        try {
            callback.onError(error);
        } catch (RuntimeException callbackError) {
            CLog.e("RiskEngine error callback failed", callbackError);
        }
    }

    /** Internal seam allowing pure-JVM verification of async init native hooks. */
    interface NativeRuntimeHooks {
        boolean ensureNativeLoaded();
        void setAntiDumpable(boolean enable);
        void startMonitor();
        void stopMonitor();
    }

    private static final class EngineSnapshot {
        private final Context appContext;
        private final RiskEngineConfig config;
        private final TaskScheduler scheduler;
        private final DataAggregator dataAggregator;
        private final ReentrantLock collectionLock;
        private final long generation;

        private EngineSnapshot(Context appContext,
                               RiskEngineConfig config,
                               TaskScheduler scheduler,
                               DataAggregator dataAggregator,
                               ReentrantLock collectionLock,
                               long generation) {
            this.appContext = appContext;
            this.config = config;
            this.scheduler = scheduler;
            this.dataAggregator = dataAggregator;
            this.collectionLock = collectionLock;
            this.generation = generation;
        }
    }
}
