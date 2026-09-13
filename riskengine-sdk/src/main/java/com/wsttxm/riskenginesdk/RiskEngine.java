package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.os.Looper;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.CollectorRegistry;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.TaskScheduler;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.DetectorRegistry;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.RiskReportJsonSerializer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public final class RiskEngine {
    private static volatile RiskEngine instance;

    private final Object lifecycleLock = new Object();

    private Context appContext;
    private RiskEngineConfig config;
    private TaskScheduler taskScheduler;
    private DataAggregator dataAggregator;
    private ReentrantLock collectionLock;
    private volatile boolean initialized;
    private volatile long lifecycleGeneration;

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

    public static void init(Context context, RiskEngineConfig config) {
        getInstance().doInit(context, config);
    }

    /** Atomically initializes the singleton once. Returns true when this call initialized it. */
    public static boolean initIfNeeded(Context context, RiskEngineConfig config) {
        RiskEngine engine = getInstance();
        synchronized (engine.lifecycleLock) {
            if (engine.initialized) {
                return false;
            }
            engine.doInit(context, config);
            return true;
        }
    }

    private void doInit(Context context, RiskEngineConfig requestedConfig) {
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        if (requestedConfig == null) {
            throw new IllegalArgumentException("config must not be null");
        }

        synchronized (lifecycleLock) {
            if (initialized) {
                throw new IllegalStateException(
                        "RiskEngine already initialized; call shutdown before reinitializing");
            }

            Context application = context.getApplicationContext();
            appContext = application != null ? application : context;
            config = requestedConfig;
            CLog.setEnabled(config.isDebugLog());
            taskScheduler = new TaskScheduler();
            dataAggregator = new DataAggregator(
                    new com.wsttxm.riskenginesdk.core.FingerprintStore(appContext));
            collectionLock = new ReentrantLock(true);
            // JNI_OnLoad starts the monitor on first load. An explicit start
            // is also required after shutdown/reinitialization in one process.
            com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge.startMonitor();
            lifecycleGeneration++;
            initialized = true;
        }
        CLog.i("RiskEngine initialized");
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
            requestGeneration = lifecycleGeneration;
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

    private RiskReport doCollectSync(long startNanos, long expectedGeneration,
                                     CollectScene sceneOverride) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException(
                    "Synchronous collection must not run on the Android main thread");
        }
        EngineSnapshot snapshot = snapshotState();
        if (expectedGeneration >= 0 && snapshot.generation != expectedGeneration) {
            throw new CancellationException("RiskEngine lifecycle changed before collection");
        }
        long deadlineNanos = startNanos
                + TimeUnit.MILLISECONDS.toNanos(snapshot.config.getCollectTimeoutMs());
        CollectScene scene = sceneOverride != null
                ? sceneOverride : snapshot.config.getCollectScene();
        CLog.i("Starting collection...");

        if (!acquireCollectionLock(snapshot, deadlineNanos)) {
            ensureCollectionActive(snapshot);
            return buildTimeoutReport(snapshot, startNanos, scene);
        }
        try {
            ensureCollectionActive(snapshot);

            // Use a collection-local signal cache. invokeAll cancels work at
            // the deadline, but platform/native calls are not guaranteed to
            // react to interruption immediately. A late task must therefore
            // be unable to repopulate the next report's cache.
            SignalSnapshot signals = new SignalSnapshot(snapshot.appContext);
            CollectorRegistry collectorRegistry = new CollectorRegistry(
                    snapshot.appContext, snapshot.config, signals);
            DetectorRegistry detectorRegistry = new DetectorRegistry(
                    snapshot.appContext, snapshot.config, signals, scene);

            List<BaseCollector> collectors = collectorRegistry.getCollectors();
            List<CollectorResult> collectorResults = snapshot.scheduler.submitAllAndWait(
                    collectors, remainingMillis(deadlineNanos));
            ensureCollectionActive(snapshot);
            addMissingCollectorResults(collectors, collectorResults);

            List<BaseDetector> detectors = detectorRegistry.getDetectors();
            List<DetectionResult> detectionResults = snapshot.scheduler.submitAllAndWait(
                    detectors, remainingMillis(deadlineNanos));
            ensureCollectionActive(snapshot);
            addMissingDetectionResults(detectors, detectionResults);

            RiskReport report = snapshot.dataAggregator.aggregate(
                    collectorResults, detectionResults, scene);
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            CLog.i("Collection completed in " + elapsedMs + "ms, risk level: "
                    + report.getOverallRiskLevel());
            return report;
        } finally {
            snapshot.collectionLock.unlock();
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
                                          CollectScene scene) {
        SignalSnapshot signals = new SignalSnapshot(snapshot.appContext);
        List<BaseCollector> collectors = new CollectorRegistry(
                snapshot.appContext, snapshot.config, signals).getCollectors();
        List<CollectorResult> collectorResults = new ArrayList<>();
        addMissingCollectorResults(collectors, collectorResults);

        List<BaseDetector> detectors = new DetectorRegistry(
                snapshot.appContext, snapshot.config, signals, scene).getDetectors();
        List<DetectionResult> detectionResults = new ArrayList<>();
        addMissingDetectionResults(detectors, detectionResults);

        RiskReport report = snapshot.dataAggregator.aggregate(
                collectorResults, detectionResults, scene);
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
        CLog.w("Collection timed out while waiting for the previous collection after "
                + elapsedMs + "ms");
        return report;
    }

    public static void shutdown() {
        RiskEngine engine = getInstance();
        TaskScheduler scheduler;
        synchronized (engine.lifecycleLock) {
            boolean wasInitialized = engine.initialized;
            engine.initialized = false;
            engine.lifecycleGeneration++;
            scheduler = engine.taskScheduler;
            engine.taskScheduler = null;
            engine.dataAggregator = null;
            engine.collectionLock = null;
            engine.config = null;
            engine.appContext = null;
            // Serialize stop against a concurrent reinitialization; otherwise
            // an older shutdown could stop the newly initialized monitor.
            if (wasInitialized) {
                com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge.stopMonitor();
            }
        }
        if (scheduler != null) {
            scheduler.shutdown();
        }
        // Stop the native re-verification thread so it does not outlive the
        // engine and keep running after the host app tears the SDK down.
        CLog.i("RiskEngine shutdown");
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
                    collectionLock, lifecycleGeneration);
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
                || lifecycleGeneration != snapshot.generation
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
                        detector.getName(), "collection_deadline_exceeded"));
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
