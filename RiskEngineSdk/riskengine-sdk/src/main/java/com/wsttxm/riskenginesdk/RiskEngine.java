package com.wsttxm.riskenginesdk;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.CollectorRegistry;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.TaskScheduler;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.DetectorRegistry;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.transport.DataEncryptor;
import com.wsttxm.riskenginesdk.transport.HeartbeatManager;
import com.wsttxm.riskenginesdk.transport.ReportSerializer;
import com.wsttxm.riskenginesdk.transport.TransportClient;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

public class RiskEngine {
    private static volatile RiskEngine instance;

    private Context appContext;
    private RiskEngineConfig config;
    private TaskScheduler taskScheduler;
    private CollectorRegistry collectorRegistry;
    private DetectorRegistry detectorRegistry;
    private DataAggregator dataAggregator;
    private ReportSerializer reportSerializer;
    private TransportClient transportClient;
    private HeartbeatManager heartbeatManager;
    private boolean initialized = false;

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

    private synchronized void doInit(Context context, RiskEngineConfig config) {
        if (initialized) {
            CLog.w("RiskEngine already initialized");
            return;
        }

        this.appContext = context.getApplicationContext();
        this.config = config;
        CLog.setEnabled(config.isDebugLog());

        this.taskScheduler = new TaskScheduler();
        this.collectorRegistry = new CollectorRegistry(appContext);
        this.detectorRegistry = new DetectorRegistry(appContext);
        this.dataAggregator = new DataAggregator();
        this.reportSerializer = new ReportSerializer();

        if (config.getServerUrl() != null) {
            this.transportClient = new TransportClient(config.getServerUrl(), config.getAppKey());
        }

        this.initialized = true;
        CLog.i("RiskEngine initialized");
    }

    public static void collect(RiskEngineCallback callback) {
        getInstance().doCollect(callback);
    }

    private void doCollect(RiskEngineCallback callback) {
        if (!initialized) {
            if (callback != null) {
                callback.onError(new IllegalStateException("RiskEngine not initialized"));
            }
            return;
        }

        taskScheduler.submit(() -> {
            try {
                RiskReport report = doCollectSync();
                if (callback != null) {
                    callback.onSuccess(report);
                }
            } catch (Exception e) {
                CLog.e("Collection failed", e);
                if (callback != null) {
                    callback.onError(e);
                }
            }
            return null;
        });
    }

    public static RiskReport collectSync() {
        return getInstance().doCollectSync();
    }

    private RiskReport doCollectSync() {
        if (!initialized) {
            throw new IllegalStateException("RiskEngine not initialized");
        }

        long startTime = System.currentTimeMillis();
        CLog.i("Starting collection...");

        // Collect fingerprints
        List<Callable<CollectorResult>> collectorTasks = new ArrayList<>();
        for (BaseCollector collector : collectorRegistry.getCollectors()) {
            collectorTasks.add(collector);
        }
        List<CollectorResult> collectorResults = taskScheduler.submitAllAndWait(
                collectorTasks, config.getCollectTimeoutMs());

        // Run detectors
        List<Callable<DetectionResult>> detectorTasks = new ArrayList<>();
        for (BaseDetector detector : detectorRegistry.getDetectors()) {
            detectorTasks.add(detector);
        }
        List<DetectionResult> detectionResults = taskScheduler.submitAllAndWait(
                detectorTasks, config.getCollectTimeoutMs());

        // Aggregate
        RiskReport report = dataAggregator.aggregate(collectorResults, detectionResults);

        long elapsed = System.currentTimeMillis() - startTime;
        CLog.i("Collection completed in " + elapsed + "ms, risk level: " +
                report.getOverallRiskLevel());

        // Upload if server configured
        uploadReport(report);

        return report;
    }

    private void uploadReport(RiskReport report) {
        if (transportClient == null) return;

        try {
            String json = reportSerializer.serialize(report);
            String payload;
            boolean encrypted = false;

            // 配置了加密密钥时, 使用AES-256-GCM加密传输
            if (config.getEncryptionKey() != null && config.getEncryptionKey().length > 0) {
                DataEncryptor encryptor = new DataEncryptor(config.getEncryptionKey());
                payload = encryptor.encrypt(json);
                encrypted = true;
                if (payload == null) {
                    CLog.e("Encryption failed, falling back to plaintext");
                    payload = json;
                    encrypted = false;
                }
            } else {
                payload = json;
            }

            transportClient.sendReport(payload, encrypted, new TransportClient.TransportCallback() {
                @Override
                public void onSuccess(String response) {
                    CLog.i("Report uploaded successfully");
                }

                @Override
                public void onFailure(Exception e) {
                    CLog.e("Report upload failed", e);
                }
            });
        } catch (Exception e) {
            CLog.e("Report serialization failed", e);
        }
    }

    public static void startHeartbeat(long intervalMs) {
        RiskEngine engine = getInstance();
        if (!engine.initialized) return;

        engine.heartbeatManager = new HeartbeatManager(() -> {
            try {
                engine.doCollectSync();
            } catch (Exception e) {
                CLog.e("Heartbeat collection failed", e);
            }
        });
        engine.heartbeatManager.start(intervalMs);
    }

    public static void shutdown() {
        RiskEngine engine = getInstance();
        if (engine.heartbeatManager != null) {
            engine.heartbeatManager.stop();
        }
        if (engine.taskScheduler != null) {
            engine.taskScheduler.shutdown();
        }
        engine.initialized = false;
        CLog.i("RiskEngine shutdown");
    }

    public static String getReportJson() {
        RiskEngine engine = getInstance();
        if (!engine.initialized) return null;
        RiskReport report = engine.doCollectSync();
        return engine.reportSerializer.serialize(report);
    }

    public static boolean isInitialized() {
        return getInstance().initialized;
    }
}
