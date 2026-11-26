package com.wsttxm.riskenginesdk.integrationtest;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.DeviceStateListener;
import com.wsttxm.riskenginesdk.EnvelopeMode;
import com.wsttxm.riskenginesdk.ExecutionStateListener;
import com.wsttxm.riskenginesdk.PrivacyProfile;
import com.wsttxm.riskenginesdk.RiskEngine;
import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.ThreatListener;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.model.TierReport;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** End-to-end smoke host exercising the standalone release AAR runtime. */
public final class SmokeActivity extends Activity {
    private TextView statusView;
    private ExecutorService smokeExecutor;
    private final AtomicReference<String> lastSummary = new AtomicReference<>("Initializing...");
    private final CountDownLatch monitoringFinishedLatch = new CountDownLatch(1);
    private final CountDownLatch smokeFinishedLatch = new CountDownLatch(1);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        statusView = new TextView(this);
        statusView.setText(lastSummary.get());
        setContentView(statusView);

        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.BALANCED)
                .build();
        RiskEngine.initIfNeeded(getApplicationContext(), config);

        RiskEngine.startMonitoring(
                new ThreatListener() {
                    @Override
                    public void onThreatDetected(ThreatEvent event) {
                        // Exercised for runtime AAR callback wiring.
                    }

                    @Override
                    public void onRuntimeTamperDetected(ThreatEvent event) {
                        // Exercised for runtime AAR callback wiring.
                    }
                },
                new DeviceStateListener() {
                    @Override
                    public void onDeviceStateEvaluated(DevicePosture posture) {
                        // Exercised for runtime AAR callback wiring.
                    }
                },
                new ExecutionStateListener() {
                    @Override
                    public void onCriticalChecksFinished(TierReport report) {
                        // Exercised for progressive tier wiring.
                    }

                    @Override
                    public void onFastChecksFinished(TierReport report) {
                        // Exercised for progressive tier wiring.
                    }

                    @Override
                    public void onPostponedChecksFinished(RiskReport report) {
                        monitoringFinishedLatch.countDown();
                    }
                });

        smokeExecutor = Executors.newSingleThreadExecutor();
        smokeExecutor.execute(() -> {
            String summary;
            try {
                // Serialize after initial tiered monitoring pass to avoid collectionLock budget contention.
                boolean monitoringDone = monitoringFinishedLatch.await(30, TimeUnit.SECONDS);
                RiskReport report = RiskEngine.collectSync(CollectScene.DIAGNOSTIC);
                byte[] challenge = "riskengine-smoke-nonce-32bytes!!".getBytes(StandardCharsets.UTF_8);
                SignedRiskEnvelope envelope = RiskEngine.collectSignedEnvelopeSync(
                        CollectScene.LOGIN, challenge, EnvelopeMode.PERSISTENT_KEY);
                int canonicalDomains = countCanonicalDomains(report);
                summary = String.format(
                        Locale.US,
                        "AAR OK | domains=%d | monitor=%s | level=%s | trust=%s | env=%s",
                        canonicalDomains,
                        monitoringDone ? "OK" : "TIMEOUT",
                        report != null && report.getOverallRiskLevel() != null
                                ? report.getOverallRiskLevel().name() : "NULL",
                        report != null && report.getTrustTier() != null
                                ? report.getTrustTier().name() : "NULL",
                        envelope != null && envelope.getAttestationMode() != null
                                ? envelope.getAttestationMode().name() : "NULL");
            } catch (Exception | LinkageError e) {
                summary = "AAR ERROR: " + e.getClass().getSimpleName();
            }
            lastSummary.set(summary);
            smokeFinishedLatch.countDown();
            final String display = summary;
            runOnUiThread(() -> {
                if (!isDestroyed() && statusView != null) {
                    statusView.setText(display);
                }
            });
        });
    }

    static boolean isSyntheticDetectionName(String name) {
        if (name == null) {
            return false;
        }
        return "signal_correlation".equals(name)
                || "multi_source_validation".equals(name)
                || "fingerprint_continuity".equals(name)
                || name.startsWith("collector:");
    }

    private static int countCanonicalDomains(RiskReport report) {
        if (report == null) {
            return -1;
        }
        int count = 0;
        for (DetectionResult result : report.getDetections()) {
            if (result != null && !isSyntheticDetectionName(result.getDetectorName())) {
                count++;
            }
        }
        return count;
    }

    /** Returns the latest rendered AAR smoke summary string. */
    public String getLastSummary() {
        return lastSummary.get();
    }

    /** Blocks up to {@code timeoutMs} for the async smoke check to finish. */
    boolean awaitSmokeFinished(long timeoutMs) throws InterruptedException {
        return smokeFinishedLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
    }

    @Override
    protected void onDestroy() {
        if (smokeExecutor != null) {
            smokeExecutor.shutdownNow();
            smokeExecutor = null;
        }
        RiskEngine.stopMonitoring();
        if (isFinishing()) {
            RiskEngine.shutdown();
        }
        super.onDestroy();
    }
}
