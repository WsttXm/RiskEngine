package com.wsttxm.riskenginesdk.integrationtest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

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
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.SignedRiskEnvelope;
import com.wsttxm.riskenginesdk.model.ThreatEvent;
import com.wsttxm.riskenginesdk.model.TierReport;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * L3 Android instrumentation suite verifying the standalone release AAR runtime
 * end-to-end across API 30 / 34 / 36 KVM emulators.
 */
@RunWith(AndroidJUnit4.class)
public final class RiskEngineInstrumentationTest {
    private static final Set<String> EXPECTED_16_DOMAINS = new HashSet<>(Arrays.asList(
            "root",
            "mount_analysis",
            "hook_framework",
            "debug",
            "consistency",
            "emulator",
            "cloud_phone",
            "adb",
            "custom_rom",
            "app_integrity",
            "tee_integrity",
            "multi_instance",
            "network_risk",
            "location_risk",
            "screen_and_fraud",
            "threat_apps"
    ));

    private Context appContext;

    @Before
    public void setUp() {
        appContext = InstrumentationRegistry.getInstrumentation().getTargetContext().getApplicationContext();
        RiskEngine.stopMonitoring();
        RiskEngine.shutdown();
    }

    @After
    public void tearDown() {
        RiskEngine.stopMonitoring();
        RiskEngine.shutdown();
    }

    @Test
    public void initAndCollectSyncCoversAll16DomainsEvidenceItemsAndJsonV2() throws Exception {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.BALANCED)
                .build();

        assertTrue("First initIfNeeded must initialize SDK", RiskEngine.initIfNeeded(appContext, config));
        assertFalse("Second initIfNeeded must be idempotent", RiskEngine.initIfNeeded(appContext, config));
        assertTrue(RiskEngine.isInitialized());

        RiskReport report = RiskEngine.collectSync(CollectScene.DIAGNOSTIC);
        assertNotNull("RiskReport must not be null", report);
        assertNotNull("OverallRiskLevel must not be null", report.getOverallRiskLevel());
        assertNotNull("TrustTier must not be null", report.getTrustTier());
        assertNotNull("DevicePosture must not be null", report.getDevicePosture());
        assertNotNull("FingerprintId must not be null", report.getFingerprintId());

        List<DetectionResult> detections = report.getDetections();
        assertExact16CanonicalDomains(detections);

        String jsonStr = RiskEngine.reportToJson(report);
        assertNotNull(jsonStr);
        JSONObject root = new JSONObject(jsonStr);
        assertEquals("JSON schema version must be v2", 2, root.getInt("schemaVersion"));
        assertTrue("JSON must include trustTier", root.has("trustTier"));
        assertTrue("JSON must include devicePosture", root.has("devicePosture"));
        assertTrue("JSON must include fingerprintId", root.has("fingerprintId"));

        JSONArray detArray = root.getJSONArray("detections");
        assertEquals("JSON detections length must match report detections", detections.size(), detArray.length());
        Set<String> jsonCanonicalDomains = new HashSet<>();
        for (int i = 0; i < detArray.length(); i++) {
            JSONObject item = detArray.getJSONObject(i);
            assertTrue("Each detection must include evidenceItems array", item.has("evidenceItems"));
            assertTrue("Each detection must include evidenceFamilies array", item.has("evidenceFamilies"));
            assertTrue("Each detection must include scanTier", item.has("scanTier"));
            String detName = item.getString("detectorName");
            if (!SmokeActivity.isSyntheticDetectionName(detName)) {
                assertTrue("Duplicate canonical domain in JSON: " + detName,
                        jsonCanonicalDomains.add(detName));
            }
        }
        assertEquals("JSON must contain all 16 canonical domains", EXPECTED_16_DOMAINS, jsonCanonicalDomains);
    }

    @Test
    public void monitoringCallbacksDeliverProgressiveTiersAndDevicePosture() throws Exception {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.BALANCED)
                .build();
        assertTrue(RiskEngine.initIfNeeded(appContext, config));

        CountDownLatch criticalLatch = new CountDownLatch(1);
        CountDownLatch fastLatch = new CountDownLatch(1);
        CountDownLatch postponedLatch = new CountDownLatch(1);
        CountDownLatch postureLatch = new CountDownLatch(1);

        AtomicReference<TierReport> criticalRef = new AtomicReference<>();
        AtomicReference<TierReport> fastRef = new AtomicReference<>();
        AtomicReference<RiskReport> postponedRef = new AtomicReference<>();
        AtomicReference<DevicePosture> postureRef = new AtomicReference<>();
        AtomicReference<Throwable> callbackError = new AtomicReference<>();

        ThreatListener threatListener = new ThreatListener() {
            @Override
            public void onThreatDetected(ThreatEvent event) {
                if (event == null) {
                    callbackError.compareAndSet(null, new AssertionError("ThreatEvent must not be null"));
                }
            }

            @Override
            public void onRuntimeTamperDetected(ThreatEvent event) {
                if (event == null) {
                    callbackError.compareAndSet(null, new AssertionError("Runtime tamper ThreatEvent must not be null"));
                }
            }
        };

        DeviceStateListener deviceStateListener = new DeviceStateListener() {
            @Override
            public void onDeviceStateEvaluated(DevicePosture posture) {
                postureRef.set(posture);
                postureLatch.countDown();
            }
        };

        ExecutionStateListener executionStateListener = new ExecutionStateListener() {
            @Override
            public void onCriticalChecksFinished(TierReport report) {
                criticalRef.set(report);
                criticalLatch.countDown();
            }

            @Override
            public void onFastChecksFinished(TierReport report) {
                fastRef.set(report);
                fastLatch.countDown();
            }

            @Override
            public void onPostponedChecksFinished(RiskReport report) {
                postponedRef.set(report);
                postponedLatch.countDown();
            }
        };

        RiskEngine.startMonitoring(threatListener, deviceStateListener, executionStateListener);

        assertTrue("CRITICAL tier callback did not fire within 20s",
                criticalLatch.await(20, TimeUnit.SECONDS));
        assertTrue("FAST tier callback did not fire within 20s",
                fastLatch.await(20, TimeUnit.SECONDS));
        assertTrue("POSTPONED tier callback did not fire within 30s",
                postponedLatch.await(30, TimeUnit.SECONDS));
        assertTrue("DeviceStateListener callback did not fire within 20s",
                postureLatch.await(20, TimeUnit.SECONDS));

        assertNull("Unexpected error in monitoring callback", callbackError.get());
        assertNotNull(criticalRef.get());
        assertNotNull(fastRef.get());
        assertNotNull(postponedRef.get());
        assertExact16CanonicalDomains(postponedRef.get().getDetections());
        assertNotNull(postureRef.get());

        RiskEngine.stopMonitoring();
    }

    @Test
    public void collectSignedEnvelopePersistentKeyProducesValidCanonicalPayload() throws Exception {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.BALANCED)
                .build();
        assertTrue(RiskEngine.initIfNeeded(appContext, config));

        byte[] challenge = "riskengine-l3-challenge-nonce-32".getBytes(StandardCharsets.UTF_8);
        SignedRiskEnvelope envelope = RiskEngine.collectSignedEnvelopeSync(
                CollectScene.PAYMENT, challenge, EnvelopeMode.PERSISTENT_KEY);

        assertNotNull("SignedRiskEnvelope must not be null", envelope);
        assertNotNull("Wrapped RiskReport must not be null", envelope.getReport());
        assertExact16CanonicalDomains(envelope.getReport().getDetections());
        assertEquals(EnvelopeMode.PERSISTENT_KEY, envelope.getRequestedMode());
        assertNotNull(envelope.getAttestationMode());
        assertNotNull(envelope.getKeySecurityLevel());
        assertNotNull(envelope.getChallengeBase64Url());
        assertFalse(envelope.getChallengeBase64Url().isEmpty());
        assertNotNull(envelope.getReportSha256());
        assertEquals(64, envelope.getReportSha256().length());

        String canonicalJson = envelope.getCanonicalPayloadJson();
        assertNotNull(canonicalJson);
        JSONObject canonical = new JSONObject(canonicalJson);
        assertEquals(2, SignedRiskEnvelope.PROTOCOL_VERSION);
        assertEquals(SignedRiskEnvelope.PROTOCOL_VERSION, canonical.getInt("v"));
        assertEquals(envelope.getReportSha256(), canonical.getString("reportSha256"));
        assertEquals(envelope.getChallengeBase64Url(), canonical.getString("challenge"));
        assertEquals(envelope.getReport().getRecommendedAction().name(), canonical.getString("action"));
        assertEquals(envelope.getReport().getConfidencePercent(), canonical.getInt("confidence"));
        JSONObject payloadDims = canonical.getJSONObject("dimensions");
        assertEquals(4, payloadDims.length());

        String fullJson = envelope.toReportJson();
        assertNotNull(fullJson);
        JSONObject fullObj = new JSONObject(fullJson);
        assertEquals(2, fullObj.getInt("schemaVersion"));
        assertEquals(100, fullObj.getInt("maxRiskScore"));
        assertEquals(100, fullObj.getInt("displayThresholdMaximum"));
        assertTrue("JSON v2 must include dimensionScores", fullObj.has("dimensionScores"));
        assertTrue("JSON v2 must include scoreBreakdown", fullObj.has("scoreBreakdown"));
        assertTrue("JSON v2 must include recommendedAction", fullObj.has("recommendedAction"));
        assertTrue("JSON v2 must include hardTriggers", fullObj.has("hardTriggers"));
        assertTrue("JSON v2 must include confidencePercent", fullObj.has("confidencePercent"));
        assertTrue("Signed envelope JSON must contain signedEnvelope object",
                fullObj.has("signedEnvelope"));
        JSONObject envelopeObj = fullObj.getJSONObject("signedEnvelope");
        assertEquals(envelope.getAttestationMode().name(), envelopeObj.getString("attestationMode"));
        assertEquals(envelope.getKeySecurityLevel().name(), envelopeObj.getString("keySecurityLevel"));
        assertTrue("signedEnvelope must include payload", envelopeObj.has("payload"));
        assertTrue("signedEnvelope must include signatureBase64", envelopeObj.has("signatureBase64"));
        assertTrue("signedEnvelope must include certChainPem", envelopeObj.has("certChainPem"));
    }

    @Test
    public void smokeActivityExercisesReleaseAarEndToEnd() throws Exception {
        AtomicReference<SmokeActivity> activityRef = new AtomicReference<>();
        try (ActivityScenario<SmokeActivity> scenario = ActivityScenario.launch(SmokeActivity.class)) {
            scenario.onActivity(activityRef::set);
            SmokeActivity activity = activityRef.get();
            assertNotNull("SmokeActivity must launch", activity);
            assertTrue("SmokeActivity async AAR check did not complete within 60s",
                    activity.awaitSmokeFinished(60_000L));
            String summary = activity.getLastSummary();
            assertNotNull(summary);
            assertTrue("Expected AAR OK summary with 16 domains and monitor=OK, got: " + summary,
                    summary.startsWith("AAR OK | domains=16 | monitor=OK"));
        }
    }

    @Test
    public void cleanShutdownResetsStateAndAllowsReinitialization() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.MINIMAL)
                .build();

        assertTrue(RiskEngine.initIfNeeded(appContext, config));
        assertTrue(RiskEngine.isInitialized());

        RiskEngine.shutdown();
        assertFalse("SDK must report uninitialized after shutdown", RiskEngine.isInitialized());

        assertTrue("Re-initialization after clean shutdown must succeed",
                RiskEngine.initIfNeeded(appContext, config));
        assertTrue(RiskEngine.isInitialized());

        RiskReport afterReinit = RiskEngine.collectSync(CollectScene.STANDARD);
        assertNotNull(afterReinit);
        assertExact16CanonicalDomains(afterReinit.getDetections());
    }

    private static void assertExact16CanonicalDomains(List<DetectionResult> detections) {
        assertNotNull("Detections list must not be null", detections);
        Set<String> canonicalDomains = new HashSet<>();
        for (DetectionResult result : detections) {
            assertNotNull(result);
            assertNotNull(result.getDetectorName());
            assertNotNull(result.getStatus());
            assertNotNull(result.getRiskLevel());
            assertNotNull(result.getScanTier());
            assertNotNull(result.getDetails());
            assertNotNull(result.getEvidenceItems());
            for (EvidenceItem item : result.getEvidenceItems()) {
                assertNotNull("EvidenceItem code must not be null", item.getCode());
                assertFalse("EvidenceItem code must not be empty", item.getCode().isEmpty());
                assertNotNull("EvidenceItem primarySource must not be null", item.getPrimarySource());
                assertNotNull("EvidenceItem mergedSources must not be null", item.getMergedSources());
                assertNotNull("EvidenceItem rank must not be null", item.getRank());
            }
            if (!SmokeActivity.isSyntheticDetectionName(result.getDetectorName())) {
                assertTrue("Duplicate canonical domain: " + result.getDetectorName(),
                        canonicalDomains.add(result.getDetectorName()));
            }
        }
        assertEquals(
                "Canonical domains must match exact 16 converged domains without inflation",
                EXPECTED_16_DOMAINS,
                canonicalDomains);
    }
}
