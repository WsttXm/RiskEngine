package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.detector.ScreenAndFraudDetector;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class ScreenAndFraudDetectorTest {

    private static final class FakeScreenFraudEnv
            implements ScreenAndFraudDetector.ScreenAndFraudEnvironment {
        List<String> virtualDisplays = Collections.emptyList();
        List<String> thirdPartyA11y = Collections.emptyList();
        List<String> virtualInputs = Collections.emptyList();
        boolean recordingActive = false;
        long lastCaptureMs = 0L;
        String callMode = null;
        long nowWallMs = 1_750_000_000_000L;
        long nowMonoMs = 500_000L;
        long buildTimeMs = 1_700_000_000_000L;
        Integer autoTime = 1;
        ScreenAndFraudDetector.ClockAnchor anchor = null;

        @Override public List<String> findVirtualOrPresentationDisplays() { return virtualDisplays; }
        @Override public List<String> findThirdPartyAccessibilityServices() { return thirdPartyA11y; }
        @Override public List<String> findVirtualInputDevices() { return virtualInputs; }
        @Override public boolean isScreenRecordingActive() { return recordingActive; }
        @Override public long getLastScreenCaptureWallMs() { return lastCaptureMs; }
        @Override public String getOngoingCallMode() { return callMode; }
        @Override public long currentTimeMillis() { return nowWallMs; }
        @Override public long elapsedRealtimeMillis() { return nowMonoMs; }
        @Override public long getBuildTimeMillis() { return buildTimeMs; }
        @Override public Integer getAutoTimeSetting() { return autoTime; }
        @Override public ScreenAndFraudDetector.ClockAnchor getAndUpdateClockAnchor(
                ScreenAndFraudDetector.ClockAnchor next) {
            ScreenAndFraudDetector.ClockAnchor prev = anchor;
            anchor = next;
            return prev;
        }
    }

    @Before
    @After
    public void resetStaticHooks() {
        ScreenAndFraudDetector.resetRuntimeStateForTest();
    }

    @Test
    public void cleanDeviceProducesSafe() {
        FakeScreenFraudEnv env = new FakeScreenFraudEnv();
        DetectionResult result = ScreenAndFraudDetector.createForTest(null, env).call();

        assertEquals("screen_and_fraud", result.getDetectorName());
        assertEquals(ScanTier.FAST, result.getScanTier());
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertEquals(0, result.getScore());
        assertTrue(result.getDetails().isEmpty());
        assertTrue(result.getEvidenceItems().isEmpty());
    }

    @Test
    public void ongoingCallAloneStaysLow1Informational() {
        FakeScreenFraudEnv env = new FakeScreenFraudEnv();
        env.callMode = "in_call";

        DetectionResult raw = ScreenAndFraudDetector.createForTest(null, env).call();
        assertEquals(RiskLevel.LOW, raw.getRiskLevel());
        assertEquals(1, raw.getScore());
        assertTrue(raw.isInformational());
        assertTrue(raw.getDetails().contains("ongoing_call:in_call"));
        assertTrue(raw.getEvidenceItems().stream()
                .anyMatch(e -> "ongoing_call".equals(e.getCode())
                        && "fraud_context".equals(e.getEvidenceFamily())));

        // Even in PAYMENT, ongoing_call alone does NOT trigger C10 or escalate to HIGH.
        DetectionResult payment = CorrelationEngine.applyScene(raw, CollectScene.PAYMENT);
        assertTrue(payment.isInformational());
        assertNull(CorrelationEngine.correlate(List.of(payment), CollectScene.PAYMENT));
    }

    @Test
    public void timeSpoofingTriggersMedium4ActionableInAllScenes() {
        // Case 1: currentTimeMillis < Build.TIME and AUTO_TIME == 0
        FakeScreenFraudEnv env = new FakeScreenFraudEnv();
        env.nowWallMs = 1_600_000_000_000L;
        env.buildTimeMs = 1_700_000_000_000L;
        env.autoTime = 0;

        DetectionResult res1 = ScreenAndFraudDetector.createForTest(null, env).call();
        assertEquals(RiskLevel.MEDIUM, res1.getRiskLevel());
        assertEquals(4, res1.getScore());
        assertFalse(res1.isInformational());
        assertTrue(res1.getDetails().contains("time_spoofing:before_build_time"));
        assertTrue(res1.getDetails().contains("time_spoofing:auto_time_disabled"));

        // Case 2: wall-clock rollback relative to monotonic elapsedRealtime
        FakeScreenFraudEnv driftEnv = new FakeScreenFraudEnv();
        driftEnv.anchor = new ScreenAndFraudDetector.ClockAnchor(1_750_000_000_000L, 500_000L);
        driftEnv.nowWallMs = 1_749_999_800_000L; // rolled back 200 seconds
        driftEnv.nowMonoMs = 505_000L;           // monotonic advanced 5 seconds

        DetectionResult res2 = ScreenAndFraudDetector.createForTest(null, driftEnv).call();
        assertEquals(RiskLevel.MEDIUM, res2.getRiskLevel());
        assertEquals(4, res2.getScore());
        assertFalse(res2.isInformational());
        assertTrue(res2.getDetails().contains("time_spoofing:clock_rollback"));

        // Case 3: large forward jump relative to monotonic clock
        FakeScreenFraudEnv jumpEnv = new FakeScreenFraudEnv();
        jumpEnv.anchor = new ScreenAndFraudDetector.ClockAnchor(1_750_000_000_000L, 500_000L);
        jumpEnv.nowWallMs = 1_750_001_000_000L; // jumped forward 1000s
        jumpEnv.nowMonoMs = 502_000L;           // monotonic advanced 2s

        DetectionResult res3 = ScreenAndFraudDetector.createForTest(null, jumpEnv).call();
        assertEquals(RiskLevel.MEDIUM, res3.getRiskLevel());
        assertTrue(res3.getDetails().contains("time_spoofing:clock_jump"));
    }

    @Test
    public void virtualDisplayThirdPartyA11yAndVirtualInputElevateToHigh7InPaymentAndTriggerC10WithCall() {
        FakeScreenFraudEnv env = new FakeScreenFraudEnv();
        env.virtualDisplays = Collections.singletonList("scrcpy_virtual");
        env.thirdPartyA11y = Collections.singletonList("com.remote.autoclicker");
        env.virtualInputs = Collections.singletonList("uinput_touch");
        env.callMode = "in_communication";

        DetectionResult raw = ScreenAndFraudDetector.createForTest(null, env).call();
        assertEquals(RiskLevel.MEDIUM, raw.getRiskLevel());
        assertEquals(5, raw.getScore());
        assertFalse(raw.isInformational());
        assertTrue(raw.getDetails().contains("virtual_display:scrcpy_virtual"));
        assertTrue(raw.getDetails().contains("third_party_a11y:com.remote.autoclicker"));
        assertTrue(raw.getDetails().contains("virtual_input:uinput_touch"));
        assertTrue(raw.getDetails().contains("ongoing_call:in_communication"));

        Set<String> families = EvidenceFamily.families(raw.getDetails(), raw.getEvidenceItems());
        assertTrue(families.contains("screen_control"));
        assertTrue(families.contains("fraud_context"));

        DetectionResult payment = CorrelationEngine.applyScene(raw, CollectScene.PAYMENT);
        assertEquals(RiskLevel.HIGH, payment.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, payment.getStatus());
        assertEquals(7, payment.getScore());
        assertFalse(payment.isInformational());

        DetectionResult correlated = CorrelationEngine.correlate(
                List.of(payment), CollectScene.PAYMENT);
        assertNotNull(correlated);
        assertEquals(RiskLevel.HIGH, correlated.getRiskLevel());
        assertEquals(8, correlated.getScore());
        assertTrue(correlated.getDetails().contains("C10:vishing_fraud_combo"));
    }

    @Test
    public void runtimeCaptureAndRecordingStateHooksSurfaceAndRiskWindowGuardIsNullSafe() {
        ScreenAndFraudDetector.setScreenRecordingActive(true);
        ScreenAndFraudDetector.notifyScreenCaptureObservedAt(1_750_000_000_000L);
        assertTrue(ScreenAndFraudDetector.isScreenRecordingActive());
        assertEquals(1_750_000_000_000L, ScreenAndFraudDetector.getLastScreenCaptureWallMs());

        FakeScreenFraudEnv env = new FakeScreenFraudEnv();
        env.recordingActive = ScreenAndFraudDetector.isScreenRecordingActive();
        env.lastCaptureMs = ScreenAndFraudDetector.getLastScreenCaptureWallMs();
        env.nowWallMs = 1_750_000_005_000L;

        DetectionResult result = ScreenAndFraudDetector.createForTest(null, env).call();
        assertEquals(RiskLevel.MEDIUM, result.getRiskLevel());
        assertTrue(result.getDetails().contains("screen_recording_active"));
        assertTrue(result.getDetails().contains("screen_capture_observed"));
        assertTrue(result.getEvidenceItems().stream()
                .anyMatch(e -> "screen_recording_active".equals(e.getCode())
                        && e.getRank() == EvidenceItem.Rank.STRONG));

        // RiskWindowGuard must be crash-free on null inputs
        RiskWindowGuard.enableScreenCaptureProtection(null, true);
        RiskWindowGuard.enableOverlayProtection(null, true);
        RiskWindowGuard.enableTouchObscuredFilter(null, true);
    }

    @Test
    public void virtualInputFilterExemptsXiaomiHardwareUinputDriversWhileCatchingRemoteTools() {
        // Stock Xiaomi 15 / Qualcomm under-display fingerprint & hardware uinput drivers must NOT trigger.
        assertFalse(ScreenAndFraudDetector.isVirtualInputCandidate(
                5, false, "uinput-goodix", android.view.InputDevice.SOURCE_KEYBOARD,
                android.view.InputDevice.KEYBOARD_TYPE_NON_ALPHABETIC));
        assertFalse(ScreenAndFraudDetector.isVirtualInputCandidate(
                6, true, "uinput-fpc", android.view.InputDevice.SOURCE_TOUCHSCREEN,
                android.view.InputDevice.KEYBOARD_TYPE_NONE));
        assertFalse(ScreenAndFraudDetector.isVirtualInputCandidate(
                7, false, "uinput-silead", android.view.InputDevice.SOURCE_KEYBOARD,
                android.view.InputDevice.KEYBOARD_TYPE_NONE));
        assertFalse(ScreenAndFraudDetector.isVirtualInputCandidate(
                8, false, "uhid-bluetooth-hid", android.view.InputDevice.SOURCE_KEYBOARD,
                android.view.InputDevice.KEYBOARD_TYPE_ALPHABETIC));
        assertFalse(ScreenAndFraudDetector.isVirtualInputCandidate(
                9, false, "uinput_sensor_key", android.view.InputDevice.SOURCE_KEYBOARD,
                android.view.InputDevice.KEYBOARD_TYPE_NON_ALPHABETIC));

        // Explicit remote-control tools and untrusted virtual touch injectors MUST still trigger.
        assertTrue(ScreenAndFraudDetector.isVirtualInputCandidate(
                10, false, "scrcpy_input", android.view.InputDevice.SOURCE_KEYBOARD,
                android.view.InputDevice.KEYBOARD_TYPE_NONE));
        assertTrue(ScreenAndFraudDetector.isVirtualInputCandidate(
                11, false, "uinput_touch", android.view.InputDevice.SOURCE_TOUCHSCREEN,
                android.view.InputDevice.KEYBOARD_TYPE_NONE));
        assertTrue(ScreenAndFraudDetector.isVirtualInputCandidate(
                12, true, "custom_remote_pad", android.view.InputDevice.SOURCE_MOUSE,
                android.view.InputDevice.KEYBOARD_TYPE_NONE));
    }
}
