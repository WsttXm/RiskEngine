package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.detector.LocationRiskDetector;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class LocationRiskDetectorTest {

    private static class InMemoryLocationAdapter implements LocationRiskDetector.LocationCanaryAdapter {
        boolean functional = true;
        boolean supportsSetMock = true;
        double lat;
        double lon;
        double alt;
        boolean hasAlt;
        float acc;
        boolean hasAcc;
        long time;
        boolean mock;

        @Override public boolean isFunctionalRuntime() { return functional; }
        @Override public void setLatitude(double lat) { this.lat = lat; }
        @Override public double getLatitude() { return lat; }
        @Override public void setLongitude(double lon) { this.lon = lon; }
        @Override public double getLongitude() { return lon; }
        @Override public void setAltitude(double alt) { this.alt = alt; this.hasAlt = true; }
        @Override public double getAltitude() { return alt; }
        @Override public boolean hasAltitude() { return hasAlt; }
        @Override public void setAccuracy(float acc) { this.acc = acc; this.hasAcc = true; }
        @Override public float getAccuracy() { return acc; }
        @Override public boolean hasAccuracy() { return hasAcc; }
        @Override public void setTime(long timeMs) { this.time = timeMs; }
        @Override public long getTime() { return time; }
        @Override public void reset() {
            lat = 0.0;
            lon = 0.0;
            alt = 0.0;
            hasAlt = false;
            acc = 0.0f;
            hasAcc = false;
            time = 0L;
            mock = false;
        }
        @Override public boolean supportsSetMock() { return supportsSetMock; }
        @Override public void setMock(boolean mock) { this.mock = mock; }
        @Override public boolean isMock() { return mock; }
    }

    private static final class FakeLocationEnv implements LocationRiskDetector.LocationEnvironment {
        LocationRiskDetector.LocationCanaryAdapter adapter = new InMemoryLocationAdapter();
        List<String> mockProviders = null; // null simulates missing location permissions
        Boolean mockAppOpAllowed = null;

        @Override public LocationRiskDetector.LocationCanaryAdapter createCanaryAdapter() {
            return adapter;
        }
        @Override public List<String> findMockCachedLocationProviders() { return mockProviders; }
        @Override public Boolean isMockLocationAppOpAllowed() { return mockAppOpAllowed; }
    }

    @Test
    public void pureJvmAndroidJarDefaultStubDoesNotFalsePositive() {
        DetectionResult result = new LocationRiskDetector(null).call();
        assertEquals("location_risk", result.getDetectorName());
        assertEquals(ScanTier.FAST, result.getScanTier());
        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(0, result.getScore());
        assertTrue(result.getDetails().isEmpty());
    }

    @Test
    public void cleanCanaryWithoutLocationPermissionIsSafe() {
        FakeLocationEnv env = new FakeLocationEnv();
        DetectionResult result = LocationRiskDetector.createForTest(null, env).call();

        assertEquals(RiskLevel.SAFE, result.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, result.getStatus());
        assertEquals(0, result.getScore());
        assertTrue(result.getDetails().isEmpty());
        assertTrue(result.getEvidenceItems().isEmpty());
    }

    @Test
    public void hookedGetterReturningFixedCoordinatesTriggersHigh7ActionableInAllScenes() {
        FakeLocationEnv env = new FakeLocationEnv();
        env.adapter = new InMemoryLocationAdapter() {
            @Override public double getLatitude() { return 37.7749; } // coarse Xposed getter hook
        };

        DetectionResult raw = LocationRiskDetector.createForTest(null, env).call();
        assertEquals(RiskLevel.HIGH, raw.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, raw.getStatus());
        assertEquals(7, raw.getScore());
        assertFalse(raw.isInformational());
        assertTrue(raw.getDetails().contains("location_canary_tamper:lat_lon_roundtrip_a"));
        assertTrue(raw.getEvidenceItems().stream()
                .anyMatch(e -> "location_canary_tamper".equals(e.getCode())
                        && "location_spoof".equals(e.getEvidenceFamily())
                        && e.getRank() == EvidenceItem.Rank.STRONG));

        // Never leaks coordinates into details or evidence
        assertFalse(raw.getEvidence().contains("37.7749"));
        assertFalse(raw.getEvidence().contains("12.345678"));

        DetectionResult standard = CorrelationEngine.applyScene(raw, CollectScene.STANDARD);
        assertFalse(standard.isInformational());
        assertEquals(7, standard.getScore());
    }

    @Test
    public void hookedResetAndIsMockSuppressorTriggerHigh7Actionable() {
        FakeLocationEnv resetEnv = new FakeLocationEnv();
        resetEnv.adapter = new InMemoryLocationAdapter() {
            @Override public void reset() {
                // Broken reset leaving mFieldsMask/hasAltitude dirty
            }
        };
        DetectionResult resetRes = LocationRiskDetector.createForTest(null, resetEnv).call();
        assertEquals(RiskLevel.HIGH, resetRes.getRiskLevel());
        assertEquals(7, resetRes.getScore());
        assertTrue(resetRes.getDetails().contains("location_canary_tamper:reset_fields_mask"));

        FakeLocationEnv mockHookEnv = new FakeLocationEnv();
        mockHookEnv.adapter = new InMemoryLocationAdapter() {
            @Override public boolean isMock() { return false; } // hook forcing isMock()==false
        };
        DetectionResult mockHookRes = LocationRiskDetector.createForTest(null, mockHookEnv).call();
        assertEquals(RiskLevel.HIGH, mockHookRes.getRiskLevel());
        assertEquals(7, mockHookRes.getScore());
        assertTrue(mockHookRes.getDetails().contains("location_canary_tamper:set_mock_roundtrip"));
    }

    @Test
    public void cachedMockLocationAndAppOpAreMedium4ActionableInLoginAndPaymentWithoutCoordinates() {
        FakeLocationEnv env = new FakeLocationEnv();
        env.mockProviders = Collections.singletonList("gps");
        env.mockAppOpAllowed = Boolean.TRUE;

        DetectionResult raw = LocationRiskDetector.createForTest(null, env).call();
        assertEquals(RiskLevel.MEDIUM, raw.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, raw.getStatus());
        assertEquals(4, raw.getScore());
        assertTrue(raw.isInformational());
        assertTrue(raw.getDetails().contains("cached_location_mock:gps"));
        assertTrue(raw.getDetails().contains("mock_location_appop_allowed"));

        Set<String> families = EvidenceFamily.families(raw.getDetails(), raw.getEvidenceItems());
        assertEquals(Collections.singleton("location_spoof"), families);

        DetectionResult standard = CorrelationEngine.applyScene(raw, CollectScene.STANDARD);
        assertTrue(standard.isInformational());

        DetectionResult login = CorrelationEngine.applyScene(raw, CollectScene.LOGIN);
        assertFalse(login.isInformational());
        assertEquals(4, login.getScore());

        DetectionResult payment = CorrelationEngine.applyScene(raw, CollectScene.PAYMENT);
        assertFalse(payment.isInformational());
        assertEquals(4, payment.getScore());
    }
}
