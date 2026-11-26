package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.detector.DetectorRegistry;

import org.junit.Test;

import static org.junit.Assert.*;

public class RiskEngineConfigTest {

    @Test
    public void defaultConfigValues() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();
        assertNotNull(config);
        assertTrue(config.isEnableRoot());
        assertTrue(config.isEnableHookDetection());
        assertEquals(10_000, config.getCollectTimeoutMs());
        assertEquals(PrivacyProfile.BALANCED, config.getPrivacyProfile());
        assertEquals(CollectScene.STANDARD, config.getCollectScene());
        assertTrue(config.isCollectAndroidId());
        assertFalse(config.isCollectBootId());
        assertFalse(config.isCollectDrmId());
        assertFalse(config.isEnableAntiDumpable());
        assertTrue(config.isEnablePeriodicMonitor());
    }

    @Test
    public void privacyProfilesAndOverridesAreResolvedAtBuildTime() {
        RiskEngineConfig minimal = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.MINIMAL)
                .build();
        assertFalse(minimal.isCollectAndroidId());
        assertFalse(minimal.isCollectBootId());
        assertFalse(minimal.isCollectDrmId());

        RiskEngineConfig diagnostic = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.DIAGNOSTIC)
                .collectDrmId(false)
                .build();
        assertTrue(diagnostic.isCollectAndroidId());
        assertTrue(diagnostic.isCollectBootId());
        assertFalse(diagnostic.isCollectDrmId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsNullPrivacyProfile() {
        new RiskEngineConfig.Builder().privacyProfile(null);
    }

    @Test
    public void customConfigValues() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .debugLog(true)
                .enableRoot(false)
                .enableAdbDetection(false)
                .enableAntiDumpable(true)
                .enablePeriodicMonitor(false)
                .collectTimeout(1234)
                .build();
        assertTrue(config.isDebugLog());
        assertFalse(config.isEnableRoot());
        assertFalse(config.isEnableAdbDetection());
        assertTrue(config.isEnableAntiDumpable());
        assertFalse(config.isEnablePeriodicMonitor());
        assertEquals(1234, config.getCollectTimeoutMs());
    }

    @Test
    public void buildCreatesImmutableSnapshot() {
        RiskEngineConfig.Builder builder = new RiskEngineConfig.Builder().collectTimeout(1000);
        RiskEngineConfig first = builder.build();
        RiskEngineConfig second = builder.collectTimeout(2000).build();

        assertEquals(1000, first.getCollectTimeoutMs());
        assertEquals(2000, second.getCollectTimeoutMs());
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsNonPositiveTimeout() {
        new RiskEngineConfig.Builder().collectTimeout(0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsTimeoutThatCanOutliveACollectionRequest() {
        new RiskEngineConfig.Builder().collectTimeout(Long.MAX_VALUE);
    }

    @Test
    public void disabledDetectorsAreNotRegistered() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .enableRoot(false)
                .enableHookDetection(false)
                .enableAdbDetection(false)
                .enableEmulatorDetection(false)
                .enableDebugDetection(false)
                .enableCloudPhoneDetection(false)
                .enableCustomRomDetection(false)
                .enableAppIntegrityDetection(false)
                .enableMultiInstanceDetection(false)
                .enableNetworkRiskDetection(false)
                .enableLocationRiskDetection(false)
                .enableScreenAndFraudDetection(false)
                .enableTeeAttestation(false)
                .enableThreatAppDetection(false)
                .build();

        DetectorRegistry registry = new DetectorRegistry(null, config);
        assertEquals(1, registry.getDetectors().size());
        assertEquals("consistency", registry.getDetectors().get(0).getName());

        DetectorRegistry defaultRegistry =
                new DetectorRegistry(null, new RiskEngineConfig.Builder().build());
        assertEquals(16, defaultRegistry.getDetectors().size());
    }
}
