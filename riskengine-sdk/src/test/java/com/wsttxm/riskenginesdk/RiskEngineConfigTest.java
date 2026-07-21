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
    }

    @Test
    public void customConfigValues() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .debugLog(true)
                .enableRoot(false)
                .enableAdbDetection(false)
                .collectTimeout(1234)
                .build();
        assertTrue(config.isDebugLog());
        assertFalse(config.isEnableRoot());
        assertFalse(config.isEnableAdbDetection());
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
                .enableSandboxDetection(false)
                .enableDebugDetection(false)
                .enableCloudPhoneDetection(false)
                .enableCustomRomDetection(false)
                .build();

        assertTrue(new DetectorRegistry(null, config).getDetectors().isEmpty());
    }
}
