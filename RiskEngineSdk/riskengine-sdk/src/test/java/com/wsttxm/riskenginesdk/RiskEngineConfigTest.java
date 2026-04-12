package com.wsttxm.riskenginesdk;

import org.junit.Test;

import static org.junit.Assert.*;

public class RiskEngineConfigTest {

    @Test
    public void defaultConfigValues() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();
        assertNotNull(config);
    }

    @Test
    public void customConfigValues() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .debugLog(true)
                .collectTimeout(10000)
                .build();
        assertNotNull(config);
    }
}
