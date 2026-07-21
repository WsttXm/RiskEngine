package com.wsttxm.riskenginesdk;

import android.content.Context;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class RiskEngineIntegrationTest {

    @Test
    public void sdkInitializesAndCollectsSuccessfully() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        assertNotNull(context);
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .enableRoot(false)
                .enableHookDetection(false)
                .enableAdbDetection(false)
                .enableEmulatorDetection(false)
                .enableSandboxDetection(false)
                .enableDebugDetection(false)
                .enableCloudPhoneDetection(false)
                .enableCustomRomDetection(false)
                .collectTimeout(5_000)
                .build();
        try {
            RiskEngine.init(context, config);
            assertTrue(RiskEngine.isInitialized());
            assertNotNull(RiskEngine.collectSync());
        } finally {
            RiskEngine.shutdown();
        }
    }
}
