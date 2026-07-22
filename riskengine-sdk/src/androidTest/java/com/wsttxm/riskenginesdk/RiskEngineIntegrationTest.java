package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.os.Build;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskReport;

import java.util.Locale;

@RunWith(AndroidJUnit4.class)
public class RiskEngineIntegrationTest {

    @Test
    public void sdkInitializesAndCollectsSuccessfully() {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        assertNotNull(context);
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.MINIMAL)
                .collectTimeout(15_000)
                .build();
        try {
            RiskEngine.init(context, config);
            assertTrue(RiskEngine.isInitialized());
            RiskReport report = RiskEngine.collectSync();
            assertNotNull(report);
            assertFalse(report.getDetections().isEmpty());
            assertTrue(report.getCheckCount() > 0);

            String fingerprint = Build.FINGERPRINT.toLowerCase(Locale.ROOT);
            if (fingerprint.contains("generic") || fingerprint.contains("emulator")) {
                DetectionResult emulator = null;
                for (DetectionResult result : report.getDetections()) {
                    if ("emulator".equals(result.getDetectorName())) {
                        emulator = result;
                        break;
                    }
                }
                assertNotNull("emulator detector must be registered", emulator);
                assertNotEquals("emulator should provide a natural positive signal",
                        DetectionStatus.NORMAL, emulator.getStatus());
            }
        } finally {
            RiskEngine.shutdown();
        }
    }
}
