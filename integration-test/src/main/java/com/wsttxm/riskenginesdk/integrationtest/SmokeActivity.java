package com.wsttxm.riskenginesdk.integrationtest;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import com.wsttxm.riskenginesdk.PrivacyProfile;
import com.wsttxm.riskenginesdk.RiskEngine;
import com.wsttxm.riskenginesdk.RiskEngineConfig;

/** Compile/link smoke test for the standalone release AAR. */
public final class SmokeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.MINIMAL)
                .build();
        RiskEngine.initIfNeeded(this, config);
        TextView status = new TextView(this);
        status.setText(RiskEngine.isInitialized() ? "RiskEngine AAR loaded" : "Load failed");
        setContentView(status);
    }

    @Override
    protected void onDestroy() {
        if (isFinishing()) {
            RiskEngine.shutdown();
        }
        super.onDestroy();
    }
}
