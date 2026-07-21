package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.PrivacyUtils;

public class SettingsCollector extends BaseCollector {

    private static final String[] SECURE_KEYS = {
            "bluetooth_address",
            "android_id"
    };

    public SettingsCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "settings";
    }

    @Override
    protected void collect(CollectorResult result) {
        for (String key : SECURE_KEYS) {
            try {
                String value = Settings.Secure.getString(context.getContentResolver(), key);
                if (value != null) {
                    result.addValue("secure_" + key,
                            PrivacyUtils.hashIdentifier(context, value));
                }
            } catch (Exception e) {
                CLog.e("Settings.Secure." + key + " failed", e);
            }
        }

    }
}
