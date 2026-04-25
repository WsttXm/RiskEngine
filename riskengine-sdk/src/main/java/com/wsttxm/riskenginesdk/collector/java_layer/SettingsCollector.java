package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

public class SettingsCollector extends BaseCollector {

    private static final String[] SECURE_KEYS = {
            "bluetooth_address",
            "android_id"
    };

    private static final String[] GLOBAL_KEYS = {
            "device_name",
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
                    result.addValue("secure_" + key, value);
                }
            } catch (Exception e) {
                CLog.e("Settings.Secure." + key + " failed", e);
            }
        }

        for (String key : GLOBAL_KEYS) {
            try {
                String value = Settings.Global.getString(context.getContentResolver(), key);
                if (value != null) {
                    result.addValue("global_" + key, value);
                }
            } catch (Exception e) {
                CLog.e("Settings.Global." + key + " failed", e);
            }
        }
    }
}
