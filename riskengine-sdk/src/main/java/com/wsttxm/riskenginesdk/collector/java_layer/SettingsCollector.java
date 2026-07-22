package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

public class SettingsCollector extends BaseCollector {

    public SettingsCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "settings";
    }

    @Override
    protected void collect(CollectorResult result) {
        try {
            int development = Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
            result.addValue("development_settings_enabled", String.valueOf(development == 1));
        } catch (Exception e) {
            CLog.e("Development settings collection failed", e);
        }
    }
}
