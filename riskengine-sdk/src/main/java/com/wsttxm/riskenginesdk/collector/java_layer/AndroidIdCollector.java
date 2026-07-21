package com.wsttxm.riskenginesdk.collector.java_layer;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.PrivacyUtils;
import com.wsttxm.riskenginesdk.util.ShellExecutor;

public class AndroidIdCollector extends BaseCollector {

    public AndroidIdCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "android_id";
    }

    @Override
    protected boolean comparesSources() {
        return true;
    }

    @Override
    protected void collect(CollectorResult result) {
        collectViaSettingsApi(result);
        collectViaContentResolver(result);
        collectViaContentQuery(result);
    }

    @SuppressLint("HardwareIds")
    private void collectViaSettingsApi(CollectorResult result) {
        try {
            String androidId = Settings.Secure.getString(
                    context.getContentResolver(), Settings.Secure.ANDROID_ID);
            addHashed(result, "settings_api", androidId);
        } catch (Exception e) {
            CLog.e("AndroidId settings_api failed", e);
        }
    }

    private void collectViaContentResolver(CollectorResult result) {
        try {
            Bundle callResult = context.getContentResolver().call(
                    Uri.parse("content://settings/secure"),
                    "GET_secure",
                    "android_id",
                    new Bundle()
            );
            if (callResult != null) {
                String androidId = callResult.getString("value");
                addHashed(result, "content_resolver", androidId);
            }
        } catch (Exception e) {
            CLog.e("AndroidId content_resolver failed", e);
        }
    }

    private void collectViaContentQuery(CollectorResult result) {
        try {
            String raw = ShellExecutor.execute(
                    "content query --uri content://settings/secure --where \"name=\\'android_id\\'\"");
            if (raw != null && raw.contains("value=")) {
                int idx = raw.indexOf("value=");
                String value = raw.substring(idx + 6).trim();
                if (value.contains(",")) {
                    value = value.substring(0, value.indexOf(","));
                }
                addHashed(result, "content_query", value);
            }
        } catch (Exception e) {
            CLog.e("AndroidId content_query failed", e);
        }
    }

    private void addHashed(CollectorResult result, String source, String value) {
        String hashed = PrivacyUtils.hashIdentifier(context, value);
        if (!hashed.isEmpty()) {
            result.addValue(source, hashed);
        }
    }
}
