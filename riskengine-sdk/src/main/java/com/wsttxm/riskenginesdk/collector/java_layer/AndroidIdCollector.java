package com.wsttxm.riskenginesdk.collector.java_layer;

import android.annotation.SuppressLint;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.PrivacyUtils;

public class AndroidIdCollector extends BaseCollector {
    private static final String SECURE_URI_STRING = "content://settings/secure";

    public AndroidIdCollector(Context context) {
        this(context, null);
    }

    public AndroidIdCollector(Context context, SignalSnapshot signals) {
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
        collectViaProviderQuery(result);
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
                    Uri.parse(SECURE_URI_STRING),
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

    /**
     * In-process ContentResolver query without forking /system/bin/sh.
     */
    private void collectViaProviderQuery(CollectorResult result) {
        try (Cursor cursor = context.getContentResolver().query(
                Uri.parse(SECURE_URI_STRING),
                new String[]{"value"},
                "name=?",
                new String[]{"android_id"},
                null)) {
            if (cursor != null && cursor.moveToFirst()) {
                String value = cursor.getString(0);
                if (value != null && !"null".equalsIgnoreCase(value.trim())) {
                    addHashed(result, "provider_query", value.trim());
                }
            }
        } catch (Exception e) {
            CLog.e("AndroidId provider_query failed", e);
        }
    }

    private void addHashed(CollectorResult result, String source, String value) {
        String hashed = PrivacyUtils.hashIdentifier(context, value);
        if (!hashed.isEmpty()) {
            result.addValue(source, hashed);
        }
    }
}
