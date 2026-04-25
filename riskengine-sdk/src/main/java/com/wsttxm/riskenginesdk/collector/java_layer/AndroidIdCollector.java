package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.ArrayMap;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ShellExecutor;

import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.lang.reflect.Field;

public class AndroidIdCollector extends BaseCollector {

    public AndroidIdCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "android_id";
    }

    @Override
    protected void collect(CollectorResult result) {
        collectViaSettingsApi(result);
        collectViaNameValueCache(result);
        collectViaContentResolver(result);
        collectViaContentQuery(result);
    }

    private void collectViaSettingsApi(CollectorResult result) {
        try {
            String androidId = Settings.Secure.getString(
                    context.getContentResolver(), Settings.Secure.ANDROID_ID);
            result.addValue("settings_api", androidId);
        } catch (Exception e) {
            CLog.e("AndroidId settings_api failed", e);
        }
    }

    @SuppressWarnings("unchecked")
    private void collectViaNameValueCache(CollectorResult result) {
        try {
            HiddenApiBypass.addHiddenApiExemptions("");
            Field sNameValueCache = Settings.Secure.class.getDeclaredField("sNameValueCache");
            sNameValueCache.setAccessible(true);
            Object cacheObj = sNameValueCache.get(null);
            if (cacheObj != null) {
                Field fieldmValues = cacheObj.getClass().getDeclaredField("mValues");
                fieldmValues.setAccessible(true);
                Object valuesObj = fieldmValues.get(cacheObj);
                if (valuesObj instanceof ArrayMap) {
                    ArrayMap<String, String> mValues = (ArrayMap<String, String>) valuesObj;
                    String androidId = mValues.get("android_id");
                    result.addValue("name_value_cache", androidId);
                }
            }
        } catch (Exception e) {
            CLog.e("AndroidId name_value_cache failed", e);
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
                result.addValue("content_resolver", androidId);
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
                result.addValue("content_query", value);
            }
        } catch (Exception e) {
            CLog.e("AndroidId content_query failed", e);
        }
    }
}
