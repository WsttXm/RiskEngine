package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.content.pm.PackageManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;

/** Collects Wi-Fi hardware capabilities without connection or network metadata. */
public class WifiInfoCollector extends BaseCollector {

    public WifiInfoCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "wifi_info";
    }

    @Override
    protected void collect(CollectorResult result) {
        PackageManager manager = context.getPackageManager();
        result.addValue("supported", String.valueOf(
                manager.hasSystemFeature(PackageManager.FEATURE_WIFI)));
        result.addValue("wifi_direct_supported", String.valueOf(
                manager.hasSystemFeature(PackageManager.FEATURE_WIFI_DIRECT)));
    }
}
