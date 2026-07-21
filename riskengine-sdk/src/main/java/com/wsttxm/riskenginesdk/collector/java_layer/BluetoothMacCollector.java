package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.content.pm.PackageManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;

/** Collects non-sensitive Bluetooth capability information; local MAC is inaccessible to apps. */
public class BluetoothMacCollector extends BaseCollector {
    public BluetoothMacCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "bluetooth_info";
    }

    @Override
    protected void collect(CollectorResult result) {
        PackageManager manager = context.getPackageManager();
        result.addValue("supported", String.valueOf(
                manager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)));
        result.addValue("low_energy_supported", String.valueOf(
                manager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)));
    }
}
