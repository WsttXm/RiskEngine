package com.wsttxm.riskenginesdk.collector.java_layer;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ReflectionUtils;

public class BluetoothMacCollector extends BaseCollector {

    public BluetoothMacCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "bluetooth_mac";
    }

    @Override
    protected void collect(CollectorResult result) {
        try {
            BluetoothManager bm = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
            if (bm != null) {
                BluetoothAdapter adapter = bm.getAdapter();
                if (adapter != null) {
                    // getAddress() returns 02:00:00:00:00:00 on Android 6+, use reflection
                    Object address = ReflectionUtils.invokeMethod(adapter, "getAddress", new Class[0]);
                    if (address instanceof String) {
                        result.addValue("reflection", (String) address);
                    }
                }
            }
        } catch (Exception e) {
            CLog.e("BluetoothMac failed", e);
        }
    }
}
