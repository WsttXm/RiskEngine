package com.wsttxm.riskenginesdk.collector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.java_layer.*;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;

import java.util.ArrayList;
import java.util.List;

public class CollectorRegistry {
    private final List<BaseCollector> collectors = new ArrayList<>();

    public CollectorRegistry(Context context) {
        // Java layer collectors
        collectors.add(new AndroidIdCollector(context));
        collectors.add(new BuildPropsCollector(context));
        collectors.add(new ScreenInfoCollector(context));
        collectors.add(new ApkSignatureCollector(context));
        collectors.add(new BluetoothMacCollector(context));
        collectors.add(new WifiInfoCollector(context));
        collectors.add(new TelephonyCollector(context));
        collectors.add(new SettingsCollector(context));
        collectors.add(new AdbStateCollector(context));
        collectors.add(new ContainerSignalCollector(context));

        // Native layer collectors (via JNI bridge)
        NativeCollectorBridge nativeBridge = new NativeCollectorBridge(context);
        collectors.add(nativeBridge.getDrmCollector());
        collectors.add(nativeBridge.getBootIdCollector());
        collectors.add(nativeBridge.getSystemPropertyCollector());
        collectors.add(nativeBridge.getCpuInfoCollector());
        collectors.add(nativeBridge.getDiskSizeCollector());
        collectors.add(nativeBridge.getMacNetlinkCollector());
        collectors.add(nativeBridge.getKernelInfoCollector());
    }

    public List<BaseCollector> getCollectors() {
        return collectors;
    }
}
