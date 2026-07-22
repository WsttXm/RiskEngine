package com.wsttxm.riskenginesdk.collector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.java_layer.*;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CollectorRegistry {
    private final List<BaseCollector> collectors = new ArrayList<>();

    public CollectorRegistry(Context context) {
        this(context, new RiskEngineConfig.Builder().build(), new SignalSnapshot(context));
    }

    public CollectorRegistry(Context context, RiskEngineConfig config) {
        this(context, config, new SignalSnapshot(context));
    }

    public CollectorRegistry(Context context, RiskEngineConfig config, SignalSnapshot signals) {
        // Java layer collectors
        if (config.isCollectAndroidId()) {
            collectors.add(new AndroidIdCollector(context, signals));
        }
        collectors.add(new BuildPropsCollector(context));
        collectors.add(new ScreenInfoCollector(context));
        collectors.add(new ApkSignatureCollector(context));
        collectors.add(new BluetoothCapabilityCollector(context));
        collectors.add(new WifiInfoCollector(context));
        collectors.add(new TelephonyCollector(context));
        collectors.add(new SettingsCollector(context));
        collectors.add(new AdbStateCollector(context, signals));
        collectors.add(new ContainerSignalCollector(context, signals));

        // Native layer collectors (via JNI bridge)
        NativeCollectorBridge nativeBridge = new NativeCollectorBridge(context, signals);
        if (config.isCollectDrmId()) {
            collectors.add(nativeBridge.getDrmCollector());
        }
        if (config.isCollectBootId()) {
            collectors.add(nativeBridge.getBootIdCollector());
        }
        collectors.add(nativeBridge.getSystemPropertyCollector());
        collectors.add(nativeBridge.getCpuInfoCollector());
        collectors.add(nativeBridge.getDiskSizeCollector());
        collectors.add(nativeBridge.getKernelInfoCollector());
    }

    public List<BaseCollector> getCollectors() {
        return Collections.unmodifiableList(collectors);
    }
}
