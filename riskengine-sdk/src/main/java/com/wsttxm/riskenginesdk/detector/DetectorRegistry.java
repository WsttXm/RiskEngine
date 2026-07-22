package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DetectorRegistry {
    private final List<BaseDetector> detectors = new ArrayList<>();

    public DetectorRegistry(Context context, RiskEngineConfig config) {
        this(context, config, new SignalSnapshot(context));
    }

    public DetectorRegistry(Context context, RiskEngineConfig config, SignalSnapshot signals) {
        if (config.isEnableRoot()) {
            detectors.add(new RootDetector(context, signals));
            detectors.add(new MountAnalysisDetector(context, signals));
        }
        if (config.isEnableHookDetection()) {
            detectors.add(new HookFrameworkDetector(context, signals));
            detectors.add(new ProcessScanDetector(context, signals));
        }
        if (config.isEnableAdbDetection()) {
            detectors.add(new AdbDetector(context, signals));
        }
        if (config.isEnableEmulatorDetection()) {
            detectors.add(new EmulatorDetector(context, signals));
        }
        if (config.isEnableSandboxDetection()) {
            detectors.add(new SandboxDetector(context));
        }
        if (config.isEnableDebugDetection()) {
            detectors.add(new DebugDetector(context, signals));
        }
        if (config.isEnableCloudPhoneDetection()) {
            detectors.add(new CloudPhoneDetector(context));
        }
        if (config.isEnableCustomRomDetection()) {
            detectors.add(new CustomRomDetector(context, signals));
        }
    }

    public List<BaseDetector> getDetectors() {
        return Collections.unmodifiableList(detectors);
    }
}
