package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.RiskEngineConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DetectorRegistry {
    private final List<BaseDetector> detectors = new ArrayList<>();

    public DetectorRegistry(Context context, RiskEngineConfig config) {
        if (config.isEnableRoot()) {
            detectors.add(new RootDetector(context));
            detectors.add(new MountAnalysisDetector(context));
        }
        if (config.isEnableHookDetection()) {
            detectors.add(new HookFrameworkDetector(context));
            detectors.add(new ProcessScanDetector(context));
        }
        if (config.isEnableAdbDetection()) {
            detectors.add(new AdbDetector(context));
        }
        if (config.isEnableEmulatorDetection()) {
            detectors.add(new EmulatorDetector(context));
        }
        if (config.isEnableSandboxDetection()) {
            detectors.add(new SandboxDetector(context));
        }
        if (config.isEnableDebugDetection()) {
            detectors.add(new DebugDetector(context));
        }
        if (config.isEnableCloudPhoneDetection()) {
            detectors.add(new CloudPhoneDetector(context));
        }
        if (config.isEnableCustomRomDetection()) {
            detectors.add(new CustomRomDetector(context));
        }
    }

    public List<BaseDetector> getDetectors() {
        return Collections.unmodifiableList(detectors);
    }
}
