package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import java.util.ArrayList;
import java.util.List;

public class DetectorRegistry {
    private final List<BaseDetector> detectors = new ArrayList<>();

    public DetectorRegistry(Context context) {
        detectors.add(new RootDetector(context));
        detectors.add(new HookFrameworkDetector(context));
        detectors.add(new MethodIntegrityDetector(context));
        detectors.add(new AdbDetector(context));
        detectors.add(new EmulatorDetector(context));
        detectors.add(new SandboxDetector(context));
        detectors.add(new DebugDetector(context));
        detectors.add(new CloudPhoneDetector(context));
        detectors.add(new CustomRomDetector(context));
        detectors.add(new ProcessScanDetector(context));
        detectors.add(new MountAnalysisDetector(context));
    }

    public List<BaseDetector> getDetectors() {
        return detectors;
    }
}
