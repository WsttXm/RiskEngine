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
            detectors.add(new MountAnalysisDetector(
                    context, signals, config.isEnableIsolatedProcessProbe()));
        }
        if (config.isEnableHookDetection()) {
            detectors.add(new HookFrameworkDetector(context, signals));
        }
        if (config.isEnableAdbDetection()) {
            detectors.add(new AdbDetector(context, signals));
        }
        if (config.isEnableEmulatorDetection()) {
            detectors.add(new EmulatorDetector(context, signals));
        }
        if (config.isEnableDebugDetection()) {
            detectors.add(new DebugDetector(context, signals));
        }
        if (config.isEnableCloudPhoneDetection()) {
            detectors.add(new CloudPhoneDetector(context, signals));
        }
        if (config.isEnableCustomRomDetection()) {
            detectors.add(new CustomRomDetector(context, signals));
        }
        if (config.isEnableAppIntegrityDetection()) {
            detectors.add(new AppIntegrityDetector(context, config, signals));
        }
        if (config.isEnableMultiInstanceDetection()) {
            detectors.add(new MultiInstanceDetector(context, signals));
        }
        if (config.isEnableNetworkRiskDetection()) {
            detectors.add(new NetworkRiskDetector(context, signals));
        }
        if (config.isEnableLocationRiskDetection()) {
            detectors.add(new LocationRiskDetector(context));
        }
        if (config.isEnableScreenAndFraudDetection()) {
            detectors.add(new ScreenAndFraudDetector(context));
        }
        if (config.isEnableTeeAttestation()) {
            detectors.add(new TeeIntegrityDetector(context, config, signals));
        }
        if (config.isEnableThreatAppDetection()) {
            detectors.add(new ThreatAppDetector(context, config));
        }
        // Signature-free checks: these find contradictions rather than known
        // artifacts, so they do not go stale as tools are renamed.
        detectors.add(new ConsistencyDetector(
                context, signals, null, config.isEnableTeeAttestation()));
    }

    public List<BaseDetector> getDetectors() {
        return Collections.unmodifiableList(detectors);
    }

    /** Returns detectors that declare deferred Stage 3 probes via {@link BaseDetector#hasPostponedProbes()}. */
    public List<BaseDetector> getPostponedProbeDetectors() {
        List<BaseDetector> postponed = new ArrayList<>();
        for (BaseDetector detector : detectors) {
            if (detector != null && detector.hasPostponedProbes()) {
                postponed.add(detector);
            }
        }
        return Collections.unmodifiableList(postponed);
    }
}
