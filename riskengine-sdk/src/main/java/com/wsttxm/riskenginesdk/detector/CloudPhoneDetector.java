package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraManager;
import android.os.BatteryManager;

import com.wsttxm.riskenginesdk.collector.java_layer.MediaCodecCollector;
import com.wsttxm.riskenginesdk.core.GpuClassifier;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.virtualization.SensorNoiseProbe;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class CloudPhoneDetector extends BaseDetector {
    /** Shared with {@link EmulatorDetector} so CorrelationEngine deduplicates overlapping hits. */
    public static final String EVIDENCE_FAMILY = "emulator";

    private final SignalSnapshot signals;
    private final SensorNoiseProbe.SensorFrameSampler sensorNoiseSampler;

    public CloudPhoneDetector(Context context) {
        this(context, new SignalSnapshot(context), null);
    }

    public CloudPhoneDetector(Context context, SignalSnapshot signals) {
        this(context, signals, null);
    }

    public CloudPhoneDetector(Context context,
                              SignalSnapshot signals,
                              SensorNoiseProbe.SensorFrameSampler sensorNoiseSampler) {
        super(context);
        this.signals = signals != null ? signals : new SignalSnapshot(context);
        this.sensorNoiseSampler = sensorNoiseSampler;
    }

    @Override
    public String getName() {
        return "cloud_phone";
    }

    @Override
    public boolean hasPostponedProbes() {
        return true;
    }

    @Override
    protected DetectionResult detect() {
        List<String> strong = new ArrayList<>();
        List<String> weak = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        if (checkPackages(strong)) coverage.success();
        else coverage.failure("packages_unavailable");
        checkCloudProperties(strong, coverage);
        checkVirtualGpu(strong, coverage);
        // Wired ethN can legitimately appear on USB-C docks, tablets, and ChromeOS;
        // treat as a weak corroborating signal rather than standalone HIGH danger.
        checkWiredInterface(weak, coverage);
        if (checkBatteryAnomaly(weak)) coverage.success();
        else coverage.failure("battery_unavailable");
        if (checkCameraCount(weak)) coverage.success();
        else coverage.failure("camera_unavailable");
        if (checkSensorCount(weak)) coverage.success();
        else coverage.failure("sensors_unavailable");
        checkZeroHardwareMediaCodec(weak, coverage);

        List<String> evidence = new ArrayList<>(strong);
        evidence.addAll(weak);
        List<EvidenceItem> items = buildEvidenceItems(strong, weak);

        DetectionResult res;
        if (!strong.isEmpty()) {
            // A virtualized GPU or a cloud vendor property is definitive
            // enough to rank higher than the old package-only signal did.
            res = result(RiskLevel.HIGH, DetectionStatus.DANGER, 7, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        } else if (weak.size() >= 2) {
            res = result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        } else if (!weak.isEmpty()) {
            res = result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        } else {
            res = safe(coverage);
        }
        return items.isEmpty() ? res : res.withEvidenceItems(items);
    }

    @Override
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        DetectionResult base = priorResult != null ? priorResult : call();
        if (base == null) {
            return null;
        }

        // Anti-FP red line: static sensor zero-variance MUST ONLY corroborate an existing
        // battery/camera/hardware/cloud anomaly — never trigger standalone actionable risk.
        if (base.getDetails().isEmpty()) {
            return base;
        }

        SensorNoiseProbe.Result noise = SensorNoiseProbe.sample(
                context, SensorNoiseProbe.DEFAULT_WINDOW_MS, sensorNoiseSampler);
        if (noise == null || !noise.isAvailable() || !noise.isStaticZeroVariance()) {
            return base;
        }

        String token = "sensor_static_zero_var:" + noise.getSensorType() + ":" + noise.getFrameCount();
        if (base.getDetails().contains(token)) {
            return base;
        }

        List<String> strong = new ArrayList<>();
        List<String> weak = new ArrayList<>();
        for (String existing : base.getDetails()) {
            if (isStrongCloudToken(existing)) {
                strong.add(existing);
            } else {
                weak.add(existing);
            }
        }
        weak.add(token);

        List<String> merged = new ArrayList<>(strong);
        merged.addAll(weak);
        List<EvidenceItem> items = buildEvidenceItems(strong, weak);

        RiskLevel level;
        DetectionStatus status;
        int score;
        boolean informational;
        if (!strong.isEmpty()) {
            level = RiskLevel.HIGH;
            status = DetectionStatus.DANGER;
            score = 7;
            informational = false;
        } else if (weak.size() >= 2) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = 4;
            informational = false;
        } else {
            level = RiskLevel.LOW;
            status = DetectionStatus.WARNING;
            score = 1;
            informational = true;
        }

        int attempted = base.getChecksAttempted() + 1;
        int succeeded = base.getChecksSucceeded() + 1;
        int failed = base.getChecksFailed();
        DetectionExecutionStatus execStatus = failed > 0
                ? DetectionExecutionStatus.PARTIAL
                : DetectionExecutionStatus.RISK;

        return new DetectionResult(
                getName(),
                level,
                status,
                score,
                10,
                informational,
                execStatus,
                attempted,
                succeeded,
                failed,
                base.getFailureReasons(),
                merged,
                String.join("; ", merged)
        ).withEvidenceItems(items).withScanTier(getScanTier());
    }

    /** Corroborates zero-SoC-hardware MediaCodec (c2.android.* / OMX.google.* software only). */
    private void checkZeroHardwareMediaCodec(List<String> weak, CheckCoverage coverage) {
        try {
            SignalResult<MediaCodecCollector.CodecSummary> codecs = signals.getMediaCodecSummary();
            if (codecs == null || codecs.getStatus() == SignalResult.Status.UNAVAILABLE) {
                return;
            }
            if (!codecs.isSuccess() || codecs.getValue() == null) {
                coverage.failure("media_codec:" + codecs.getFailureReason());
                return;
            }
            coverage.success();
            MediaCodecCollector.CodecSummary summary = codecs.getValue();
            if (summary.isZeroHardwareOnly()) {
                weak.add("zero_hw_codec:sw=" + summary.swAndroidGoogleCount + ",hw=0");
            }
        } catch (Exception | LinkageError e) {
            CLog.e("MediaCodec check failed", e);
        }
    }

    /** Cloud vendors leave their own properties set; presence alone is enough. */
    private void checkCloudProperties(List<String> evidence, CheckCoverage coverage) {
        int readable = 0;
        for (String property : DetectionLists.CLOUD_PHONE_PROPERTIES) {
            SignalResult<String> value = signals.getSystemProperty(property);
            if (!value.isSuccess()) continue;
            readable++;
            if (value.getValue() != null && !value.getValue().isBlank()) {
                evidence.add("cloud_prop:" + property + "=" + value.getValue().trim());
            }
        }
        if (readable > 0) coverage.success();
        else coverage.failure("cloud_properties_unavailable");
    }

    /**
     * A virtualized GPU renderer is the strongest available cloud-phone signal.
     * Physical handsets report Adreno, Mali, PowerVR or Xclipse; hosted
     * instances report virgl, virtio, SwiftShader or llvmpipe.
     */
    private void checkVirtualGpu(List<String> evidence, CheckCoverage coverage) {
        SignalResult<SignalSnapshot.GpuIdentity> gpu = signals.getGpuIdentity();
        if (!gpu.isSuccess() || gpu.getValue() == null) {
            coverage.failure("gpu_identity:" + gpu.getFailureReason());
            return;
        }
        coverage.success();
        SignalSnapshot.GpuIdentity identity = gpu.getValue();
        String marker = GpuClassifier.matchVirtualMarker(identity.vendor, identity.renderer);
        if (marker != null) {
            evidence.add("virtual_gpu:" + marker + ":" + identity.renderer);
        }
    }

    /**
     * Hosted Android instances expose ethernet rather than only wlan. A
     * handset-shaped device has wlan and no ethN interface.
     */
    private void checkWiredInterface(List<String> evidence, CheckCoverage coverage) {
        SignalResult<List<String>> interfaces = signals.getNetworkInterfaceNames();
        if (!interfaces.isSuccess() || interfaces.getValue() == null
                || interfaces.getValue().isEmpty()) {
            String reason = interfaces.getFailureReason();
            if ("internet_permission_missing".equals(reason)
                    || "net_iface_unavailable".equals(reason)) {
                // Zero-permission host apps may be unable to enumerate network interfaces;
                // treat as cleanly skipped rather than a runtime coverage failure.
                coverage.success();
                return;
            }
            coverage.failure("net_iface:" + interfaces.getFailureReason());
            return;
        }
        coverage.success();
        for (String name : interfaces.getValue()) {
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.length() > 3 && lower.startsWith("eth")
                    && Character.isDigit(lower.charAt(3))) {
                evidence.add("wired_interface:" + lower);
                return;
            }
        }
    }

    private boolean checkPackages(List<String> evidence) {
        try {
            PackageManager pm = context.getPackageManager();
            for (String pkg : DetectionLists.CLOUD_PACKAGES) {
                try {
                    pm.getPackageInfo(pkg, 0);
                    evidence.add("cloud_pkg:" + pkg);
                } catch (PackageManager.NameNotFoundException ignored) {}
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkBatteryAnomaly(List<String> evidence) {
        try {
            IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent battery = context.registerReceiver(null, filter);
            if (battery == null) {
                return false;
            }
            int voltage = battery.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1);
            int temperature = battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);
            if (voltage == 0 || temperature == 0) {
                evidence.add("battery_zero:v=" + voltage + ",t=" + temperature);
            }
            int status = battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
            int level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            if (level == 100 && status == BatteryManager.BATTERY_STATUS_CHARGING) {
                int plugged = battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
                if (plugged == 0) {
                    evidence.add("battery_anomaly:100%_charging_no_plug");
                }
            }
            return true;
        } catch (Exception e) {
            CLog.e("Battery check failed", e);
            return false;
        }
    }

    private boolean checkCameraCount(List<String> evidence) {
        try {
            PackageManager pm = context.getPackageManager();
            if (pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
                return true;
            }
            CameraManager cm = (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
            if (cm == null) {
                evidence.add("low_camera_count:0");
                return true;
            }
            String[] cameras = cm.getCameraIdList();
            if (cameras.length == 0) {
                evidence.add("low_camera_count:0");
            }
            return true;
        } catch (Exception e) {
            CLog.e("Camera check failed", e);
            return false;
        }
    }

    private boolean checkSensorCount(List<String> evidence) {
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) {
                evidence.add("very_low_sensor_count:0");
                return true;
            }
            int physical = 0;
            for (Sensor sensor : sm.getSensorList(Sensor.TYPE_ALL)) {
                if (sensor.getType() == Sensor.TYPE_SIGNIFICANT_MOTION
                        || sensor.getType() == Sensor.TYPE_STEP_DETECTOR
                        || sensor.getType() == Sensor.TYPE_STEP_COUNTER) {
                    continue;
                }
                physical++;
            }
            if (physical < 2) {
                evidence.add("very_low_sensor_count:" + physical);
            }
            return true;
        } catch (Exception e) {
            CLog.e("Sensor count check failed", e);
            return false;
        }
    }

    private static boolean isStrongCloudToken(String token) {
        if (token == null) return false;
        String lower = token.toLowerCase(Locale.ROOT);
        return lower.startsWith("cloud_pkg:")
                || lower.startsWith("cloud_prop:")
                || lower.startsWith("virtual_gpu:");
    }

    private static List<EvidenceItem> buildEvidenceItems(List<String> strong, List<String> weak) {
        Map<String, EvidenceItem> byKey = new LinkedHashMap<>();
        addTokens(byKey, strong, EvidenceItem.Rank.STRONG);
        addTokens(byKey, weak, EvidenceItem.Rank.WEAK);
        return byKey.isEmpty() ? Collections.emptyList() : new ArrayList<>(byKey.values());
    }

    private static void addTokens(Map<String, EvidenceItem> byKey,
                                  List<String> tokens,
                                  EvidenceItem.Rank rank) {
        if (tokens == null) return;
        for (String token : tokens) {
            if (token == null || token.isBlank()) continue;
            int colon = token.indexOf(':');
            String code = colon > 0 ? token.substring(0, colon) : token;
            String location = colon > 0 && colon + 1 < token.length()
                    ? token.substring(colon + 1) : token;
            String lower = token.toLowerCase(Locale.ROOT);
            EvidenceItem.SourceLayer source = (lower.startsWith("cloud_prop:")
                    || lower.startsWith("wired_interface:"))
                    ? EvidenceItem.SourceLayer.NATIVE
                    : EvidenceItem.SourceLayer.JAVA;
            EvidenceItem item = new EvidenceItem(
                    code, source, location, token, EVIDENCE_FAMILY, rank);
            String key = code + "|" + location;
            EvidenceItem existing = byKey.get(key);
            byKey.put(key, existing == null ? item : existing.mergeWith(item));
        }
    }
}
