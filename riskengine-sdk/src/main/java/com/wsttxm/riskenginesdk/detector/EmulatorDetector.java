package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraManager;
import android.os.BatteryManager;
import android.os.Build;

import com.wsttxm.riskenginesdk.collector.java_layer.MediaCodecCollector;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.EmulatorEvidenceClassifier;
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

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class EmulatorDetector extends BaseDetector {
    public static final String EVIDENCE_FAMILY = "emulator";

    private final SignalSnapshot signals;
    private final SensorNoiseProbe.SensorFrameSampler sensorNoiseSampler;

    public EmulatorDetector(Context context) {
        this(context, new SignalSnapshot(context), null);
    }

    public EmulatorDetector(Context context, SignalSnapshot signals) {
        this(context, signals, null);
    }

    public EmulatorDetector(Context context,
                            SignalSnapshot signals,
                            SensorNoiseProbe.SensorFrameSampler sensorNoiseSampler) {
        super(context);
        this.signals = signals != null ? signals : new SignalSnapshot(context);
        this.sensorNoiseSampler = sensorNoiseSampler;
    }

    @Override
    public String getName() {
        return "emulator";
    }

    @Override
    public boolean hasPostponedProbes() {
        return true;
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        checkBuildProperties(evidence, coverage);
        checkQemuProperties(evidence, coverage);
        checkHardwareFeatures(evidence, coverage);
        checkEmulatorFiles(evidence, coverage);
        checkThermalZones(evidence, coverage);
        checkRuntimeArch(evidence, coverage);
        checkCpuAndDisk(evidence, coverage);
        checkScreen(evidence, coverage);
        checkSensors(evidence, coverage);
        checkEmulatorIp(evidence, coverage);
        checkEmulatorPackages(evidence, coverage);
        checkContainerSignals(evidence, coverage);
        checkVirtualGpu(evidence, coverage);
        checkBuildCharacteristics(evidence, coverage);
        checkModernVirtualizationProps(evidence, coverage);
        checkAvfJointMarkers(evidence, coverage);
        checkNativeBridgeFast(evidence, coverage);
        checkZeroHardwareMediaCodec(evidence, coverage);

        return scoreAndBuild(evidence, coverage);
    }

    @Override
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        DetectionResult base = priorResult != null ? priorResult : call();
        if (base == null) {
            return null;
        }

        List<String> merged = new ArrayList<>(base.getDetails());
        int initialCount = merged.size();
        int extraSucceeded = 0;

        // 1. Native postponed virtualization traps (disposable_child: sched_yield CV + ARM64 clock drift)
        try {
            SignalResult<String> traps = signals.getVirtualizationTraps(true);
            if (traps != null && traps.isSuccess() && traps.getValue() != null) {
                NativePayloadCodec.DecodedPayload decoded =
                        NativePayloadCodec.decodePayload(traps.getValue());
                if (decoded.isOk()) {
                    extraSucceeded++;
                    for (Map<String, String> rec : decoded.getRecords()) {
                        String kind = rec.get("kind");
                        if (kind == null || kind.isEmpty()) {
                            continue;
                        }
                        if (kind.startsWith("native_bridge_")) {
                            addUnique(merged, formatNativeBridgeToken(kind, rec));
                        } else if ("arm64_clock_drift".equals(kind)) {
                            String counterNs = safeVal(rec.get("counter_ns"));
                            String wallNs = safeVal(rec.get("wall_ns"));
                            addUnique(merged, "arm64_clock_drift:counter_ns=" + counterNs
                                    + ",wall_ns=" + wallNs);
                        } else if ("sched_yield_low_cv".equals(kind)) {
                            String cv = safeVal(rec.get("cv"));
                            String meanNs = safeVal(rec.get("mean_ns"));
                            addUnique(merged, "sched_yield_low_cv:cv=" + cv
                                    + ",mean_ns=" + meanNs);
                        }
                    }
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Postponed virtualization traps failed", e);
        }

        // 2. POSTPONED short-window (<= 200ms) MEMS static micro-noise probe.
        // Anti-FP: solo static zero-variance NEVER triggers standalone actionable risk;
        // only corroborate when paired with battery/camera/hardware/virtualization anomalies.
        try {
            SensorNoiseProbe.Result noise = SensorNoiseProbe.sample(
                    context, SensorNoiseProbe.DEFAULT_WINDOW_MS, sensorNoiseSampler);
            if (noise != null && noise.isAvailable()) {
                extraSucceeded++;
                if (noise.isStaticZeroVariance() && hasCorroboratingAnomalyForSensorNoise(merged)) {
                    addUnique(merged, "sensor_static_zero_var:" + noise.getSensorType()
                            + ":" + noise.getFrameCount());
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Postponed sensor noise probe failed", e);
        }

        if (merged.size() == initialCount) {
            return base;
        }

        return rebuildPostponedResult(base, merged, extraSucceeded);
    }

    private DetectionResult scoreAndBuild(List<String> evidence, CheckCoverage coverage) {
        ScoreBreakdown score = computeScore(evidence);
        List<EvidenceItem> items = buildEvidenceItems(evidence);

        DetectionResult res;
        if (score.level == RiskLevel.SAFE && evidence.isEmpty()) {
            res = safe(coverage);
        } else {
            res = result(score.level, score.status, score.score, 10, score.informational,
                    evidence, evidence.isEmpty() ? "no risk detected" : String.join("; ", evidence),
                    coverage);
        }
        return items.isEmpty() ? res : res.withEvidenceItems(items);
    }

    private DetectionResult rebuildPostponedResult(DetectionResult base,
                                                   List<String> merged,
                                                   int extraSucceeded) {
        ScoreBreakdown score = computeScore(merged);
        List<EvidenceItem> items = buildEvidenceItems(merged);

        int attempted = base.getChecksAttempted() + extraSucceeded;
        int succeeded = base.getChecksSucceeded() + extraSucceeded;
        int failed = base.getChecksFailed();
        DetectionExecutionStatus execStatus;
        if (succeeded == 0) {
            execStatus = base.getExecutionStatus();
        } else if (failed > 0) {
            execStatus = DetectionExecutionStatus.PARTIAL;
        } else if (score.level == RiskLevel.SAFE) {
            execStatus = DetectionExecutionStatus.SAFE;
        } else {
            execStatus = DetectionExecutionStatus.RISK;
        }

        String summary = merged.isEmpty() ? "no risk detected" : String.join("; ", merged);
        DetectionResult updated = new DetectionResult(
                getName(),
                score.level,
                score.status,
                score.score,
                10,
                score.informational,
                execStatus,
                attempted,
                succeeded,
                failed,
                base.getFailureReasons(),
                merged,
                summary
        ).withScanTier(getScanTier());
        return items.isEmpty() ? updated : updated.withEvidenceItems(items);
    }

    private static ScoreBreakdown computeScore(List<String> evidence) {
        int strongSignals = 0;
        int weakSignals = 0;
        int noiseWeak = 0;
        int softOnlyCount = 0;
        for (String signal : evidence) {
            EmulatorEvidenceClassifier.Rank rank = EmulatorEvidenceClassifier.rank(signal);
            if (rank == EmulatorEvidenceClassifier.Rank.STRONG) {
                strongSignals++;
            } else {
                weakSignals++;
                if (EmulatorEvidenceClassifier.isHardwareNoise(signal)) {
                    noiseWeak++;
                }
                if (EmulatorEvidenceClassifier.isSoftCorroboratorOnly(signal)) {
                    softOnlyCount++;
                }
            }
        }
        int usefulWeak = weakSignals - noiseWeak;

        if (strongSignals >= 2 || (strongSignals >= 1 && usefulWeak >= 1)) {
            return new ScoreBreakdown(RiskLevel.HIGH, DetectionStatus.DANGER, 8, false);
        }
        if (strongSignals == 1) {
            return new ScoreBreakdown(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, false);
        }
        if (!evidence.isEmpty()) {
            // Anti-FP: solo soft timing/sensor corroborators (sched_yield CV / sensor static zero-var)
            // MUST NEVER produce actionable risk (not even under LOGIN/PAYMENT scene elevation).
            if (softOnlyCount == evidence.size()) {
                return new ScoreBreakdown(RiskLevel.SAFE, DetectionStatus.NORMAL, 0, true);
            }
            return new ScoreBreakdown(RiskLevel.LOW, DetectionStatus.WARNING, 1, true);
        }
        return new ScoreBreakdown(RiskLevel.SAFE, DetectionStatus.NORMAL, 0, false);
    }

    private static final class ScoreBreakdown {
        final RiskLevel level;
        final DetectionStatus status;
        final int score;
        final boolean informational;

        ScoreBreakdown(RiskLevel level, DetectionStatus status, int score, boolean informational) {
            this.level = level;
            this.status = status;
            this.score = score;
            this.informational = informational;
        }
    }

    private void checkBuildProperties(List<String> evidence, CheckCoverage coverage) {
        String rawFingerprint = Build.FINGERPRINT == null ? "" : Build.FINGERPRINT;
        String rawModel = Build.MODEL == null ? "" : Build.MODEL;
        String rawManufacturer = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER;
        String rawProduct = Build.PRODUCT == null ? "" : Build.PRODUCT;
        String rawHardware = Build.HARDWARE == null ? "" : Build.HARDWARE;
        String rawBoard = Build.BOARD == null ? "" : Build.BOARD;
        if (rawFingerprint.isEmpty() && rawModel.isEmpty() && rawProduct.isEmpty()
                && rawHardware.isEmpty() && rawBoard.isEmpty() && rawManufacturer.isEmpty()) {
            coverage.failure("build_properties:unavailable");
            return;
        }
        String fingerprint = rawFingerprint.toLowerCase(Locale.ROOT);
        if (fingerprint.contains("vbox")) {
            evidence.add("fingerprint:" + rawFingerprint);
        } else if (fingerprint.contains("generic") || fingerprint.contains("emulator")) {
            evidence.add("generic_fingerprint:" + rawFingerprint);
        }

        String[] modelKeywords = {"google_sdk", "emulator", "android sdk built for", "droid4x"};
        for (String kw : modelKeywords) {
            if (rawModel.toLowerCase(Locale.ROOT).contains(kw)) {
                evidence.add("model:" + rawModel);
                break;
            }
        }

        if (rawManufacturer.toLowerCase(Locale.ROOT).contains("genymotion")) {
            evidence.add("manufacturer:Genymotion");
        }

        String[] productKeywords = {"google_sdk", "sdk_phone", "sdk_x86", "vbox86p", "nox"};
        for (String kw : productKeywords) {
            if (rawProduct.toLowerCase(Locale.ROOT).contains(kw)) {
                evidence.add("product:" + rawProduct);
                break;
            }
        }

        String[] hwKeywords = {"ranchu", "goldfish", "vbox86"};
        for (String kw : hwKeywords) {
            if (rawHardware.equalsIgnoreCase(kw)) {
                evidence.add("hardware:" + rawHardware);
                break;
            }
        }

        if (rawBoard.toLowerCase(Locale.ROOT).contains("nox")) {
            evidence.add("board:" + rawBoard);
        }
        coverage.success();
    }

    private void checkQemuProperties(List<String> evidence, CheckCoverage coverage) {
        try {
            for (String prop : new String[]{"ro.kernel.qemu", "ro.boot.qemu"}) {
                SignalResult<String> value = signals.getSystemProperty(prop);
                if (!value.isSuccess()) continue;
                String raw = value.getValue() == null ? "" : value.getValue().trim();
                if ("1".equals(raw)) {
                    evidence.add("qemu_prop:" + prop);
                }
            }
            // ro.hardware.virtual is denied via default_prop SELinux policy on API 33+.
            if (Build.VERSION.SDK_INT < 33) {
                SignalResult<String> virtual = signals.getSystemProperty("ro.hardware.virtual");
                if (virtual.isSuccess() && virtual.getValue() != null && !virtual.getValue().isBlank()) {
                    evidence.add("qemu_prop:ro.hardware.virtual");
                }
            }
            coverage.success();
        } catch (Exception e) {
            coverage.failure("qemu_props:" + e.getClass().getSimpleName());
        }
    }

    /**
     * Checks modern virtualization properties (Waydroid, Cuttlefish, WSA, Corellium,
     * LDPlayer 9, MuMu 12) without penalizing coverage when absent/unreadable.
     */
    private void checkModernVirtualizationProps(List<String> evidence, CheckCoverage coverage) {
        try {
            String[][] modernProps = {
                    {"ro.waydroid.version", "waydroid"},
                    {"ro.wsa.version", "wsa"},
                    {"ro.corellium.version", "corellium"},
                    {"ro.ldplayer.version", "ldplayer9"},
                    {"ro.mumu.version", "mumu12"}
            };
            for (String[] pair : modernProps) {
                SignalResult<String> val = signals.getSystemProperty(pair[0]);
                if (val != null && val.isSuccess() && val.getValue() != null
                        && !val.getValue().isBlank()) {
                    addUnique(evidence, "emu_prop:" + pair[1] + ":" + pair[0]);
                }
            }

            SignalResult<String> bootHw = signals.getSystemProperty("ro.boot.hardware");
            if (bootHw != null && bootHw.isSuccess() && bootHw.getValue() != null) {
                String lower = bootHw.getValue().trim().toLowerCase(Locale.ROOT);
                if (lower.contains("cutf_cvm") || lower.contains("cuttlefish")
                        || lower.startsWith("vsoc")) {
                    addUnique(evidence, "emu_prop:cuttlefish:ro.boot.hardware=" + lower);
                } else if (lower.contains("waydroid")) {
                    addUnique(evidence, "emu_prop:waydroid:ro.boot.hardware=" + lower);
                } else if (lower.contains("corellium")) {
                    addUnique(evidence, "emu_prop:corellium:ro.boot.hardware=" + lower);
                } else if (lower.contains("windows_x86_64")) {
                    addUnique(evidence, "emu_prop:wsa:ro.boot.hardware=" + lower);
                }
            }
        } catch (Exception | LinkageError e) {
            CLog.e("Modern virtualization property check failed", e);
        }
    }

    /**
     * Detects Android Virtualization Framework (AVF / Microdroid) guests ONLY when at least
     * 2 independent AVF markers co-occur (e.g. {@code authfs} + {@code virtiofs}/{@code crosvm}).
     * A single AVF marker NEVER triggers standalone risk.
     */
    private void checkAvfJointMarkers(List<String> evidence, CheckCoverage coverage) {
        try {
            Set<String> avfHits = new TreeSet<>();

            SignalResult<String> mounts = signals.getTextFile("/proc/mounts");
            if (mounts != null && mounts.isSuccess() && mounts.getValue() != null) {
                String lower = mounts.getValue().toLowerCase(Locale.ROOT);
                if (lower.contains("authfs")) avfHits.add("authfs");
                if (lower.contains("virtiofs")) avfHits.add("virtiofs");
                if (lower.contains("crosvm")) avfHits.add("crosvm");
            }

            SignalResult<String> cmdline = signals.getTextFile("/proc/cmdline");
            if (cmdline != null && cmdline.isSuccess() && cmdline.getValue() != null) {
                String lower = cmdline.getValue().toLowerCase(Locale.ROOT);
                if (lower.contains("authfs")) avfHits.add("authfs");
                if (lower.contains("virtiofs")) avfHits.add("virtiofs");
                if (lower.contains("crosvm")) avfHits.add("crosvm");
                if (lower.contains("microdroid")) avfHits.add("microdroid");
            }

            SignalResult<String> cpu = signals.getCpuInfo();
            if (cpu != null && cpu.isSuccess() && cpu.getValue() != null) {
                String lower = cpu.getValue().toLowerCase(Locale.ROOT);
                if (lower.contains("crosvm")) avfHits.add("crosvm");
            }

            SignalResult<String> bootHw = signals.getSystemProperty("ro.boot.hardware");
            if (bootHw != null && bootHw.isSuccess() && bootHw.getValue() != null) {
                String lower = bootHw.getValue().toLowerCase(Locale.ROOT);
                if (lower.contains("microdroid")) avfHits.add("microdroid");
                if (lower.contains("crosvm")) avfHits.add("crosvm");
            }

            SignalResult<String> microDebug =
                    signals.getSystemProperty("ro.boot.microdroid.debuggable");
            if (microDebug != null && microDebug.isSuccess() && microDebug.getValue() != null
                    && !microDebug.getValue().isBlank()) {
                avfHits.add("microdroid");
            }

            // Require >= 2 joint AVF markers (anti-FP guard).
            if (avfHits.size() >= 2) {
                addUnique(evidence, "avf_virtualization:" + String.join("+", avfHits));
            }
        } catch (Exception | LinkageError e) {
            CLog.e("AVF joint marker check failed", e);
        }
    }

    /** Consumes fast-path Native Bridge translation hits from virtualization_traps. */
    private void checkNativeBridgeFast(List<String> evidence, CheckCoverage coverage) {
        try {
            SignalResult<String> traps = signals.getVirtualizationTraps(false);
            if (traps == null || !traps.isSuccess() || traps.getValue() == null) {
                return;
            }
            NativePayloadCodec.DecodedPayload decoded =
                    NativePayloadCodec.decodePayload(traps.getValue());
            if (!decoded.isOk()) {
                return;
            }
            coverage.success();
            for (Map<String, String> rec : decoded.getRecords()) {
                String kind = rec.get("kind");
                if (kind != null && kind.startsWith("native_bridge_")) {
                    addUnique(evidence, formatNativeBridgeToken(kind, rec));
                }
            }
        } catch (Exception | LinkageError e) {
            CLog.e("Native Bridge check failed", e);
        }
    }

    /** Corroborates zero-SoC-hardware MediaCodec (c2.android.* / OMX.google.* software only). */
    private void checkZeroHardwareMediaCodec(List<String> evidence, CheckCoverage coverage) {
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
                addUnique(evidence, "zero_hw_codec:sw=" + summary.swAndroidGoogleCount + ",hw=0");
            }
        } catch (Exception | LinkageError e) {
            CLog.e("MediaCodec check failed", e);
        }
    }

    private void checkHardwareFeatures(List<String> evidence, CheckCoverage coverage) {
        try {
            PackageManager pm = context.getPackageManager();
            boolean touchscreen = pm.hasSystemFeature(PackageManager.FEATURE_TOUCHSCREEN);
            boolean telephony = pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY);
            String radio = Build.getRadioVersion();
            if (touchscreen && !telephony && radio != null && !radio.isBlank()
                    && !"unknown".equalsIgnoreCase(radio)) {
                evidence.add("missing_feature:telephony");
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Hardware feature check failed", e);
            coverage.failure("hardware_features:" + e.getClass().getSimpleName());
        }
    }

    private void checkEmulatorFiles(List<String> evidence, CheckCoverage coverage) {
        if (!NativeCollectorBridge.isNativeAvailable()) {
            coverage.failure("emulator_files:native_unavailable");
            return;
        }
        try {
            SignalResult<String> nativeResult = NativeCollectorBridge.checkEmulatorFilesResult();
            if (!nativeResult.isSuccess()) {
                coverage.failure("emulator_files:" + nativeResult.getFailureReason());
                return;
            }
            String found = nativeResult.getValue();
            if (found != null && !found.isEmpty()) {
                for (String path : found.split(",")) {
                    if (path.contains("qemu_pipe") || path.contains("goldfish_pipe")
                            || path.contains("qemu_trace") || path.contains("qemud")) {
                        evidence.add("qemu_pipe:" + path.trim());
                    } else {
                        evidence.add("emu_file:" + path.trim());
                    }
                }
            }
            coverage.success();
        } catch (Exception | LinkageError e) {
            CLog.e("Emulator file check failed", e);
            coverage.failure("emulator_files:" + e.getClass().getSimpleName());
        }
    }

    private void checkThermalZones(List<String> evidence, CheckCoverage coverage) {
        if (!NativeCollectorBridge.isNativeAvailable()) {
            coverage.failure("thermal_zones:native_unavailable");
            return;
        }
        try {
            SignalResult<Integer> nativeResult = NativeCollectorBridge.getThermalZoneCountResult();
            if (!nativeResult.isSuccess() || nativeResult.getValue() == null) {
                coverage.failure("thermal_zones:" + nativeResult.getFailureReason());
                return;
            }
            if (nativeResult.getValue() == 0) {
                evidence.add("no_thermal_zones");
            }
            coverage.success();
        } catch (Exception | LinkageError e) {
            CLog.e("Thermal zone check failed", e);
            coverage.failure("thermal_zones:" + e.getClass().getSimpleName());
        }
    }

    private void checkRuntimeArch(List<String> evidence, CheckCoverage coverage) {
        if (!NativeCollectorBridge.isNativeAvailable()) {
            coverage.failure("runtime_arch:native_unavailable");
            return;
        }
        try {
            SignalResult<String> nativeResult = NativeCollectorBridge.getRuntimeArchResult();
            if (!nativeResult.isSuccess()) {
                coverage.failure("runtime_arch:" + nativeResult.getFailureReason());
                return;
            }
            String arch = nativeResult.getValue();
            if ("X86_64".equals(arch) || "I386".equals(arch)) {
                evidence.add("runtime_arch:" + arch);
            }
            coverage.success();
        } catch (Exception | LinkageError e) {
            CLog.e("Runtime architecture check failed", e);
            coverage.failure("runtime_arch:" + e.getClass().getSimpleName());
        }
    }

    private void checkCpuAndDisk(List<String> evidence, CheckCoverage coverage) {
        try {
            SignalResult<String> cpu = signals.getCpuInfo();
            if (cpu.isSuccess() && cpu.getValue() != null) {
                String lower = cpu.getValue().toLowerCase(Locale.ROOT);
                if (lower.contains("goldfish") || lower.contains("ranchu")
                        || lower.contains("qemu") || lower.contains("hypervisor")) {
                    evidence.add("cpu:hypervisor");
                }
                coverage.success();
            } else {
                coverage.failure("cpu_info:" + cpu.getFailureReason());
            }
        } catch (Exception e) {
            coverage.failure("cpu_info:" + e.getClass().getSimpleName());
        }
        try {
            SignalResult<Long> disk = signals.getDiskSizeData();
            if (disk.isSuccess() && disk.getValue() != null) {
                if (disk.getValue() > 0 && disk.getValue() < 4L * 1024 * 1024 * 1024) {
                    evidence.add("disk_small");
                }
                coverage.success();
            } else {
                coverage.failure("disk_size:" + disk.getFailureReason());
            }
        } catch (Exception e) {
            coverage.failure("disk_size:" + e.getClass().getSimpleName());
        }
        try {
            SignalResult<String> kernel = signals.getKernelInfo();
            if (kernel.isSuccess() && kernel.getValue() != null) {
                String lower = kernel.getValue().toLowerCase(Locale.ROOT);
                if (lower.contains("x86_64") || lower.contains("i686") || lower.contains("i386")) {
                    if (!containsPrefix(evidence, "runtime_arch:")) {
                        evidence.add("runtime_arch:X86_64");
                    }
                }
                coverage.success();
            } else {
                coverage.failure("kernel_info:" + kernel.getFailureReason());
            }
        } catch (Exception e) {
            coverage.failure("kernel_info:" + e.getClass().getSimpleName());
        }
    }

    private void checkScreen(List<String> evidence, CheckCoverage coverage) {
        try {
            SignalResult<SignalSnapshot.ScreenMetrics> screen = signals.getScreenMetrics();
            if (!screen.isSuccess() || screen.getValue() == null) {
                coverage.failure("screen:" + screen.getFailureReason());
                return;
            }
            SignalSnapshot.ScreenMetrics metrics = screen.getValue();
            boolean stockDensity = metrics.densityDpi == 160 || metrics.densityDpi == 240;
            boolean equalDpi = Math.abs(metrics.xdpi - metrics.ydpi) < 0.01f;
            boolean stockRes = (metrics.width == 1080 && metrics.height == 1920)
                    || (metrics.width == 720 && metrics.height == 1280)
                    || (metrics.width == 1920 && metrics.height == 1080)
                    || (metrics.width == 1280 && metrics.height == 720);
            if (stockDensity && equalDpi && stockRes) {
                evidence.add("screen_stock");
            }
            coverage.success();
        } catch (Exception e) {
            coverage.failure("screen:" + e.getClass().getSimpleName());
        }
    }

    private void checkSensors(List<String> evidence, CheckCoverage coverage) {
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm != null) {
                List<Sensor> sensors = sm.getSensorList(Sensor.TYPE_ALL);
                if (sensors.size() < 5) {
                    evidence.add("low_sensor_count:" + sensors.size());
                }
                for (Sensor s : sensors) {
                    if ("AOSP".equalsIgnoreCase(s.getVendor())) {
                        evidence.add("aosp_sensor_vendor:" + s.getName());
                        break;
                    }
                }
                coverage.success();
            } else {
                coverage.failure("sensors:service_unavailable");
            }
        } catch (Exception e) {
            CLog.e("Sensor check failed", e);
            coverage.failure("sensors:" + e.getClass().getSimpleName());
        }
    }

    private void checkEmulatorIp(List<String> evidence, CheckCoverage coverage) {
        try {
            if (context == null || context.checkSelfPermission(android.Manifest.permission.INTERNET)
                    != PackageManager.PERMISSION_GRANTED) {
                coverage.success();
                return;
            }
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (!addr.isLoopbackAddress() && addr instanceof Inet4Address) {
                        String ip = addr.getHostAddress();
                        if ("10.0.2.15".equals(ip) || "10.0.2.16".equals(ip)) {
                            evidence.add("emulator_ip:" + ip);
                        }
                    }
                }
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Emulator IP check failed", e);
            coverage.failure("network_interfaces:" + e.getClass().getSimpleName());
        }
    }

    private void checkEmulatorPackages(List<String> evidence, CheckCoverage coverage) {
        try {
            PackageManager pm = context.getPackageManager();
            for (String pkg : DetectionLists.EMULATOR_PACKAGES) {
                try {
                    pm.getPackageInfo(pkg, 0);
                    evidence.add("emu_pkg:" + pkg);
                } catch (PackageManager.NameNotFoundException ignored) {}
            }
            coverage.success();
        } catch (Exception e) {
            coverage.failure("emulator_packages:" + e.getClass().getSimpleName());
        }
    }

    private void checkContainerSignals(List<String> evidence, CheckCoverage coverage) {
        try {
            SignalResult<List<String>> container = signals.getContainerSignals();
            if (!container.isSuccess() || container.getValue() == null) {
                coverage.failure("container_signals:" + container.getFailureReason());
                return;
            }
            for (String signal : container.getValue()) {
                if ("mount_overlay".equals(signal)) {
                    continue;
                }
                evidence.add(signal);
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Container signal check failed", e);
            coverage.failure("container_signals:" + e.getClass().getSimpleName());
        }
    }

    /**
     * A virtualized GPU renderer is a strong emulator signal and, unlike the
     * Build fields, cannot be changed by a property override.
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
            evidence.add("virtual_gpu:" + marker);
        }
    }

    /** AOSP emulator images declare themselves in ro.build.characteristics. */
    private void checkBuildCharacteristics(List<String> evidence, CheckCoverage coverage) {
        SignalResult<String> value = signals.getSystemProperty("ro.build.characteristics");
        if (!value.isSuccess()) {
            coverage.failure("build_characteristics:" + value.getFailureReason());
            return;
        }
        coverage.success();
        String raw = value.getValue();
        if (raw == null || raw.isBlank()) return;
        if (raw.toLowerCase(Locale.ROOT).contains("emulator")) {
            evidence.add("qemu_prop:ro.build.characteristics=" + raw.trim());
        }
    }

    private boolean hasCorroboratingAnomalyForSensorNoise(List<String> existingEvidence) {
        for (String token : existingEvidence) {
            if (!EmulatorEvidenceClassifier.isSoftCorroboratorOnly(token)) {
                return true;
            }
        }
        return hasBatteryOrCameraHardwareAnomaly();
    }

    private boolean hasBatteryOrCameraHardwareAnomaly() {
        if (context == null) {
            return false;
        }
        try {
            Intent battery = context.registerReceiver(null,
                    new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (battery != null) {
                int voltage = battery.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1);
                int temperature = battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);
                if (voltage == 0 || temperature == 0) {
                    return true;
                }
            }
        } catch (Exception | LinkageError ignored) {}
        try {
            PackageManager pm = context.getPackageManager();
            if (pm != null && !pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
                CameraManager cm = (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
                if (cm == null || cm.getCameraIdList().length == 0) {
                    return true;
                }
            }
        } catch (Exception | LinkageError ignored) {}
        return false;
    }

    private static List<EvidenceItem> buildEvidenceItems(List<String> evidence) {
        if (evidence == null || evidence.isEmpty()) {
            return Collections.emptyList();
        }
        Map<String, EvidenceItem> byKey = new LinkedHashMap<>();
        for (String token : evidence) {
            if (token == null || token.isBlank()) {
                continue;
            }
            EvidenceItem item = toEvidenceItem(token);
            String key = item.getCode() + "|" + item.getLocation();
            EvidenceItem existing = byKey.get(key);
            byKey.put(key, existing == null ? item : existing.mergeWith(item));
        }
        return new ArrayList<>(byKey.values());
    }

    private static EvidenceItem toEvidenceItem(String token) {
        int colon = token.indexOf(':');
        String code = colon > 0 ? token.substring(0, colon) : token;
        String detail = colon > 0 && colon + 1 < token.length() ? token.substring(colon + 1) : token;
        String lower = token.toLowerCase(Locale.ROOT);

        EvidenceItem.SourceLayer source;
        if (lower.startsWith("native_bridge:")
                || lower.startsWith("emu_file:")
                || lower.startsWith("qemu_pipe:")
                || lower.startsWith("runtime_arch:")
                || lower.startsWith("no_thermal")
                || lower.startsWith("cpu:hypervisor")
                || lower.startsWith("avf_virtualization:")
                || lower.startsWith("arm64_clock_drift")
                || lower.startsWith("sched_yield_low_cv")
                || lower.startsWith("emu_prop:")
                || lower.startsWith("qemu_prop:")) {
            source = EvidenceItem.SourceLayer.NATIVE;
        } else {
            source = EvidenceItem.SourceLayer.JAVA;
        }

        EvidenceItem.Rank rank;
        if (lower.startsWith("sched_yield_low_cv")) {
            rank = EvidenceItem.Rank.INFO;
        } else if (EmulatorEvidenceClassifier.rank(token) == EmulatorEvidenceClassifier.Rank.STRONG) {
            rank = EvidenceItem.Rank.STRONG;
        } else {
            rank = EvidenceItem.Rank.WEAK;
        }

        return new EvidenceItem(code, source, detail, token, EVIDENCE_FAMILY, rank);
    }

    private static String formatNativeBridgeToken(String kind, Map<String, String> rec) {
        String detail = rec.get("path");
        if (detail == null || detail.isEmpty()) detail = rec.get("value");
        if (detail == null || detail.isEmpty()) detail = rec.get("arg");
        if (detail == null || detail.isEmpty()) detail = kind;
        return "native_bridge:" + kind + ":" + detail;
    }

    private static String safeVal(String s) {
        return s == null || s.isEmpty() ? "0" : s;
    }

    private static void addUnique(List<String> list, String value) {
        if (value != null && !value.isBlank() && !list.contains(value)) {
            list.add(value);
        }
    }

    private static boolean containsPrefix(List<String> evidence, String prefix) {
        for (String item : evidence) {
            if (item.startsWith(prefix)) return true;
        }
        return false;
    }
}
