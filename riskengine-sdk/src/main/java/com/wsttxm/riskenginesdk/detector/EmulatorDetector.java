package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

public class EmulatorDetector extends BaseDetector {
    private final SignalSnapshot signals;

    public EmulatorDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public EmulatorDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "emulator";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        checkBuildProperties(evidence, coverage);
        checkHardwareFeatures(evidence, coverage);
        checkEmulatorFiles(evidence, coverage);
        checkThermalZones(evidence, coverage);
        checkRuntimeArch(evidence, coverage);
        checkSensors(evidence, coverage);
        checkEmulatorIp(evidence, coverage);
        checkEmulatorPackages(evidence, coverage);
        checkContainerSignals(evidence, coverage);

        int strongSignals = 0;
        for (String signal : evidence) {
            if (isStrongSignal(signal)) {
                strongSignals++;
            }
        }
        int weakSignals = evidence.size() - strongSignals;

        if (strongSignals >= 2 || (strongSignals >= 1 && weakSignals >= 2)) {
            return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        } else if (strongSignals == 1) {
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        } else if (!evidence.isEmpty()) {
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        }
        return safe(coverage);
    }

    private boolean isStrongSignal(String signal) {
        return signal.startsWith("fingerprint:")
                || signal.startsWith("model:")
                || signal.startsWith("manufacturer:")
                || signal.startsWith("product:")
                || signal.startsWith("hardware:")
                || signal.startsWith("board:")
                || signal.startsWith("emu_file:")
                || signal.startsWith("emu_pkg:");
    }

    private void checkBuildProperties(List<String> evidence, CheckCoverage coverage) {
        String fingerprint = Build.FINGERPRINT.toLowerCase(Locale.ROOT);
        if (fingerprint.contains("vbox")) {
            evidence.add("fingerprint:" + Build.FINGERPRINT);
        } else if (fingerprint.contains("generic")) {
            // "generic" is also used by legitimate AOSP-derived and embedded
            // builds, so it must be correlated with stronger evidence.
            evidence.add("generic_fingerprint:" + Build.FINGERPRINT);
        }

        String[] modelKeywords = {"google_sdk", "emulator", "android sdk built for", "droid4x"};
        for (String kw : modelKeywords) {
            if (Build.MODEL.toLowerCase(Locale.ROOT).contains(kw)) {
                evidence.add("model:" + Build.MODEL);
                break;
            }
        }

        if (Build.MANUFACTURER.toLowerCase(Locale.ROOT).contains("genymotion")) {
            evidence.add("manufacturer:Genymotion");
        }

        String[] productKeywords = {"google_sdk", "sdk_phone", "sdk_x86", "vbox86p", "nox"};
        for (String kw : productKeywords) {
            if (Build.PRODUCT.toLowerCase(Locale.ROOT).contains(kw)) {
                evidence.add("product:" + Build.PRODUCT);
                break;
            }
        }

        String[] hwKeywords = {"ranchu", "vbox86", "goldfish"};
        for (String kw : hwKeywords) {
            if (Build.HARDWARE.equalsIgnoreCase(kw)) {
                evidence.add("hardware:" + Build.HARDWARE);
                break;
            }
        }

        if (Build.BOARD.toLowerCase(Locale.ROOT).contains("nox")) {
            evidence.add("board:" + Build.BOARD);
        }
        coverage.success();
    }

    private void checkHardwareFeatures(List<String> evidence, CheckCoverage coverage) {
        try {
            PackageManager pm = context.getPackageManager();
            String[] features = {
                    PackageManager.FEATURE_BLUETOOTH,
                    PackageManager.FEATURE_CAMERA_FLASH,
                    PackageManager.FEATURE_TELEPHONY
            };
            int missing = 0;
            for (String feature : features) {
                if (!pm.hasSystemFeature(feature)) {
                    missing++;
                }
            }
            if (missing > 0) {
                evidence.add("limited_hardware_features:" + missing);
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
                evidence.add("emu_file:" + found);
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
            int count = nativeResult.getValue();
            if (count == 0) {
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

    private void checkSensors(List<String> evidence, CheckCoverage coverage) {
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm != null) {
                List<Sensor> sensors = sm.getSensorList(Sensor.TYPE_ALL);
                if (sensors.size() < 5) {
                    evidence.add("low_sensor_count:" + sensors.size());
                }
                // Check for AOSP vendor
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
        String[] emulatorPackages = {
                "com.google.android.launcher.layouts.genymotion",
                "com.bluestacks",
                "com.bignox.app"
        };
        try {
            PackageManager pm = context.getPackageManager();
            for (String pkg : emulatorPackages) {
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
            evidence.addAll(container.getValue());
            coverage.success();
        } catch (Exception e) {
            CLog.e("Container signal check failed", e);
            coverage.failure("container_signals:" + e.getClass().getSimpleName());
        }
    }
}
