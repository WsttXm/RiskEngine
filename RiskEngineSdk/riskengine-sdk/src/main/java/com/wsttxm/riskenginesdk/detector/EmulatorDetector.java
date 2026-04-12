package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

public class EmulatorDetector extends BaseDetector {

    public EmulatorDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "emulator";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();

        checkBuildProperties(evidence);
        checkHardwareFeatures(evidence);
        checkEmulatorFiles(evidence);
        checkThermalZones(evidence);
        checkSeccompArch(evidence);
        checkSensors(evidence);
        checkEmulatorIp(evidence);
        checkEmulatorPackages(evidence);

        if (evidence.size() >= 3) {
            return risk(RiskLevel.HIGH, String.join("; ", evidence));
        } else if (!evidence.isEmpty()) {
            return risk(RiskLevel.MEDIUM, String.join("; ", evidence));
        }
        return safe();
    }

    private void checkBuildProperties(List<String> evidence) {
        String[] fingerprintKeywords = {"generic", "vbox"};
        for (String kw : fingerprintKeywords) {
            if (Build.FINGERPRINT.toLowerCase(Locale.ROOT).contains(kw)) {
                evidence.add("fingerprint:" + Build.FINGERPRINT);
                break;
            }
        }

        String[] modelKeywords = {"google_sdk", "emulator", "android sdk built for", "droid4x"};
        for (String kw : modelKeywords) {
            if (Build.MODEL.toLowerCase(Locale.ROOT).contains(kw)) {
                evidence.add("model:" + Build.MODEL);
                break;
            }
        }

        if (Build.MANUFACTURER.contains("Genymotion")) {
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
    }

    private void checkHardwareFeatures(List<String> evidence) {
        try {
            PackageManager pm = context.getPackageManager();
            String[] features = {
                    PackageManager.FEATURE_BLUETOOTH,
                    PackageManager.FEATURE_CAMERA_FLASH,
                    PackageManager.FEATURE_TELEPHONY
            };
            for (String feature : features) {
                if (!pm.hasSystemFeature(feature)) {
                    evidence.add("missing_feature:" + feature);
                }
            }
        } catch (Exception e) {
            CLog.e("Hardware feature check failed", e);
        }
    }

    private void checkEmulatorFiles(List<String> evidence) {
        try {
            String found = NativeCollectorBridge.nativeCheckEmulatorFiles();
            if (found != null && !found.isEmpty()) {
                evidence.add("emu_file:" + found);
            }
        } catch (Exception e) {
            CLog.e("Emulator file check failed", e);
        }
    }

    private void checkThermalZones(List<String> evidence) {
        try {
            int count = NativeCollectorBridge.nativeGetThermalZoneCount();
            if (count == 0) {
                evidence.add("no_thermal_zones");
            }
        } catch (Exception e) {
            CLog.e("Thermal zone check failed", e);
        }
    }

    private void checkSeccompArch(List<String> evidence) {
        try {
            String arch = NativeCollectorBridge.nativeCheckSeccompArch();
            if (arch != null && !arch.isEmpty()) {
                evidence.add("seccomp_arch:" + arch);
            }
        } catch (Exception e) {
            CLog.e("Seccomp arch check failed", e);
        }
    }

    private void checkSensors(List<String> evidence) {
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
            }
        } catch (Exception e) {
            CLog.e("Sensor check failed", e);
        }
    }

    private void checkEmulatorIp(List<String> evidence) {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
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
        } catch (Exception e) {
            CLog.e("Emulator IP check failed", e);
        }
    }

    private void checkEmulatorPackages(List<String> evidence) {
        String[] emuPkgs = {
                "com.google.android.launcher.layouts.genymotion",
                "com.bluestacks",
                "com.bignox.app"
        };
        PackageManager pm = context.getPackageManager();
        for (String pkg : emuPkgs) {
            try {
                pm.getPackageInfo(pkg, 0);
                evidence.add("emu_pkg:" + pkg);
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
    }
}
