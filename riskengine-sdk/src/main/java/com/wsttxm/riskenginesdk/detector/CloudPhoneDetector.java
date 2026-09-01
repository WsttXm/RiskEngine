package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraManager;
import android.os.BatteryManager;

import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;

public class CloudPhoneDetector extends BaseDetector {

    public CloudPhoneDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "cloud_phone";
    }

    @Override
    protected DetectionResult detect() {
        List<String> strong = new ArrayList<>();
        List<String> weak = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        if (checkPackages(strong)) coverage.success();
        else coverage.failure("packages_unavailable");
        if (checkBatteryAnomaly(weak)) coverage.success();
        else coverage.failure("battery_unavailable");
        if (checkCameraCount(weak)) coverage.success();
        else coverage.failure("camera_unavailable");
        if (checkSensorCount(weak)) coverage.success();
        else coverage.failure("sensors_unavailable");

        List<String> evidence = new ArrayList<>(strong);
        evidence.addAll(weak);
        if (!strong.isEmpty()) {
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (!weak.isEmpty()) {
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        }
        return safe(coverage);
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
            if (pm.hasSystemFeature(PackageManager.FEATURE_CAMERA)) {
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
}
