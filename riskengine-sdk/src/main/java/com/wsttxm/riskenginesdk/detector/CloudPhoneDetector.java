package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraManager;
import android.os.BatteryManager;

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
        List<String> evidence = new ArrayList<>();

        boolean batteryAvailable = checkBatteryAnomaly(evidence);
        boolean cameraAvailable = checkCameraCount(evidence);
        boolean sensorsAvailable = checkSensorCount(evidence);
        CheckCoverage coverage = new CheckCoverage();
        if (batteryAvailable) coverage.success();
        else coverage.failure("battery_unavailable");
        if (cameraAvailable) coverage.success();
        else coverage.failure("camera_unavailable");
        if (sensorsAvailable) coverage.success();
        else coverage.failure("sensors_unavailable");

        if (!evidence.isEmpty()) {
            RiskLevel level = evidence.size() >= 3 ? RiskLevel.MEDIUM : RiskLevel.LOW;
            return result(level, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (!batteryAvailable && !cameraAvailable && !sensorsAvailable) {
            return unavailable("hardware_signals_unavailable");
        }
        return safe(coverage);
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

            // Cloud phones often have abnormal battery values
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
            CameraManager cm = (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
            if (cm == null) {
                evidence.add("low_camera_count:0");
                return true;
            }
            String[] cameras = cm.getCameraIdList();
            if (cameras.length < 2) {
                evidence.add("low_camera_count:" + cameras.length);
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
            List<Sensor> sensors = sm.getSensorList(Sensor.TYPE_ALL);
            if (sensors.size() < 3) {
                evidence.add("very_low_sensor_count:" + sensors.size());
            }
            return true;
        } catch (Exception e) {
            CLog.e("Sensor count check failed", e);
            return false;
        }
    }
}
