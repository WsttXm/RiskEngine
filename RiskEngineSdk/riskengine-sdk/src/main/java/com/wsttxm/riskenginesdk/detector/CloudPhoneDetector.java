package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraManager;
import android.os.BatteryManager;

import com.wsttxm.riskenginesdk.model.DetectionResult;
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

        checkBatteryAnomaly(evidence);
        checkCameraCount(evidence);
        checkSensorCount(evidence);

        if (evidence.size() >= 2) {
            return risk(RiskLevel.HIGH, String.join("; ", evidence));
        } else if (!evidence.isEmpty()) {
            return risk(RiskLevel.MEDIUM, String.join("; ", evidence));
        }
        return safe();
    }

    private void checkBatteryAnomaly(List<String> evidence) {
        try {
            IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent battery = context.registerReceiver(null, filter);
            if (battery != null) {
                int voltage = battery.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1);
                int temperature = battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);

                // Cloud phones often have abnormal battery values
                if (voltage == 0 || temperature == 0) {
                    evidence.add("battery_zero:v=" + voltage + ",t=" + temperature);
                }

                int status = battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
                int level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                // Always 100% and charging is suspicious
                if (level == 100 && status == BatteryManager.BATTERY_STATUS_CHARGING) {
                    // Check power: if USB charging but reporting very high power, likely fake
                    int plugged = battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
                    if (plugged == 0) {
                        evidence.add("battery_anomaly:100%_charging_no_plug");
                    }
                }
            }
        } catch (Exception e) {
            CLog.e("Battery check failed", e);
        }
    }

    private void checkCameraCount(List<String> evidence) {
        try {
            CameraManager cm = (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
            if (cm != null) {
                String[] cameras = cm.getCameraIdList();
                if (cameras.length < 2) {
                    evidence.add("low_camera_count:" + cameras.length);
                }
            }
        } catch (Exception e) {
            CLog.e("Camera check failed", e);
        }
    }

    private void checkSensorCount(List<String> evidence) {
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm != null) {
                List<Sensor> sensors = sm.getSensorList(Sensor.TYPE_ALL);
                if (sensors.size() < 3) {
                    evidence.add("very_low_sensor_count:" + sensors.size());
                }
            }
        } catch (Exception e) {
            CLog.e("Sensor count check failed", e);
        }
    }
}
