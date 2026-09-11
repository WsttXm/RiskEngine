package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Builds a sensor-set fingerprint from full per-sensor tuples.
 *
 * The existing emulator detector only counted sensors. A count is weak and
 * unstable; the vendor/name/version/resolution/range/power tuple set is
 * hardware-bound and survives reinstall and factory reset. Hashing the sorted
 * tuple list yields one high-entropy stable field instead of a large payload,
 * which is the approach the reference device-info apps use.
 */
public class SensorFingerprintCollector extends BaseCollector {

    public SensorFingerprintCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "sensor_fingerprint";
    }

    @Override
    protected void collect(CollectorResult result) {
        try {
            SensorManager manager =
                    (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (manager == null) {
                result.markUnsupported("sensor_service_unavailable");
                return;
            }
            List<Sensor> sensors = manager.getSensorList(Sensor.TYPE_ALL);
            if (sensors == null || sensors.isEmpty()) {
                result.addValue("count", "0");
                return;
            }

            List<String> tuples = new ArrayList<>(sensors.size());
            List<String> vendors = new ArrayList<>();
            int wakeUp = 0;
            int dynamic = 0;
            for (Sensor sensor : sensors) {
                tuples.add(String.format(Locale.ROOT, "%d|%s|%s|%d|%.6f|%.6f|%.4f|%d|%d",
                        sensor.getType(),
                        safe(sensor.getName()),
                        safe(sensor.getVendor()),
                        sensor.getVersion(),
                        sensor.getResolution(),
                        sensor.getMaximumRange(),
                        sensor.getPower(),
                        sensor.getMinDelay(),
                        sensor.getFifoMaxEventCount()));
                String vendor = safe(sensor.getVendor());
                if (!vendor.isEmpty() && !vendors.contains(vendor)) {
                    vendors.add(vendor);
                }
                if (sensor.isWakeUpSensor()) wakeUp++;
                if (sensor.isDynamicSensor()) dynamic++;
            }
            Collections.sort(tuples);
            Collections.sort(vendors);

            result.addValue("count", String.valueOf(sensors.size()));
            result.addValue("tuple_hash", GpuInfoCollector.sha256(String.join("||", tuples)));
            result.addValue("vendor_hash", GpuInfoCollector.sha256(String.join(",", vendors)));
            result.addValue("vendor_count", String.valueOf(vendors.size()));
            result.addValue("wakeup_count", String.valueOf(wakeUp));
            result.addValue("dynamic_count", String.valueOf(dynamic));

            // Core physical sensors a real handset always has. Their absence is
            // consumed by the emulator and cloud-phone detectors.
            result.addValue("has_accelerometer", String.valueOf(
                    manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null));
            result.addValue("has_gyroscope", String.valueOf(
                    manager.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null));
            result.addValue("has_proximity", String.valueOf(
                    manager.getDefaultSensor(Sensor.TYPE_PROXIMITY) != null));
            result.addValue("has_magnetometer", String.valueOf(
                    manager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) != null));
        } catch (Exception e) {
            CLog.e("Sensor fingerprint collection failed", e);
            result.markError(e);
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
