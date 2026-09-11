package com.wsttxm.riskenginesdk.collector.java_layer;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.os.BatteryManager;
import android.util.Size;
import android.util.SizeF;
import android.view.Display;
import android.view.WindowManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Collects hardware profile dimensions: memory, display capability, camera
 * characteristics and battery specification.
 *
 * These are grouped because each is individually small but jointly they carry
 * substantial entropy, and all four are hardware-bound rather than settable by
 * a property override. Camera physical sensor size and battery design capacity
 * in particular are values device-spoofing tools rarely bother to forge.
 */
public class HardwareProfileCollector extends BaseCollector {

    public HardwareProfileCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "hardware_profile";
    }

    @Override
    protected void collect(CollectorResult result) {
        collectMemory(result);
        collectDisplay(result);
        collectCamera(result);
        collectBattery(result);
        collectSystemLibraries(result);
    }

    private void collectMemory(CollectorResult result) {
        try {
            ActivityManager manager =
                    (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            if (manager == null) return;
            ActivityManager.MemoryInfo info = new ActivityManager.MemoryInfo();
            manager.getMemoryInfo(info);
            // Rounded to 256MB so normal runtime variation does not destabilise
            // the fingerprint while still separating device tiers.
            long totalMb = info.totalMem / (1024 * 1024);
            result.addValue("ram_total_mb_bucket",
                    String.valueOf((totalMb / 256) * 256));
            result.addValue("low_ram_device", String.valueOf(manager.isLowRamDevice()));
        } catch (Exception e) {
            CLog.e("Memory collection failed", e);
        }
    }

    private void collectDisplay(CollectorResult result) {
        try {
            WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
            if (wm == null) return;
            Display display = wm.getDefaultDisplay();
            if (display == null) return;
            result.addValue("refresh_rate",
                    String.format(Locale.ROOT, "%.2f", display.getRefreshRate()));
            result.addValue("hdr_supported", String.valueOf(display.isHdr()));
            result.addValue("wide_color_gamut", String.valueOf(display.isWideColorGamut()));

            Display.Mode[] modes = display.getSupportedModes();
            if (modes != null && modes.length > 0) {
                List<String> modeList = new ArrayList<>(modes.length);
                for (Display.Mode mode : modes) {
                    modeList.add(String.format(Locale.ROOT, "%dx%d@%.0f",
                            mode.getPhysicalWidth(), mode.getPhysicalHeight(),
                            mode.getRefreshRate()));
                }
                java.util.Collections.sort(modeList);
                result.addValue("display_modes", String.join(",", modeList));
            }
            Display.HdrCapabilities hdr = display.getHdrCapabilities();
            if (hdr != null && hdr.getSupportedHdrTypes().length > 0) {
                int[] types = hdr.getSupportedHdrTypes();
                StringBuilder joined = new StringBuilder();
                for (int i = 0; i < types.length; i++) {
                    if (i > 0) joined.append(',');
                    joined.append(types[i]);
                }
                result.addValue("hdr_types", joined.toString());
            }
        } catch (Exception e) {
            CLog.e("Display collection failed", e);
        }
    }

    private void collectCamera(CollectorResult result) {
        try {
            CameraManager manager =
                    (CameraManager) context.getSystemService(Context.CAMERA_SERVICE);
            if (manager == null) return;
            String[] ids = manager.getCameraIdList();
            result.addValue("camera_count", String.valueOf(ids.length));
            List<String> profiles = new ArrayList<>();
            for (String id : ids) {
                try {
                    CameraCharacteristics chars = manager.getCameraCharacteristics(id);
                    StringBuilder profile = new StringBuilder();
                    Integer facing = chars.get(CameraCharacteristics.LENS_FACING);
                    Integer level = chars.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL);
                    SizeF physical = chars.get(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE);
                    Size pixelArray = chars.get(
                            CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE);
                    float[] focal = chars.get(
                            CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS);
                    float[] apertures = chars.get(
                            CameraCharacteristics.LENS_INFO_AVAILABLE_APERTURES);
                    android.util.Range<Integer> iso = chars.get(
                            CameraCharacteristics.SENSOR_INFO_SENSITIVITY_RANGE);

                    profile.append("f=").append(facing == null ? "?" : facing);
                    profile.append(";hw=").append(level == null ? "?" : level);
                    if (physical != null) {
                        profile.append(String.format(Locale.ROOT, ";sz=%.3fx%.3f",
                                physical.getWidth(), physical.getHeight()));
                    }
                    if (pixelArray != null) {
                        profile.append(";px=").append(pixelArray.getWidth())
                                .append('x').append(pixelArray.getHeight());
                    }
                    if (focal != null && focal.length > 0) {
                        profile.append(";fl=").append(Arrays.toString(focal));
                    }
                    if (apertures != null && apertures.length > 0) {
                        profile.append(";ap=").append(Arrays.toString(apertures));
                    }
                    if (iso != null) {
                        profile.append(";iso=").append(iso.getLower())
                                .append('-').append(iso.getUpper());
                    }
                    profiles.add(profile.toString());
                } catch (Exception ignored) {
                    // A single unavailable camera must not void the others.
                }
            }
            if (!profiles.isEmpty()) {
                java.util.Collections.sort(profiles);
                result.addValue("camera_profile_hash",
                        GpuInfoCollector.sha256(String.join("||", profiles)));
                result.addValue("camera_profiles", String.join("||", profiles));
            }
            PackageManager pm = context.getPackageManager();
            result.addValue("camera_feature", String.valueOf(
                    pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)));
            result.addValue("camera_flash_feature", String.valueOf(
                    pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_FLASH)));
        } catch (Exception e) {
            CLog.e("Camera collection failed", e);
        }
    }

    private void collectBattery(CollectorResult result) {
        try {
            BatteryManager manager =
                    (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
            if (manager != null) {
                long chargeCounter = manager.getLongProperty(
                        BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER);
                if (chargeCounter > 0) {
                    result.addValue("battery_charge_counter_bucket",
                            String.valueOf((chargeCounter / 100000) * 100000));
                }
            }
            Intent battery = context.registerReceiver(
                    null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (battery == null) return;
            String technology = battery.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY);
            if (technology != null && !technology.isBlank()) {
                result.addValue("battery_technology", technology);
            }
            int voltage = battery.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1);
            if (voltage > 0) {
                result.addValue("battery_voltage_present", "true");
            }
            result.addValue("battery_present", String.valueOf(
                    battery.getBooleanExtra(BatteryManager.EXTRA_PRESENT, false)));
        } catch (Exception e) {
            CLog.e("Battery collection failed", e);
        }
    }

    /** The shared-library set differs by OEM and Android build. Hashed for size. */
    private void collectSystemLibraries(CollectorResult result) {
        try {
            String[] libraries = context.getPackageManager().getSystemSharedLibraryNames();
            if (libraries == null || libraries.length == 0) return;
            String[] sorted = libraries.clone();
            Arrays.sort(sorted);
            result.addValue("system_library_count", String.valueOf(sorted.length));
            result.addValue("system_library_hash",
                    GpuInfoCollector.sha256(String.join(",", sorted)));
        } catch (Exception e) {
            CLog.e("System library collection failed", e);
        }
    }
}
