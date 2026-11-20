package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.FingerprintId;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Composes a layered device fingerprint ID from collected results.
 *
 * Hardware inputs are filtered to exclude privacy-toggle-dependent fields
 * (Widevine DRM), foldable/resolution-dependent display metrics, dynamic
 * accessories, and per-core hotplug-sensitive frequency arrays. Independent
 * per-domain bucket digests allow intersection-based continuity comparison so
 * one transiently missing collector never triggers a false HARDWARE_CHANGED.
 */
public final class FingerprintIdBuilder {

    /**
     * Hardware-layer inputs grouped by physical domain: {bucket, collector, key}.
     */
    private static final String[][] HARDWARE_FIELDS = {
            {"gpu", "gpu_info", "vendor"},
            {"gpu", "gpu_info", "renderer"},
            {"gpu", "gpu_info", "extensions_hash"},
            {"gpu", "gpu_info", "max_texture_size"},
            {"sensor", "sensor_fingerprint", "tuple_hash"},
            {"sensor", "sensor_fingerprint", "vendor_hash"},
            {"camera", "hardware_profile", "camera_profile_hash"},
            {"cpu", "cpu_topology", "core_distribution"},
            {"cpu", "cpu_topology", "freq_clusters"},
            {"cpu", "cpu_topology", "soc_model"},
            {"cpu", "cpu_topology", "soc_manufacturer"},
            {"memory_battery", "hardware_profile", "ram_total_mb_bucket"},
            {"memory_battery", "hardware_profile", "battery_technology"},
    };

    private static final String[][] SYSTEM_FIELDS = {
            {"partition_fingerprints", "ro.build.fingerprint"},
            {"partition_fingerprints", "ro.vendor.build.fingerprint"},
            {"partition_fingerprints", "ro.odm.build.fingerprint"},
            {"partition_fingerprints", "ro.bootimage.build.fingerprint"},
            {"partition_fingerprints", "ro.build.date.utc"},
            {"partition_fingerprints", "ro.boot.vbmeta.digest"},
            {"build_props", "fingerprint"},
            {"build_props", "security_patch"},
            {"build_props", "bootloader"},
            {"kernel_info", "native"},
            {"hardware_profile", "system_library_hash"},
    };

    private static final String[][] VOLATILE_FIELDS = {
            {"android_id", "settings_api"},
            {"boot_id", "native_hash"},
            {"drm_id", "widevine_hash"},
    };

    private FingerprintIdBuilder() {}

    public static FingerprintId build(DeviceFingerprint fingerprint, String salt) {
        Map<String, String> hardware = new LinkedHashMap<>();
        Map<String, Map<String, String>> buckets = new LinkedHashMap<>();
        Map<String, CollectorResult> results = fingerprint.getResults();

        for (String[] spec : HARDWARE_FIELDS) {
            String bucket = spec[0];
            String collector = spec[1];
            String key = spec[2];
            CollectorResult result = results.get(collector);
            if (result == null || result.getStatus() != CollectorResult.Status.SUCCESS) {
                continue;
            }
            String value = result.getValues().get(key);
            if (value == null || value.isBlank()) continue;
            String compositeKey = collector + "." + key;
            String trimmed = value.trim();
            hardware.put(compositeKey, trimmed);
            buckets.computeIfAbsent(bucket, k -> new LinkedHashMap<>())
                    .put(compositeKey, trimmed);
        }

        Map<String, String> bucketDigests = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, String>> entry : buckets.entrySet()) {
            String d = digest(entry.getValue(), salt, "hw:" + entry.getKey());
            if (!d.isEmpty()) {
                bucketDigests.put(entry.getKey(), d.substring(0, Math.min(16, d.length())));
            }
        }

        Map<String, String> system = extract(fingerprint, SYSTEM_FIELDS);
        Map<String, String> volatileValues = extract(fingerprint, VOLATILE_FIELDS);

        String hardwareId = digest(hardware, salt, "hw");
        String systemId = digest(system, salt, "sys");
        String volatileId = digest(volatileValues, salt, "vol");

        // Never fabricate a composite ID when both stable layers are empty.
        String composite = (hardwareId.isEmpty() && systemId.isEmpty())
                ? ""
                : hashString(salt + "|composite|" + hardwareId + "|" + systemId);

        return new FingerprintId(composite, hardwareId, systemId, volatileId,
                hardware.size(), HARDWARE_FIELDS.length,
                system.size(), SYSTEM_FIELDS.length,
                new ArrayList<>(hardware.keySet()),
                bucketDigests);
    }

    private static Map<String, String> extract(DeviceFingerprint fingerprint,
                                               String[][] fields) {
        Map<String, String> present = new LinkedHashMap<>();
        Map<String, CollectorResult> results = fingerprint.getResults();
        for (String[] field : fields) {
            CollectorResult result = results.get(field[0]);
            if (result == null || result.getStatus() != CollectorResult.Status.SUCCESS) {
                continue;
            }
            String value = result.getValues().get(field[1]);
            if (value == null || value.isBlank()) continue;
            present.put(field[0] + "." + field[1], value.trim());
        }
        return present;
    }

    private static String digest(Map<String, String> values, String salt, String label) {
        if (values.isEmpty()) return "";
        List<String> parts = new ArrayList<>(values.size());
        for (Map.Entry<String, String> entry : values.entrySet()) {
            parts.add(entry.getKey() + "=" + entry.getValue());
        }
        Collections.sort(parts);
        return hashString(salt + "|" + label + "|" + String.join("\u001f", parts));
    }

    private static String hashString(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                hex.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                hex.append(Character.forDigit(item & 0x0f, 16));
            }
            return hex.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
