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
 * The previous DeviceFingerprint was a plain map with no ID at all, so callers
 * had nothing stable to key on. Three layers are hashed separately rather than
 * producing one digest, because a single digest changes completely when any one
 * input drifts and gives no way to tell a returning device from a new one.
 *
 * hardware  hardware-bound values: GPU, sensors, camera, CPU topology, DRM.
 *           Survives reinstall, app data clear and factory reset.
 * system    OS build identity: partition fingerprints, kernel, security patch.
 *           Changes only on firmware update or reflash.
 * volatile  resettable identifiers: ANDROID_ID, boot id.
 *
 * Similarity between two IDs is then computable per layer: matching hardware
 * with a changed system layer is one device after an update, whereas a changed
 * hardware layer is a different device.
 */
public final class FingerprintIdBuilder {

    /** Fields per layer, in a fixed order so the digest is reproducible. */
    private static final String[][] HARDWARE_FIELDS = {
            {"gpu_info", "vendor"},
            {"gpu_info", "renderer"},
            {"gpu_info", "extensions_hash"},
            {"gpu_info", "max_texture_size"},
            {"sensor_fingerprint", "tuple_hash"},
            {"sensor_fingerprint", "vendor_hash"},
            {"hardware_profile", "camera_profile_hash"},
            {"hardware_profile", "ram_total_mb_bucket"},
            {"hardware_profile", "display_modes"},
            {"hardware_profile", "battery_technology"},
            {"cpu_topology", "core_distribution"},
            {"cpu_topology", "freq_ranges"},
            {"cpu_topology", "soc_model"},
            {"cpu_topology", "soc_manufacturer"},
            {"drm_id", "widevine_hash"},
            {"screen_info", "xdpi"},
            {"screen_info", "ydpi"},
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
    };

    private FingerprintIdBuilder() {}

    public static FingerprintId build(DeviceFingerprint fingerprint, String salt) {
        Map<String, String> hardware = extract(fingerprint, HARDWARE_FIELDS);
        Map<String, String> system = extract(fingerprint, SYSTEM_FIELDS);
        Map<String, String> volatileValues = extract(fingerprint, VOLATILE_FIELDS);

        String hardwareId = digest(hardware, salt, "hw");
        String systemId = digest(system, salt, "sys");
        String volatileId = digest(volatileValues, salt, "vol");

        // The composite is derived from the layer digests, not from the raw
        // values again, so a layer can be recomputed independently.
        String composite = hashString(
                salt + "|composite|" + hardwareId + "|" + systemId);

        return new FingerprintId(composite, hardwareId, systemId, volatileId,
                hardware.size(), HARDWARE_FIELDS.length,
                system.size(), SYSTEM_FIELDS.length,
                new ArrayList<>(hardware.keySet()));
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

    /**
     * Digests one layer. Absent fields are skipped rather than substituted with
     * a placeholder, and the contributing key list is recorded on the result so
     * a caller can tell a thin ID from a complete one instead of treating a
     * mostly-empty digest as equally trustworthy.
     */
    private static String digest(Map<String, String> values, String salt, String label) {
        if (values.isEmpty()) return "";
        List<String> parts = new ArrayList<>(values.size());
        for (Map.Entry<String, String> entry : values.entrySet()) {
            parts.add(entry.getKey() + "=" + entry.getValue());
        }
        Collections.sort(parts);
        return hashString(salt + "|" + label + "|" + String.join("", parts));
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
