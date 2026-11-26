package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.FingerprintHasher;
import com.wsttxm.riskenginesdk.FingerprintStability;
import com.wsttxm.riskenginesdk.FingerprintVersion;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.util.CpuInfoParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Composes a layered device fingerprint ID from collected results.
 *
 * <p>Supports explicit {@link FingerprintVersion} ({@code V1} bit-exact compatibility and
 * {@code V2} declarative stability-tiered composition), {@link FingerprintStability},
 * and pluggable {@link FingerprintHasher} (default UTF-8 SHA-256).
 */
public final class FingerprintIdBuilder {

    public enum Layer {
        HARDWARE,
        SYSTEM,
        VOLATILE
    }

    /** Declarative signal descriptor participating in fingerprint computation. */
    public static final class SignalSpec {
        private final Layer layer;
        private final String bucket;
        private final String collector;
        private final String key;
        private final FingerprintVersion addedIn;
        private final FingerprintVersion removedIn;
        private final FingerprintStability stability;

        public SignalSpec(Layer layer,
                          String bucket,
                          String collector,
                          String key,
                          FingerprintVersion addedIn,
                          FingerprintVersion removedIn,
                          FingerprintStability stability) {
            this.layer = layer;
            this.bucket = bucket;
            this.collector = collector;
            this.key = key;
            this.addedIn = addedIn.resolve();
            this.removedIn = removedIn == null ? null : removedIn.resolve();
            this.stability = stability;
        }

        public Layer getLayer() { return layer; }
        public String getBucket() { return bucket; }
        public String getCollector() { return collector; }
        public String getKey() { return key; }
        public FingerprintVersion getAddedIn() { return addedIn; }
        public FingerprintVersion getRemovedIn() { return removedIn; }
        public FingerprintStability getStability() { return stability; }
        public String getCompositeKey() { return collector + "." + key; }

        public boolean activeIn(FingerprintVersion version) {
            FingerprintVersion resolved = version == null ? FingerprintVersion.V1 : version.resolve();
            if (resolved.getCode() < addedIn.getCode()) {
                return false;
            }
            return removedIn == null || resolved.getCode() < removedIn.getCode();
        }
    }

    private static final List<SignalSpec> ALL_SPECS;

    static {
        List<SignalSpec> specs = new ArrayList<>();
        // V1 Hardware specs (13 fields across 5 physical buckets)
        addHw(specs, "gpu", "gpu_info", "vendor", FingerprintVersion.V1);
        addHw(specs, "gpu", "gpu_info", "renderer", FingerprintVersion.V1);
        addHw(specs, "gpu", "gpu_info", "extensions_hash", FingerprintVersion.V1);
        addHw(specs, "gpu", "gpu_info", "max_texture_size", FingerprintVersion.V1);
        addHw(specs, "sensor", "sensor_fingerprint", "tuple_hash", FingerprintVersion.V1);
        addHw(specs, "sensor", "sensor_fingerprint", "vendor_hash", FingerprintVersion.V1);
        addHw(specs, "camera", "hardware_profile", "camera_profile_hash", FingerprintVersion.V1);
        addHw(specs, "cpu", "cpu_topology", "core_distribution", FingerprintVersion.V1);
        addHw(specs, "cpu", "cpu_topology", "freq_clusters", FingerprintVersion.V1);
        addHw(specs, "cpu", "cpu_topology", "soc_model", FingerprintVersion.V1);
        addHw(specs, "cpu", "cpu_topology", "soc_manufacturer", FingerprintVersion.V1);
        addHw(specs, "memory_battery", "hardware_profile", "ram_total_mb_bucket", FingerprintVersion.V1);
        addHw(specs, "memory_battery", "hardware_profile", "battery_technology", FingerprintVersion.V1);

        // V1 System specs (11 fields)
        addSys(specs, "partition_fingerprints", "ro.build.fingerprint", FingerprintVersion.V1);
        addSys(specs, "partition_fingerprints", "ro.vendor.build.fingerprint", FingerprintVersion.V1);
        addSys(specs, "partition_fingerprints", "ro.odm.build.fingerprint", FingerprintVersion.V1);
        addSys(specs, "partition_fingerprints", "ro.bootimage.build.fingerprint", FingerprintVersion.V1);
        addSys(specs, "partition_fingerprints", "ro.build.date.utc", FingerprintVersion.V1);
        addSys(specs, "partition_fingerprints", "ro.boot.vbmeta.digest", FingerprintVersion.V1);
        addSys(specs, "build_props", "fingerprint", FingerprintVersion.V1);
        addSys(specs, "build_props", "security_patch", FingerprintVersion.V1);
        addSys(specs, "build_props", "bootloader", FingerprintVersion.V1);
        addSys(specs, "kernel_info", "native", FingerprintVersion.V1);
        addSys(specs, "hardware_profile", "system_library_hash", FingerprintVersion.V1);

        // V2 Zero-permission high-entropy & normalized CPU signals (OPTIMAL stability)
        addSys(specs, "codec_info", "codec_matrix_hash", FingerprintVersion.V2);
        addSys(specs, "input_devices", "input_device_hash", FingerprintVersion.V2);
        addSys(specs, "security_posture", "providers_hash", FingerprintVersion.V2);
        addSys(specs, "cpu_info", "raw", FingerprintVersion.V2);

        // V1 Volatile specs (3 fields, UNIQUE stability)
        addVol(specs, "android_id", "settings_api", FingerprintVersion.V1);
        addVol(specs, "boot_id", "native_hash", FingerprintVersion.V1);
        addVol(specs, "drm_id", "widevine_hash", FingerprintVersion.V1);

        ALL_SPECS = Collections.unmodifiableList(specs);
    }

    private static void addHw(List<SignalSpec> specs, String bucket, String collector,
                              String key, FingerprintVersion addedIn) {
        specs.add(new SignalSpec(Layer.HARDWARE, bucket, collector, key,
                addedIn, null, FingerprintStability.STABLE));
    }

    private static void addSys(List<SignalSpec> specs, String collector, String key,
                               FingerprintVersion addedIn) {
        specs.add(new SignalSpec(Layer.SYSTEM, null, collector, key,
                addedIn, null, FingerprintStability.OPTIMAL));
    }

    private static void addVol(List<SignalSpec> specs, String collector, String key,
                               FingerprintVersion addedIn) {
        specs.add(new SignalSpec(Layer.VOLATILE, null, collector, key,
                addedIn, null, FingerprintStability.UNIQUE));
    }

    private FingerprintIdBuilder() {}

    /** Returns declarative signal specifications active for the given version and stability. */
    public static List<SignalSpec> getSignalSpecs(FingerprintVersion version,
                                                  FingerprintStability stability) {
        FingerprintVersion resolved = version == null ? FingerprintVersion.V1 : version.resolve();
        FingerprintStability targetStability = stability == null
                ? FingerprintStability.OPTIMAL
                : stability;
        List<SignalSpec> active = new ArrayList<>();
        for (SignalSpec spec : ALL_SPECS) {
            if (!spec.activeIn(resolved)) {
                continue;
            }
            if (resolved == FingerprintVersion.V1 || targetStability.includes(spec.getStability())) {
                active.add(spec);
            }
        }
        return Collections.unmodifiableList(active);
    }

    /**
     * Legacy v1.x entry point. Guaranteed 100% bit-identical to Phase 0 {@code V1} output.
     */
    public static FingerprintId build(DeviceFingerprint fingerprint, String salt) {
        return build(fingerprint, salt, FingerprintVersion.V1,
                FingerprintStability.OPTIMAL, FingerprintHasher.SHA256, null);
    }

    public static FingerprintId build(DeviceFingerprint fingerprint,
                                      String salt,
                                      FingerprintVersion version,
                                      FingerprintStability stability,
                                      FingerprintHasher hasher) {
        return build(fingerprint, salt, version, stability, hasher, null);
    }

    public static FingerprintId build(DeviceFingerprint fingerprint,
                                      String salt,
                                      FingerprintVersion version,
                                      FingerprintStability stability,
                                      FingerprintHasher hasher,
                                      Set<String> allowedSignalKeys) {
        FingerprintVersion resolvedVersion = version == null
                ? FingerprintVersion.V1
                : version.resolve();
        FingerprintStability effectiveStability = stability == null
                ? FingerprintStability.OPTIMAL
                : stability;
        FingerprintHasher effectiveHasher = hasher == null
                ? FingerprintHasher.SHA256
                : hasher;

        if (resolvedVersion == FingerprintVersion.V1) {
            return buildV1(fingerprint, salt, effectiveHasher, allowedSignalKeys);
        }
        return buildV2(fingerprint, salt, effectiveStability, effectiveHasher, allowedSignalKeys);
    }

    private static FingerprintId buildV1(DeviceFingerprint fingerprint,
                                         String salt,
                                         FingerprintHasher hasher,
                                         Set<String> allowedSignalKeys) {
        Map<String, String> hardware = new LinkedHashMap<>();
        Map<String, Map<String, String>> buckets = new LinkedHashMap<>();
        Map<String, String> system = new LinkedHashMap<>();
        Map<String, String> volatileValues = new LinkedHashMap<>();
        int hwTotal = 0;
        int sysTotal = 0;

        Map<String, CollectorResult> results = fingerprint == null
                ? Collections.emptyMap()
                : fingerprint.getResults();

        for (SignalSpec spec : ALL_SPECS) {
            if (!spec.activeIn(FingerprintVersion.V1)) {
                continue;
            }
            String compositeKey = spec.getCompositeKey();
            if (allowedSignalKeys != null && !allowedSignalKeys.contains(compositeKey)) {
                continue;
            }
            if (spec.getLayer() == Layer.HARDWARE) {
                hwTotal++;
            } else if (spec.getLayer() == Layer.SYSTEM) {
                sysTotal++;
            }

            String value = extractRawValue(results, spec.getCollector(), spec.getKey());
            if (value == null) {
                continue;
            }
            if (spec.getLayer() == Layer.HARDWARE) {
                hardware.put(compositeKey, value);
                buckets.computeIfAbsent(spec.getBucket(), k -> new LinkedHashMap<>())
                        .put(compositeKey, value);
            } else if (spec.getLayer() == Layer.SYSTEM) {
                system.put(compositeKey, value);
            } else {
                volatileValues.put(compositeKey, value);
            }
        }

        Map<String, String> bucketDigests = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, String>> entry : buckets.entrySet()) {
            String d = digest(entry.getValue(), salt, "hw:" + entry.getKey(), hasher);
            if (!d.isEmpty()) {
                bucketDigests.put(entry.getKey(), d.substring(0, Math.min(16, d.length())));
            }
        }

        String hardwareId = digest(hardware, salt, "hw", hasher);
        String systemId = digest(system, salt, "sys", hasher);
        String volatileId = digest(volatileValues, salt, "vol", hasher);

        // Never fabricate a composite ID when both stable layers are empty.
        String composite = (hardwareId.isEmpty() && systemId.isEmpty())
                ? ""
                : safeHash(hasher, salt + "|composite|" + hardwareId + "|" + systemId);

        return new FingerprintId(composite, hardwareId, systemId, volatileId,
                hardware.size(), hwTotal,
                system.size(), sysTotal,
                new ArrayList<>(hardware.keySet()),
                bucketDigests,
                FingerprintVersion.V1,
                FingerprintStability.OPTIMAL);
    }

    private static FingerprintId buildV2(DeviceFingerprint fingerprint,
                                         String salt,
                                         FingerprintStability stability,
                                         FingerprintHasher hasher,
                                         Set<String> allowedSignalKeys) {
        Map<String, String> hardware = new LinkedHashMap<>();
        Map<String, Map<String, String>> buckets = new LinkedHashMap<>();
        Map<String, String> system = new LinkedHashMap<>();
        Map<String, String> volatileValues = new LinkedHashMap<>();
        int hwTotal = 0;
        int sysTotal = 0;

        Map<String, CollectorResult> results = fingerprint == null
                ? Collections.emptyMap()
                : fingerprint.getResults();

        for (SignalSpec spec : ALL_SPECS) {
            if (!spec.activeIn(FingerprintVersion.V2)) {
                continue;
            }
            if (!stability.includes(spec.getStability())) {
                continue;
            }
            String compositeKey = spec.getCompositeKey();
            if (allowedSignalKeys != null && !allowedSignalKeys.contains(compositeKey)) {
                continue;
            }
            if (spec.getLayer() == Layer.HARDWARE) {
                hwTotal++;
            } else if (spec.getLayer() == Layer.SYSTEM) {
                sysTotal++;
            }

            String value = extractRawValue(results, spec.getCollector(), spec.getKey());
            if (value == null) {
                continue;
            }
            if ("cpu_info".equals(spec.getCollector()) && "raw".equals(spec.getKey())) {
                value = CpuInfoParser.parse(value).toStableFingerprintString();
                if (value.isEmpty()) {
                    continue;
                }
            }
            if (spec.getLayer() == Layer.HARDWARE) {
                hardware.put(compositeKey, value);
                buckets.computeIfAbsent(spec.getBucket(), k -> new LinkedHashMap<>())
                        .put(compositeKey, value);
            } else if (spec.getLayer() == Layer.SYSTEM) {
                system.put(compositeKey, value);
            } else {
                volatileValues.put(compositeKey, value);
            }
        }

        Map<String, String> bucketDigests = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, String>> entry : buckets.entrySet()) {
            String d = digest(entry.getValue(), salt, "v2|hw:" + entry.getKey(), hasher);
            if (!d.isEmpty()) {
                bucketDigests.put(entry.getKey(), d.substring(0, Math.min(16, d.length())));
            }
        }

        String hardwareId = digest(hardware, salt, "v2|hw", hasher);
        String systemId = digest(system, salt, "v2|sys", hasher);
        String volatileId = digest(volatileValues, salt, "v2|vol", hasher);

        String composite;
        if (stability == FingerprintStability.STABLE) {
            composite = hardwareId.isEmpty()
                    ? ""
                    : safeHash(hasher, salt + "|v2|composite|STABLE|" + hardwareId);
        } else if (stability == FingerprintStability.OPTIMAL) {
            composite = (hardwareId.isEmpty() && systemId.isEmpty())
                    ? ""
                    : safeHash(hasher, salt + "|v2|composite|OPTIMAL|" + hardwareId + "|" + systemId);
        } else {
            composite = (hardwareId.isEmpty() && systemId.isEmpty() && volatileId.isEmpty())
                    ? ""
                    : safeHash(hasher, salt + "|v2|composite|UNIQUE|" + hardwareId + "|"
                    + systemId + "|" + volatileId);
        }

        List<String> contributing = new ArrayList<>(hardware.keySet());
        if (stability != FingerprintStability.STABLE) {
            contributing.addAll(system.keySet());
        }
        if (stability == FingerprintStability.UNIQUE) {
            contributing.addAll(volatileValues.keySet());
        }

        return new FingerprintId(composite, hardwareId, systemId, volatileId,
                hardware.size(), hwTotal,
                system.size(), sysTotal,
                contributing,
                bucketDigests,
                FingerprintVersion.V2,
                stability);
    }

    private static String extractRawValue(Map<String, CollectorResult> results,
                                          String collector,
                                          String key) {
        CollectorResult result = results.get(collector);
        if (result == null || result.getStatus() != CollectorResult.Status.SUCCESS) {
            return null;
        }
        String value = result.getValues().get(key);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private static String digest(Map<String, String> values,
                                 String salt,
                                 String label,
                                 FingerprintHasher hasher) {
        if (values.isEmpty()) return "";
        List<String> parts = new ArrayList<>(values.size());
        for (Map.Entry<String, String> entry : values.entrySet()) {
            parts.add(entry.getKey() + "=" + entry.getValue());
        }
        Collections.sort(parts);
        return safeHash(hasher, salt + "|" + label + "|" + String.join("\u001f", parts));
    }

    private static String safeHash(FingerprintHasher hasher, String payload) {
        try {
            String hashed = hasher.hash(payload);
            return hashed == null ? "" : hashed;
        } catch (Exception e) {
            return "";
        }
    }
}
