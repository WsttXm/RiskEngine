package com.wsttxm.riskenginesdk.model;

import com.wsttxm.riskenginesdk.FingerprintStability;
import com.wsttxm.riskenginesdk.FingerprintVersion;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A layered device fingerprint identifier.
 *
 * Each layer is exposed separately so callers can distinguish "same device,
 * new firmware" from "different device". Per-domain hardware bucket digests
 * accompany the layer hashes so transient single-collector failures do not
 * trigger false hardware-change detections.
 */
public final class FingerprintId {
    private static final String[] CORE_PHYSICAL_BUCKETS = {"gpu", "cpu", "sensor"};

    private final String compositeId;
    private final String hardwareId;
    private final String systemId;
    private final String volatileId;
    private final int hardwareFieldsPresent;
    private final int hardwareFieldsTotal;
    private final int systemFieldsPresent;
    private final int systemFieldsTotal;
    private final List<String> contributingFields;
    private final Map<String, String> hardwareBucketDigests;
    private final FingerprintVersion version;
    private final FingerprintStability stability;

    public FingerprintId(String compositeId, String hardwareId, String systemId,
                         String volatileId, int hardwareFieldsPresent,
                         int hardwareFieldsTotal, int systemFieldsPresent,
                         int systemFieldsTotal, List<String> contributingFields) {
        this(compositeId, hardwareId, systemId, volatileId,
                hardwareFieldsPresent, hardwareFieldsTotal,
                systemFieldsPresent, systemFieldsTotal,
                contributingFields, Collections.emptyMap(),
                FingerprintVersion.V1, FingerprintStability.OPTIMAL);
    }

    public FingerprintId(String compositeId, String hardwareId, String systemId,
                         String volatileId, int hardwareFieldsPresent,
                         int hardwareFieldsTotal, int systemFieldsPresent,
                         int systemFieldsTotal, List<String> contributingFields,
                         Map<String, String> hardwareBucketDigests) {
        this(compositeId, hardwareId, systemId, volatileId,
                hardwareFieldsPresent, hardwareFieldsTotal,
                systemFieldsPresent, systemFieldsTotal,
                contributingFields, hardwareBucketDigests,
                FingerprintVersion.V1, FingerprintStability.OPTIMAL);
    }

    public FingerprintId(String compositeId, String hardwareId, String systemId,
                         String volatileId, int hardwareFieldsPresent,
                         int hardwareFieldsTotal, int systemFieldsPresent,
                         int systemFieldsTotal, List<String> contributingFields,
                         Map<String, String> hardwareBucketDigests,
                         FingerprintVersion version,
                         FingerprintStability stability) {
        this.compositeId = compositeId == null ? "" : compositeId;
        this.hardwareId = hardwareId == null ? "" : hardwareId;
        this.systemId = systemId == null ? "" : systemId;
        this.volatileId = volatileId == null ? "" : volatileId;
        this.hardwareFieldsPresent = hardwareFieldsPresent;
        this.hardwareFieldsTotal = hardwareFieldsTotal;
        this.systemFieldsPresent = systemFieldsPresent;
        this.systemFieldsTotal = systemFieldsTotal;
        this.contributingFields = contributingFields == null
                ? Collections.emptyList()
                : List.copyOf(contributingFields);
        this.hardwareBucketDigests = hardwareBucketDigests == null || hardwareBucketDigests.isEmpty()
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(hardwareBucketDigests));
        this.version = version == null ? FingerprintVersion.V1 : version.resolve();
        this.stability = stability == null ? FingerprintStability.OPTIMAL : stability;
    }

    public String getCompositeId() { return compositeId; }
    public String getHardwareId() { return hardwareId; }
    public String getSystemId() { return systemId; }
    public String getVolatileId() { return volatileId; }
    public int getHardwareFieldsPresent() { return hardwareFieldsPresent; }
    public int getHardwareFieldsTotal() { return hardwareFieldsTotal; }
    public int getSystemFieldsPresent() { return systemFieldsPresent; }
    public int getSystemFieldsTotal() { return systemFieldsTotal; }
    public List<String> getContributingFields() { return contributingFields; }
    public Map<String, String> getHardwareBucketDigests() { return hardwareBucketDigests; }
    public FingerprintVersion getVersion() { return version; }
    public FingerprintStability getStability() { return stability; }

    /** Percentage of hardware-layer inputs that were actually collected. */
    public int getHardwareCoveragePercent() {
        return hardwareFieldsTotal == 0
                ? 0 : (hardwareFieldsPresent * 100) / hardwareFieldsTotal;
    }

    /** Counts present core physical hardware buckets among {@code gpu}, {@code cpu}, {@code sensor}. */
    public int getCorePhysicalBucketCount() {
        int count = 0;
        for (String bucket : CORE_PHYSICAL_BUCKETS) {
            String digest = hardwareBucketDigests.get(bucket);
            if (digest != null && !digest.isEmpty()) {
                count++;
            }
        }
        return count;
    }

    /**
     * True when enough hardware inputs were collected for the hardware layer to
     * be worth persisting or comparing: requires non-empty {@code hardwareId},
     * coverage &gt;= 50%, AND at least 2 of the 3 core physical buckets
     * ({@code gpu}, {@code cpu}, {@code sensor}).
     */
    public boolean isHardwareLayerReliable() {
        return !hardwareId.isEmpty()
                && getHardwareCoveragePercent() >= 50
                && getCorePhysicalBucketCount() >= 2;
    }
}
