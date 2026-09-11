package com.wsttxm.riskenginesdk.model;

import java.util.Collections;
import java.util.List;

/**
 * A layered device fingerprint identifier.
 *
 * Each layer is exposed separately so callers can distinguish "same device,
 * new firmware" from "different device". Coverage counts accompany the digests
 * because an ID built from three surviving fields must not be treated with the
 * same confidence as one built from seventeen.
 */
public final class FingerprintId {
    private final String compositeId;
    private final String hardwareId;
    private final String systemId;
    private final String volatileId;
    private final int hardwareFieldsPresent;
    private final int hardwareFieldsTotal;
    private final int systemFieldsPresent;
    private final int systemFieldsTotal;
    private final List<String> contributingFields;

    public FingerprintId(String compositeId, String hardwareId, String systemId,
                         String volatileId, int hardwareFieldsPresent,
                         int hardwareFieldsTotal, int systemFieldsPresent,
                         int systemFieldsTotal, List<String> contributingFields) {
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

    /** Percentage of hardware-layer inputs that were actually collected. */
    public int getHardwareCoveragePercent() {
        return hardwareFieldsTotal == 0
                ? 0 : (hardwareFieldsPresent * 100) / hardwareFieldsTotal;
    }

    /**
     * True when enough hardware inputs were collected for the hardware layer to
     * be worth persisting or comparing. Below this a match means little.
     */
    public boolean isHardwareLayerReliable() {
        return !hardwareId.isEmpty() && getHardwareCoveragePercent() >= 50;
    }
}
