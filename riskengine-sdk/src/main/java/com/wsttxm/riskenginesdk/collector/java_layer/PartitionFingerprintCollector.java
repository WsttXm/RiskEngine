package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.CollectorResult;

/**
 * Reads the per-partition build fingerprints plus verified-boot state.
 *
 * Device-spoofing tools typically rewrite ro.build.fingerprint and the Build
 * fields derived from it, but leave the vendor, odm and bootimage copies alone
 * because nothing user-visible reads them. Collecting all of them turns a
 * single spoofable value into a set that must be forged consistently. The
 * verified-boot and AVB values are recorded alongside because a modified device
 * cannot produce a locked, green boot state.
 */
public class PartitionFingerprintCollector extends BaseCollector {
    private final SignalSnapshot signals;

    public PartitionFingerprintCollector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "partition_fingerprints";
    }

    @Override
    protected void collect(CollectorResult result) {
        for (String property : DetectionLists.PARTITION_FINGERPRINT_PROPERTIES) {
            SignalResult<String> value = signals.getSystemProperty(property);
            if (value.isSuccess() && value.getValue() != null
                    && !value.getValue().isBlank()) {
                result.addValue(property, value.getValue().trim());
            }
        }
        for (String property : new String[]{
                "ro.boot.vbmeta.digest", "ro.boot.verifiedbootstate",
                "ro.boot.flash.locked", "ro.oem_unlock_supported",
                "ro.build.date.utc", "ro.build.version.incremental",
                "ro.build.tags", "ro.build.characteristics"}) {
            SignalResult<String> value = signals.getSystemProperty(property);
            if (value.isSuccess() && value.getValue() != null
                    && !value.getValue().isBlank()) {
                result.addValue(property, value.getValue().trim());
            }
        }
    }
}
