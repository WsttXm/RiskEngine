package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.FingerprintIdBuilder;
import com.wsttxm.riskenginesdk.core.FingerprintStore;
import com.wsttxm.riskenginesdk.core.HookEvidenceClassifier;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.FingerprintId;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FingerprintContinuityTest {

    @Test
    public void emptyFingerprintProducesEmptyCompositeId() {
        FingerprintId id = FingerprintIdBuilder.build(new DeviceFingerprint(), "salt123");
        assertEquals("", id.getHardwareId());
        assertEquals("", id.getSystemId());
        assertEquals("", id.getCompositeId());
        assertFalse(id.isHardwareLayerReliable());
    }

    @Test
    public void transientMissingBucketDoesNotTriggerHardwareChanged() {
        DeviceFingerprint full = buildSampleFingerprint(true, "Adreno 750", "build-1");
        FingerprintId first = FingerprintIdBuilder.build(full, "salt-abc");
        assertTrue(first.isHardwareLayerReliable());
        assertEquals(5, first.getHardwareBucketDigests().size());

        // Second run misses camera bucket transiently, all other 4 buckets match.
        DeviceFingerprint partial = buildSampleFingerprint(false, "Adreno 750", "build-1");
        FingerprintId second = FingerprintIdBuilder.build(partial, "salt-abc");
        assertTrue(second.isHardwareLayerReliable());
        assertEquals(4, second.getHardwareBucketDigests().size());

        FingerprintStore.ComparisonOutcome outcome = FingerprintStore.compare(
                first.getHardwareId(), first.getHardwareBucketDigests(),
                first.getSystemId(), second);
        assertEquals(FingerprintStore.State.STABLE, outcome.state);
        assertTrue(outcome.changedBuckets.isEmpty());
    }

    @Test
    public void coreGpuChangeTriggersHardwareChangedWithBucketDetail() {
        DeviceFingerprint firstFp = buildSampleFingerprint(true, "Adreno 750", "build-1");
        DeviceFingerprint spoofedFp = buildSampleFingerprint(true, "Mali-G715", "build-1");

        FingerprintId first = FingerprintIdBuilder.build(firstFp, "salt-abc");
        FingerprintId spoofed = FingerprintIdBuilder.build(spoofedFp, "salt-abc");

        FingerprintStore.ComparisonOutcome outcome = FingerprintStore.compare(
                first.getHardwareId(), first.getHardwareBucketDigests(),
                first.getSystemId(), spoofed);
        assertEquals(FingerprintStore.State.HARDWARE_CHANGED, outcome.state);
        assertTrue(outcome.changedBuckets.contains("gpu"));
    }

    @Test
    public void systemOnlyChangeReportsSystemChanged() {
        DeviceFingerprint v1 = buildSampleFingerprint(true, "Adreno 750", "build-1");
        DeviceFingerprint v2 = buildSampleFingerprint(true, "Adreno 750", "build-2");

        FingerprintId first = FingerprintIdBuilder.build(v1, "salt-abc");
        FingerprintId updated = FingerprintIdBuilder.build(v2, "salt-abc");

        FingerprintStore.ComparisonOutcome outcome = FingerprintStore.compare(
                first.getHardwareId(), first.getHardwareBucketDigests(),
                first.getSystemId(), updated);
        assertEquals(FingerprintStore.State.SYSTEM_CHANGED, outcome.state);
    }

    @Test
    public void fewerThanThreeComparableBucketsIsInconclusive() {
        Map<String, String> prev = new LinkedHashMap<>();
        prev.put("gpu", "1111");
        prev.put("cpu", "2222");

        DeviceFingerprint curFp = buildSampleFingerprint(true, "Adreno 750", "build-1");
        FingerprintId cur = FingerprintIdBuilder.build(curFp, "salt-abc");

        FingerprintStore.ComparisonOutcome outcome = FingerprintStore.compare(
                "old-hw", prev, cur.getSystemId(), cur);
        assertEquals(FingerprintStore.State.INCONCLUSIVE, outcome.state);
    }

    @Test
    public void xposedHooksActiveIsStrongRank() {
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("xposed_hooks_active:4"));
    }

    private static DeviceFingerprint buildSampleFingerprint(boolean includeCamera,
                                                            String gpuRenderer,
                                                            String systemBuild) {
        DeviceFingerprint fp = new DeviceFingerprint();

        CollectorResult gpu = new CollectorResult("gpu_info");
        gpu.addValue("vendor", "Qualcomm");
        gpu.addValue("renderer", gpuRenderer);
        gpu.addValue("extensions_hash", "ext-hash-1");
        gpu.addValue("max_texture_size", "16384");
        fp.addResult(gpu);

        CollectorResult sensor = new CollectorResult("sensor_fingerprint");
        sensor.addValue("tuple_hash", "sensor-tuple-1");
        sensor.addValue("vendor_hash", "sensor-vendor-1");
        fp.addResult(sensor);

        CollectorResult hw = new CollectorResult("hardware_profile");
        if (includeCamera) {
            hw.addValue("camera_profile_hash", "cam-hash-1");
        }
        hw.addValue("ram_total_mb_bucket", "12288");
        hw.addValue("battery_technology", "Li-ion");
        fp.addResult(hw);

        CollectorResult cpu = new CollectorResult("cpu_topology");
        cpu.addValue("core_distribution", "0x41|0xd80");
        cpu.addValue("freq_clusters", "300000-2000000,710000-3200000");
        cpu.addValue("soc_model", "SM8650");
        cpu.addValue("soc_manufacturer", "QTI");
        fp.addResult(cpu);

        CollectorResult build = new CollectorResult("build_props");
        build.addValue("fingerprint", "google/husky/husky:15/" + systemBuild + "/1:user/release-keys");
        fp.addResult(build);

        return fp;
    }
}
