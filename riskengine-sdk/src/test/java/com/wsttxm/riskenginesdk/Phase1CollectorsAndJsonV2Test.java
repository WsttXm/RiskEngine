package com.wsttxm.riskenginesdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import android.app.admin.DevicePolicyManager;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.collector.CollectorRegistry;
import com.wsttxm.riskenginesdk.collector.java_layer.InputDeviceCollector;
import com.wsttxm.riskenginesdk.collector.java_layer.MediaCodecCollector;
import com.wsttxm.riskenginesdk.collector.java_layer.SecurityPostureCollector;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.FingerprintStore;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.json.JSONObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class Phase1CollectorsAndJsonV2Test {

    @Test
    public void mediaCodecCollectorDegradesGracefullyAndHashesOrderIndependently() {
        CollectorResult fallback = new MediaCodecCollector(null).call();
        assertEquals(CollectorResult.Status.UNSUPPORTED, fallback.getStatus());

        List<MediaCodecCollector.CodecEntry> realDevice = Arrays.asList(
                new MediaCodecCollector.CodecEntry(
                        "c2.qti.avc.decoder", true, false, false,
                        Arrays.asList("video/avc")),
                new MediaCodecCollector.CodecEntry(
                        "c2.android.aac.decoder", false, true, false,
                        Arrays.asList("audio/mp4a-latm"))
        );
        List<MediaCodecCollector.CodecEntry> reversed = Arrays.asList(
                realDevice.get(1), realDevice.get(0));

        CollectorResult r1 = new CollectorResult("codec_info");
        MediaCodecCollector.populateFromEntries(realDevice, r1);
        CollectorResult r2 = new CollectorResult("codec_info");
        MediaCodecCollector.populateFromEntries(reversed, r2);

        assertEquals(CollectorResult.Status.SUCCESS, r1.getStatus());
        assertEquals(r1.getValues().get("codec_matrix_hash"), r2.getValues().get("codec_matrix_hash"));
        assertEquals(64, r1.getValues().get("codec_matrix_hash").length());
        assertEquals("2", r1.getValues().get("total_count"));
        assertEquals("1", r1.getValues().get("hw_count"));
        assertEquals("1", r1.getValues().get("sw_count"));
        assertEquals("c2.qti", r1.getValues().get("hw_vendor_prefixes"));

        CollectorResult swOnly = new CollectorResult("codec_info");
        MediaCodecCollector.populateFromEntries(
                Collections.singletonList(realDevice.get(1)), swOnly);
        assertNotEquals(
                r1.getValues().get("codec_matrix_hash"),
                swOnly.getValues().get("codec_matrix_hash"));
        assertEquals("0", swOnly.getValues().get("hw_count"));
    }

    @Test
    public void inputDeviceCollectorDegradesGracefullyAndHashesDeterministically() {
        CollectorResult fallback = new InputDeviceCollector(null).call();
        assertEquals(CollectorResult.Status.UNSUPPORTED, fallback.getStatus());

        List<InputDeviceCollector.InputEntry> inputs = Arrays.asList(
                new InputDeviceCollector.InputEntry("Virtual", -1, 0, 0x301, true),
                new InputDeviceCollector.InputEntry("goodix_ts", 0x27c6, 0x0113, 0x1002, false)
        );
        List<InputDeviceCollector.InputEntry> reversed = Arrays.asList(inputs.get(1), inputs.get(0));

        CollectorResult r1 = new CollectorResult("input_devices");
        InputDeviceCollector.populateFromEntries(inputs, r1);
        CollectorResult r2 = new CollectorResult("input_devices");
        InputDeviceCollector.populateFromEntries(reversed, r2);

        assertEquals(CollectorResult.Status.SUCCESS, r1.getStatus());
        assertEquals(r1.getValues().get("input_device_hash"), r2.getValues().get("input_device_hash"));
        assertEquals(64, r1.getValues().get("input_device_hash").length());
        assertEquals("2", r1.getValues().get("total_count"));
        assertEquals("1", r1.getValues().get("virtual_count"));
        assertEquals("1", r1.getValues().get("physical_count"));
    }

    @Test
    public void securityPostureCollectorCollectsJcaProvidersWithoutContextAndMapsPosture() {
        CollectorResult jvmResult = new SecurityPostureCollector(null).call();
        assertEquals(CollectorResult.Status.SUCCESS, jvmResult.getStatus());
        assertEquals(64, jvmResult.getValues().get("providers_hash").length());
        assertTrue(Integer.parseInt(jvmResult.getValues().get("provider_count")) > 0);

        assertEquals(DevicePosture.StorageEncryptionStatus.ACTIVE_PER_USER,
                SecurityPostureCollector.mapEncryptionStatus(
                        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER));
        assertEquals(DevicePosture.BiometricStatus.READY,
                SecurityPostureCollector.mapBiometricCode(BiometricManager.BIOMETRIC_SUCCESS));
        assertEquals(DevicePosture.BiometricStatus.NONE_ENROLLED,
                SecurityPostureCollector.mapBiometricCode(
                        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED));

        CollectorResult sp = new CollectorResult("security_posture");
        sp.addValue("device_secure", "true");
        sp.addValue("storage_encryption", "ACTIVE_PER_USER");
        sp.addValue("keystore_level", "STRONGBOX");
        sp.addValue("biometric_status", "READY");
        sp.addValue("dev_mode", "false");

        CollectorResult adb = new CollectorResult("adb_state");
        adb.addValue("adb_enabled", "0");

        DevicePosture posture = SecurityPostureCollector.toDevicePosture(sp, adb);
        assertTrue(posture.isDeviceSecure());
        assertTrue(posture.isStorageEncrypted());
        assertTrue(posture.isHardwareKeystoreBacked());
        assertEquals(DevicePosture.BiometricStatus.READY, posture.getBiometricStatus());
        assertEquals(Boolean.FALSE, posture.getDeveloperOptionsEnabled());
        assertEquals(Boolean.FALSE, posture.getAdbEnabled());
    }

    @Test
    public void collectorRegistryIncludesThreePhase1Collectors() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .privacyProfile(PrivacyProfile.MINIMAL)
                .build();
        CollectorRegistry registry = new CollectorRegistry(null, config);
        Set<String> names = registry.getCollectors().stream()
                .map(BaseCollector::getName)
                .collect(Collectors.toSet());
        assertTrue(names.contains("codec_info"));
        assertTrue(names.contains("input_devices"));
        assertTrue(names.contains("security_posture"));
    }

    @Test
    public void trustTierCoversAllFourLevels() {
        DeviceFingerprint strongFp = new DeviceFingerprint();
        CollectorResult strongSp = new CollectorResult("security_posture");
        strongSp.addValue("device_secure", "true");
        strongSp.addValue("storage_encryption", "ACTIVE_PER_USER");
        strongSp.addValue("keystore_level", "STRONGBOX");
        strongFp.addResult(strongSp);

        DetectionResult safeDet = new DetectionResult("root", RiskLevel.SAFE, "no risk")
                .withScanTier(ScanTier.CRITICAL);
        RiskReport strongReport = new RiskReport(strongFp, Collections.singletonList(safeDet));
        assertEquals(RiskReport.TrustTier.STRONG_HARDWARE, strongReport.getTrustTier());

        RiskReport localVerified = new RiskReport(
                new DeviceFingerprint(), Collections.singletonList(safeDet));
        assertEquals(RiskReport.TrustTier.LOCAL_VERIFIED, localVerified.getTrustTier());

        RiskReport degraded = new RiskReport(
                new DeviceFingerprint(),
                Collections.singletonList(DetectionResult.timeout("slow", "150ms")));
        assertEquals(RiskReport.TrustTier.DEGRADED, degraded.getTrustTier());

        RiskReport compromised = new RiskReport(
                new DeviceFingerprint(),
                Collections.singletonList(new DetectionResult("root", RiskLevel.HIGH, "su_binary")));
        assertEquals(RiskReport.TrustTier.COMPROMISED, compromised.getTrustTier());
    }

    @Test
    public void jsonV2EmitsDevicePostureTrustTierFingerprintV2DriftCountAndScanTier() throws Exception {
        InMemoryPrefs prefs = new InMemoryPrefs();
        FingerprintStore store = new FingerprintStore(prefs);
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .fingerprintVersion(FingerprintVersion.V2)
                .fingerprintStability(FingerprintStability.OPTIMAL)
                .build();
        DataAggregator aggregator = new DataAggregator(store, config);

        List<CollectorResult> initial = buildFullCollectors("Adreno 750");
        DetectionResult criticalSafe = new DetectionResult(
                "debug", RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                Collections.emptyList(), "clean").withScanTier(ScanTier.CRITICAL);

        RiskReport firstReport = aggregator.aggregate(initial, Collections.singletonList(criticalSafe));
        assertEquals(0, firstReport.getAnchorDriftCount());
        assertEquals(RiskReport.TrustTier.STRONG_HARDWARE, firstReport.getTrustTier());

        // Second observation with tampered GPU triggers hardware drift -> anchorDriftCount == 1
        List<CollectorResult> drifted = buildFullCollectors("Mali-G715");
        RiskReport secondReport = aggregator.aggregate(drifted, Collections.singletonList(criticalSafe));
        assertEquals(1, secondReport.getAnchorDriftCount());

        JSONObject json = new JSONObject(RiskEngine.reportToJson(secondReport));
        // Additive v2 root fields
        assertEquals(2, json.getInt("schemaVersion"));
        assertEquals("DEGRADED", json.getString("trustTier"));
        assertTrue(json.has("devicePosture"));
        JSONObject posture = json.getJSONObject("devicePosture");
        assertTrue(posture.getBoolean("hasPasscode"));
        assertTrue(posture.getBoolean("storageEncrypted"));
        assertEquals("STRONGBOX", posture.getString("keystoreLevel"));
        assertEquals("READY", posture.getString("biometricStatus"));
        assertFalse(posture.getBoolean("devMode"));
        assertFalse(posture.getBoolean("adbEnabled"));

        // Additive v2 fingerprintId fields + v1 fields intact
        JSONObject fpJson = json.getJSONObject("fingerprintId");
        assertEquals("V2", fpJson.getString("version"));
        assertEquals("OPTIMAL", fpJson.getString("stability"));
        assertEquals(1, fpJson.getInt("anchorDriftCount"));
        assertTrue(fpJson.getBoolean("hardwareLayerReliable"));
        assertFalse(fpJson.getString("compositeId").isEmpty());

        // Additive v2 detections[].scanTier + v1 fields intact
        JSONObject det0 = json.getJSONArray("detections").getJSONObject(0);
        assertEquals("debug", det0.getString("detectorName"));
        assertEquals("CRITICAL", det0.getString("scanTier"));
        assertTrue(det0.has("details"));
        assertTrue(det0.has("evidenceItems"));
        assertTrue(det0.has("evidenceFamilies"));
    }

    private static List<CollectorResult> buildFullCollectors(String gpuRenderer) {
        CollectorResult gpu = new CollectorResult("gpu_info");
        gpu.addValue("vendor", "Qualcomm");
        gpu.addValue("renderer", gpuRenderer);
        gpu.addValue("extensions_hash", "ext-1");
        gpu.addValue("max_texture_size", "16384");

        CollectorResult sensor = new CollectorResult("sensor_fingerprint");
        sensor.addValue("tuple_hash", "s-tuple");
        sensor.addValue("vendor_hash", "s-vendor");

        CollectorResult cpu = new CollectorResult("cpu_topology");
        cpu.addValue("core_distribution", "0x41|0xd80");
        cpu.addValue("freq_clusters", "300-3200");
        cpu.addValue("soc_model", "SM8650");
        cpu.addValue("soc_manufacturer", "QTI");

        CollectorResult codec = new CollectorResult("codec_info");
        codec.addValue("codec_matrix_hash", "codec-h1");

        CollectorResult input = new CollectorResult("input_devices");
        input.addValue("input_device_hash", "input-h1");

        CollectorResult sp = new CollectorResult("security_posture");
        sp.addValue("providers_hash", "prov-h1");
        sp.addValue("device_secure", "true");
        sp.addValue("storage_encryption", "ACTIVE_PER_USER");
        sp.addValue("keystore_level", "STRONGBOX");
        sp.addValue("biometric_status", "READY");
        sp.addValue("dev_mode", "false");
        sp.addValue("adb_enabled", "false");

        return Arrays.asList(gpu, sensor, cpu, codec, input, sp);
    }

    private static final class InMemoryPrefs implements SharedPreferences {
        private final Map<String, Object> data = new HashMap<>();

        @Override public Map<String, ?> getAll() { return new HashMap<>(data); }
        @Override public String getString(String key, String defValue) {
            Object v = data.get(key);
            return v instanceof String ? (String) v : defValue;
        }
        @Override @SuppressWarnings("unchecked")
        public Set<String> getStringSet(String key, Set<String> defValues) {
            Object v = data.get(key);
            return v instanceof Set ? new HashSet<>((Set<String>) v) : defValues;
        }
        @Override public int getInt(String key, int defValue) {
            Object v = data.get(key);
            return v instanceof Integer ? (Integer) v : defValue;
        }
        @Override public long getLong(String key, long defValue) {
            Object v = data.get(key);
            return v instanceof Long ? (Long) v : defValue;
        }
        @Override public float getFloat(String key, float defValue) {
            Object v = data.get(key);
            return v instanceof Float ? (Float) v : defValue;
        }
        @Override public boolean getBoolean(String key, boolean defValue) {
            Object v = data.get(key);
            return v instanceof Boolean ? (Boolean) v : defValue;
        }
        @Override public boolean contains(String key) { return data.containsKey(key); }
        @Override public Editor edit() { return new MemEditor(); }
        @Override public void registerOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener listener) {}
        @Override public void unregisterOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener listener) {}

        private final class MemEditor implements Editor {
            private final Map<String, Object> staged = new HashMap<>();
            private final Set<String> removals = new HashSet<>();
            private boolean clearAll;

            @Override public Editor putString(String k, String v) { staged.put(k, v); return this; }
            @Override public Editor putStringSet(String k, Set<String> v) {
                staged.put(k, v == null ? null : new HashSet<>(v));
                return this;
            }
            @Override public Editor putInt(String k, int v) { staged.put(k, v); return this; }
            @Override public Editor putLong(String k, long v) { staged.put(k, v); return this; }
            @Override public Editor putFloat(String k, float v) { staged.put(k, v); return this; }
            @Override public Editor putBoolean(String k, boolean v) { staged.put(k, v); return this; }
            @Override public Editor remove(String k) { removals.add(k); staged.remove(k); return this; }
            @Override public Editor clear() { clearAll = true; staged.clear(); removals.clear(); return this; }
            @Override public boolean commit() { apply(); return true; }
            @Override public void apply() {
                if (clearAll) data.clear();
                for (String k : removals) data.remove(k);
                for (Map.Entry<String, Object> e : staged.entrySet()) {
                    if (e.getValue() == null) data.remove(e.getKey());
                    else data.put(e.getKey(), e.getValue());
                }
            }
        }
    }
}
