package com.wsttxm.riskenginesdk;

import android.content.SharedPreferences;

import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.FingerprintIdBuilder;
import com.wsttxm.riskenginesdk.core.FingerprintStore;
import com.wsttxm.riskenginesdk.core.HookEvidenceClassifier;
import com.wsttxm.riskenginesdk.core.KeystoreBackingStore;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.FingerprintId;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

    @Test
    public void tamperedHardwareAcrossThreeConsecutiveCallsStillReportsHardwareChanged() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        FingerprintStore store = new FingerprintStore(prefs);
        String salt = store.getOrCreateSalt();

        FingerprintId original = FingerprintIdBuilder.build(
                buildSampleFingerprint(true, "Adreno 750", "build-1"), salt);
        FingerprintId tampered = FingerprintIdBuilder.build(
                buildSampleFingerprint(true, "Mali-G715", "build-1"), salt);

        FingerprintStore.Continuity first = store.recordAndCompare(original);
        assertEquals(FingerprintStore.State.FIRST_OBSERVATION, first.getState());
        assertEquals(1, first.getObservationCount());
        assertEquals(0, first.getDriftCount());

        for (int attempt = 1; attempt <= 3; attempt++) {
            FingerprintStore.Continuity drift = store.recordAndCompare(tampered);
            assertEquals("Attempt " + attempt + " must still report HARDWARE_CHANGED",
                    FingerprintStore.State.HARDWARE_CHANGED, drift.getState());
            assertTrue(drift.getChangedBuckets().contains("gpu"));
            assertEquals(1 + attempt, drift.getObservationCount());
            assertEquals(attempt, drift.getDriftCount());
        }

        // Anchor remains immutable while last_hw tracks the most recent observation.
        assertEquals(original.getHardwareId(), prefs.getString("anchor_hw", ""));
        assertEquals(tampered.getHardwareId(), prefs.getString("last_hw", ""));
        assertEquals(3, prefs.getInt("drift_count", 0));
    }

    @Test
    public void explicitResetBaselineAndRiskEngineResetReAnchorCleanly() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        FingerprintStore store = new FingerprintStore(prefs);
        String saltBefore = store.getOrCreateSalt();

        FingerprintId original = FingerprintIdBuilder.build(
                buildSampleFingerprint(true, "Adreno 750", "build-1"), saltBefore);
        FingerprintId replacement = FingerprintIdBuilder.build(
                buildSampleFingerprint(true, "Mali-G715", "build-1"), saltBefore);

        assertEquals(FingerprintStore.State.FIRST_OBSERVATION,
                store.recordAndCompare(original).getState());
        assertEquals(FingerprintStore.State.HARDWARE_CHANGED,
                store.recordAndCompare(replacement).getState());

        RiskEngine engine = RiskEngine.getInstance();
        try {
            engine.initForTest(store);
            RiskEngine.resetFingerprintBaseline();

            // Per-install salt is preserved while anchor and drift history are cleared.
            assertEquals(saltBefore, store.getOrCreateSalt());

            FingerprintStore.Continuity reanchored = store.recordAndCompare(replacement);
            assertEquals(FingerprintStore.State.FIRST_OBSERVATION, reanchored.getState());
            assertEquals(1, reanchored.getObservationCount());
            assertEquals(0, reanchored.getDriftCount());

            FingerprintStore.Continuity stable = store.recordAndCompare(replacement);
            assertEquals(FingerprintStore.State.STABLE, stable.getState());
            assertEquals(2, stable.getObservationCount());
            assertEquals(0, stable.getDriftCount());
        } finally {
            RiskEngine.shutdown();
        }
    }

    @Test
    public void legacyStoreWithoutAnchorKeyMigratesWithoutOverwritingOnDrift() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        FingerprintStore store = new FingerprintStore(prefs);
        String salt = store.getOrCreateSalt();

        FingerprintId original = FingerprintIdBuilder.build(
                buildSampleFingerprint(true, "Adreno 750", "build-1"), salt);
        FingerprintId tampered = FingerprintIdBuilder.build(
                buildSampleFingerprint(true, "Mali-G715", "build-1"), salt);

        // Simulate v1.x persistence that only stored last_hw / last_hw_buckets.
        StringBuilder legacyBuckets = new StringBuilder();
        for (Map.Entry<String, String> entry : original.getHardwareBucketDigests().entrySet()) {
            if (legacyBuckets.length() > 0) legacyBuckets.append(';');
            legacyBuckets.append(entry.getKey()).append('=').append(entry.getValue());
        }
        prefs.edit()
                .putString("last_hw", original.getHardwareId())
                .putString("last_hw_buckets", legacyBuckets.toString())
                .putString("last_sys", original.getSystemId())
                .commit();

        FingerprintStore.Continuity firstDrift = store.recordAndCompare(tampered);
        assertEquals(FingerprintStore.State.HARDWARE_CHANGED, firstDrift.getState());
        assertEquals(1, firstDrift.getDriftCount());

        FingerprintStore.Continuity secondDrift = store.recordAndCompare(tampered);
        assertEquals(FingerprintStore.State.HARDWARE_CHANGED, secondDrift.getState());
        assertEquals(2, secondDrift.getDriftCount());
    }

    @Test
    public void shutdownReleasesLifecycleLockBeforeNativeStopAndGuardsGeneration()
            throws Exception {
        RiskEngine engine = RiskEngine.getInstance();
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        FingerprintStore store = new FingerprintStore(prefs);

        CountDownLatch enteredStop = new CountDownLatch(1);
        CountDownLatch allowStopFinish = new CountDownLatch(1);
        AtomicBoolean heldLockInStop = new AtomicBoolean(true);
        AtomicInteger restartCalls = new AtomicInteger(0);

        try {
            engine.initForTest(store);
            long genBefore = engine.getLifecycleGenerationForTest();

            Thread shutdownThread = new Thread(() -> engine.doShutdown(
                    () -> {
                        heldLockInStop.set(engine.isLifecycleLockHeldByCurrentThread());
                        enteredStop.countDown();
                        try {
                            allowStopFinish.await(5, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    },
                    restartCalls::incrementAndGet));
            shutdownThread.start();

            assertTrue("shutdown should reach stopMonitor",
                    enteredStop.await(5, TimeUnit.SECONDS));
            assertFalse("lifecycleLock must be released BEFORE calling native stop",
                    heldLockInStop.get());
            assertFalse(RiskEngine.isInitialized());
            assertTrue(engine.getLifecycleGenerationForTest() > genBefore);

            // Reinitializing concurrently while stopMonitor is blocked must NOT deadlock.
            engine.initForTest(store);
            assertTrue(RiskEngine.isInitialized());

            allowStopFinish.countDown();
            shutdownThread.join(5000);
            assertFalse(shutdownThread.isAlive());
            assertEquals("Concurrent reinit during stopMonitor must trigger restart guard",
                    1, restartCalls.get());
        } finally {
            allowStopFinish.countDown();
            RiskEngine.shutdown();
        }
    }

    @Test
    public void deviceBindingEvidenceMapsToOrthogonalDeviceBindingFamily() {
        assertEquals("device_binding", EvidenceFamily.familyOf("device_binding_broken"));
        assertEquals("device_binding",
                EvidenceFamily.familyOf("device_binding_reason:keystore_key_missing"));
        assertEquals("device_binding",
                EvidenceFamily.familyOf("hardware_layer_changed_between_observations"));
        assertEquals("device_binding", EvidenceFamily.familyOf("changed_buckets:gpu"));
    }

    @Test
    public void v1PlaintextUpgradesToKeystoreWrappedAndRejectsPlaintextDowngrade() {
        InMemorySharedPreferences prefs = new InMemorySharedPreferences();
        String legacySalt = "fedcba9876543210fedcba9876543210";
        FingerprintId original = FingerprintIdBuilder.build(
                buildSampleFingerprint(true, "Adreno 750", "build-1"), legacySalt);
        StringBuilder legacyBuckets = new StringBuilder();
        for (Map.Entry<String, String> entry : original.getHardwareBucketDigests().entrySet()) {
            if (legacyBuckets.length() > 0) legacyBuckets.append(';');
            legacyBuckets.append(entry.getKey()).append('=').append(entry.getValue());
        }
        prefs.edit()
                .putString("salt", legacySalt)
                .putString("last_hw", original.getHardwareId())
                .putString("last_hw_buckets", legacyBuckets.toString())
                .putString("last_sys", original.getSystemId())
                .commit();

        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        SecretKeySpec aesKey = new SecretKeySpec(rawKey, "AES");
        KeystoreBackingStore backingStore = new KeystoreBackingStore(
                new KeystoreBackingStore.KeyProvider() {
                    @Override public SecretKey loadKey(String alias) { return aesKey; }
                    @Override public SecretKey generateKey(String alias, boolean sb) { return aesKey; }
                    @Override public DevicePosture.KeystoreSecurityLevel querySecurityLevel(
                            SecretKey key, boolean sb) {
                        return DevicePosture.KeystoreSecurityLevel.TEE;
                    }
                    @Override public boolean callerProvidesIv() { return true; }
                });

        FingerprintStore store = new FingerprintStore(prefs, backingStore);
        assertEquals(legacySalt, store.getOrCreateSalt());

        FingerprintStore.Continuity upgraded = store.recordAndCompare(original);
        assertEquals(FingerprintStore.State.STABLE, upgraded.getState());
        assertFalse(upgraded.isDeviceBindingBroken());
        assertTrue(KeystoreBackingStore.isWrapped(prefs.getString("salt", "")));
        assertTrue(KeystoreBackingStore.isWrapped(prefs.getString("anchor_hw", "")));
        assertTrue(prefs.getBoolean("keystore_bound", false));

        // Attacker downgrades anchor_hw back to plaintext after keystore binding -> caught!
        prefs.edit().putString("anchor_hw", "forged-plaintext-anchor").commit();
        FingerprintStore.Continuity downgraded = store.recordAndCompare(original);
        assertEquals(FingerprintStore.State.DEVICE_BINDING_BROKEN, downgraded.getState());
        assertTrue(downgraded.isDeviceBindingBroken());
        assertTrue(downgraded.getDeviceBindingReason().startsWith("plaintext_downgrade_tamper:"));
    }

    private static final class InMemorySharedPreferences implements SharedPreferences {
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
        @Override public Editor edit() { return new InMemoryEditor(); }
        @Override public void registerOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener listener) {}
        @Override public void unregisterOnSharedPreferenceChangeListener(
                OnSharedPreferenceChangeListener listener) {}

        private final class InMemoryEditor implements Editor {
            private final Map<String, Object> staged = new HashMap<>();
            private final Set<String> removals = new HashSet<>();
            private boolean clearAll;

            @Override public Editor putString(String key, String value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putStringSet(String key, Set<String> values) {
                staged.put(key, values == null ? null : new HashSet<>(values));
                return this;
            }
            @Override public Editor putInt(String key, int value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putLong(String key, long value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putFloat(String key, float value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor putBoolean(String key, boolean value) {
                staged.put(key, value);
                return this;
            }
            @Override public Editor remove(String key) {
                removals.add(key);
                staged.remove(key);
                return this;
            }
            @Override public Editor clear() {
                clearAll = true;
                staged.clear();
                removals.clear();
                return this;
            }
            @Override public boolean commit() {
                apply();
                return true;
            }
            @Override public void apply() {
                if (clearAll) {
                    data.clear();
                }
                for (String key : removals) {
                    data.remove(key);
                }
                for (Map.Entry<String, Object> entry : staged.entrySet()) {
                    if (entry.getValue() == null) {
                        data.remove(entry.getKey());
                    } else {
                        data.put(entry.getKey(), entry.getValue());
                    }
                }
            }
        }
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
