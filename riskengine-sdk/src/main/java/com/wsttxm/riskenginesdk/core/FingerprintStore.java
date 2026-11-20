package com.wsttxm.riskenginesdk.core;

import android.content.Context;
import android.content.SharedPreferences;

import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.util.CLog;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Local persistence for the per-install fingerprint salt and per-domain
 * hardware bucket baseline.
 *
 * Uses intersection comparison across hardware domains (gpu, sensor, camera,
 * cpu, memory_battery) so a transiently missing collector does not trigger a
 * false HARDWARE_CHANGED finding.
 */
public final class FingerprintStore {
    private static final String PREFS_NAME = "riskengine_fp";
    private static final String KEY_SALT = "salt";
    private static final String KEY_LAST_HARDWARE = "last_hw";
    private static final String KEY_LAST_HW_BUCKETS = "last_hw_buckets";
    private static final String KEY_LAST_SYSTEM = "last_sys";
    private static final String KEY_FIRST_SEEN = "first_seen";
    private static final String KEY_OBSERVATIONS = "observations";
    private static final Object STORE_LOCK = new Object();

    private final Context context;
    private volatile String ephemeralFallbackSalt;

    public FingerprintStore(Context context) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
    }

    private SharedPreferences prefs() {
        return context == null
                ? null
                : context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /** Returns the per-install salt, creating and synchronously persisting it on first use. */
    public String getOrCreateSalt() {
        SharedPreferences preferences = prefs();
        if (preferences == null) return getEphemeralSalt();
        synchronized (STORE_LOCK) {
            try {
                String existing = preferences.getString(KEY_SALT, null);
                if (existing != null && !existing.isEmpty()) {
                    return existing;
                }
                String salt = generateRandomHex(32);
                boolean persisted = preferences.edit()
                        .putString(KEY_SALT, salt)
                        .putLong(KEY_FIRST_SEEN, System.currentTimeMillis())
                        .commit();
                if (!persisted) {
                    CLog.w("Fingerprint salt commit returned false");
                }
                return salt;
            } catch (Exception e) {
                CLog.e("Fingerprint salt access failed", e);
                return getEphemeralSalt();
            }
        }
    }

    private String getEphemeralSalt() {
        String existing = ephemeralFallbackSalt;
        if (existing != null) return existing;
        synchronized (this) {
            if (ephemeralFallbackSalt == null) {
                String pkg = context == null ? "ephemeral" : String.valueOf(context.getPackageName());
                ephemeralFallbackSalt = pkg + ":" + generateRandomHex(16);
            }
            return ephemeralFallbackSalt;
        }
    }

    public static String generateRandomHex(int byteLength) {
        byte[] random = new byte[byteLength];
        new SecureRandom().nextBytes(random);
        StringBuilder hex = new StringBuilder(random.length * 2);
        for (byte item : random) {
            hex.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            hex.append(Character.forDigit(item & 0x0f, 16));
        }
        return hex.toString();
    }

    /**
     * Compares the given ID against stored per-domain digests using
     * intersection semantics, then updates the baseline on reliable runs.
     */
    public Continuity recordAndCompare(FingerprintId id) {
        SharedPreferences preferences = prefs();
        if (preferences == null || id == null) {
            return new Continuity(State.UNKNOWN, 0, 0, Collections.emptyList());
        }
        synchronized (STORE_LOCK) {
            try {
                String previousHardware = preferences.getString(KEY_LAST_HARDWARE, "");
                Map<String, String> previousBuckets =
                        decodeBuckets(preferences.getString(KEY_LAST_HW_BUCKETS, ""));
                String previousSystem = preferences.getString(KEY_LAST_SYSTEM, "");
                long firstSeen = preferences.getLong(KEY_FIRST_SEEN, 0L);
                int observations = preferences.getInt(KEY_OBSERVATIONS, 0);
                int nextObservations = observations == Integer.MAX_VALUE
                        ? Integer.MAX_VALUE : observations + 1;
                long effectiveFirstSeen = firstSeen == 0L
                        ? System.currentTimeMillis() : firstSeen;

                ComparisonOutcome outcome = compare(
                        previousHardware, previousBuckets, previousSystem, id);

                SharedPreferences.Editor editor = preferences.edit();
                editor.putInt(KEY_OBSERVATIONS, nextObservations);
                if (firstSeen == 0L) {
                    editor.putLong(KEY_FIRST_SEEN, effectiveFirstSeen);
                }
                if (id.isHardwareLayerReliable()) {
                    editor.putString(KEY_LAST_HARDWARE, id.getHardwareId());
                    editor.putString(KEY_LAST_SYSTEM, id.getSystemId());
                    Map<String, String> merged = new LinkedHashMap<>(previousBuckets);
                    merged.putAll(id.getHardwareBucketDigests());
                    editor.putString(KEY_LAST_HW_BUCKETS, encodeBuckets(merged));
                }
                editor.apply();

                return new Continuity(outcome.state, effectiveFirstSeen,
                        nextObservations, outcome.changedBuckets);
            } catch (Exception e) {
                CLog.e("Fingerprint continuity check failed", e);
                return new Continuity(State.UNKNOWN, 0, 0, Collections.emptyList());
            }
        }
    }

    public static ComparisonOutcome compare(String previousHardware,
                                            Map<String, String> previousBuckets,
                                            String previousSystem,
                                            FingerprintId current) {
        boolean hasPrevious = (previousHardware != null && !previousHardware.isEmpty())
                || (previousBuckets != null && !previousBuckets.isEmpty());
        if (!hasPrevious) {
            return new ComparisonOutcome(State.FIRST_OBSERVATION, Collections.emptyList());
        }
        if (current == null || !current.isHardwareLayerReliable()) {
            return new ComparisonOutcome(State.INCONCLUSIVE, Collections.emptyList());
        }

        Map<String, String> currBuckets = current.getHardwareBucketDigests();
        if (previousBuckets != null && !previousBuckets.isEmpty() && !currBuckets.isEmpty()) {
            int comparable = 0;
            List<String> changed = new ArrayList<>();
            for (Map.Entry<String, String> entry : currBuckets.entrySet()) {
                String bucket = entry.getKey();
                String currVal = entry.getValue();
                String prevVal = previousBuckets.get(bucket);
                if (prevVal == null || prevVal.isEmpty()
                        || currVal == null || currVal.isEmpty()) {
                    continue;
                }
                comparable++;
                if (!prevVal.equals(currVal)) {
                    changed.add(bucket);
                }
            }
            if (comparable < 3) {
                return new ComparisonOutcome(State.INCONCLUSIVE, Collections.emptyList());
            }
            boolean coreChanged = changed.contains("gpu") || changed.contains("cpu");
            if (changed.size() >= 2 || (changed.size() == 1 && coreChanged)) {
                return new ComparisonOutcome(State.HARDWARE_CHANGED, changed);
            }
            boolean sameSystem = previousSystem != null
                    && previousSystem.equals(current.getSystemId());
            return new ComparisonOutcome(
                    sameSystem ? State.STABLE : State.SYSTEM_CHANGED,
                    Collections.emptyList());
        }

        // Legacy fallback when upgrading from a store without bucket digests.
        if (previousHardware != null && previousHardware.equals(current.getHardwareId())) {
            boolean sameSystem = previousSystem != null
                    && previousSystem.equals(current.getSystemId());
            return new ComparisonOutcome(
                    sameSystem ? State.STABLE : State.SYSTEM_CHANGED,
                    Collections.emptyList());
        }
        return new ComparisonOutcome(State.HARDWARE_CHANGED, List.of("hardware_digest"));
    }

    static String encodeBuckets(Map<String, String> buckets) {
        if (buckets == null || buckets.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : buckets.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) continue;
            if (sb.length() > 0) sb.append(';');
            sb.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return sb.toString();
    }

    static Map<String, String> decodeBuckets(String raw) {
        Map<String, String> map = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) return map;
        for (String item : raw.split(";")) {
            int eq = item.indexOf('=');
            if (eq > 0 && eq + 1 < item.length()) {
                map.put(item.substring(0, eq).trim(), item.substring(eq + 1).trim());
            }
        }
        return map;
    }

    public static final class ComparisonOutcome {
        public final State state;
        public final List<String> changedBuckets;

        ComparisonOutcome(State state, List<String> changedBuckets) {
            this.state = state;
            this.changedBuckets = changedBuckets == null
                    ? Collections.emptyList()
                    : List.copyOf(changedBuckets);
        }
    }

    public enum State {
        FIRST_OBSERVATION,
        STABLE,
        SYSTEM_CHANGED,
        HARDWARE_CHANGED,
        INCONCLUSIVE,
        UNKNOWN
    }

    public static final class Continuity {
        private final State state;
        private final long firstSeenMs;
        private final int observationCount;
        private final List<String> changedBuckets;

        Continuity(State state, long firstSeenMs, int observationCount,
                   List<String> changedBuckets) {
            this.state = state;
            this.firstSeenMs = firstSeenMs;
            this.observationCount = observationCount;
            this.changedBuckets = changedBuckets == null
                    ? Collections.emptyList()
                    : List.copyOf(changedBuckets);
        }

        public State getState() { return state; }
        public long getFirstSeenMs() { return firstSeenMs; }
        public int getObservationCount() { return observationCount; }
        public List<String> getChangedBuckets() { return changedBuckets; }
    }
}
