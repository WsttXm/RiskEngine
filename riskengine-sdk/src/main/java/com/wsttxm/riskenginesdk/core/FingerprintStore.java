package com.wsttxm.riskenginesdk.core;

import android.content.Context;
import android.content.SharedPreferences;

import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.util.CLog;

import java.security.SecureRandom;

/**
 * Local persistence for the fingerprint salt and last observed ID.
 *
 * The SDK previously stored nothing, so every collection was stateless and no
 * ID could be stable across runs. Two things are kept here:
 *
 * salt      A per-install random value mixed into every layer digest. This
 *           makes the IDs app-scoped, so the same device seen by two different
 *           apps yields unrelated IDs and the values cannot be used to
 *           correlate a user across unrelated installs. It is generated once
 *           and never leaves the device.
 * last IDs  The previous hardware and system digests, used to report whether
 *           this is a returning device and which layer moved.
 *
 * Everything is written to the app's private preferences, so it is removed on
 * uninstall or data clear. The salt changing on reinstall is deliberate: it
 * keeps the identifier from being a permanent device-wide tracker. Persistent
 * cross-reinstall linkage is intentionally not implemented here.
 */
public final class FingerprintStore {
    private static final String PREFS_NAME = "riskengine_fp";
    private static final String KEY_SALT = "salt";
    private static final String KEY_LAST_HARDWARE = "last_hw";
    private static final String KEY_LAST_SYSTEM = "last_sys";
    private static final String KEY_FIRST_SEEN = "first_seen";
    private static final String KEY_OBSERVATIONS = "observations";
    private static final Object STORE_LOCK = new Object();

    private final Context context;

    public FingerprintStore(Context context) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
    }

    private SharedPreferences prefs() {
        return context == null
                ? null
                : context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /** Returns the per-install salt, creating it on first use. */
    public String getOrCreateSalt() {
        SharedPreferences preferences = prefs();
        if (preferences == null) return "riskengine";
        synchronized (STORE_LOCK) {
            try {
                String existing = preferences.getString(KEY_SALT, null);
                if (existing != null && !existing.isEmpty()) {
                    return existing;
                }
                byte[] random = new byte[32];
                new SecureRandom().nextBytes(random);
                StringBuilder hex = new StringBuilder(random.length * 2);
                for (byte item : random) {
                    hex.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                    hex.append(Character.forDigit(item & 0x0f, 16));
                }
                String salt = hex.toString();
                preferences.edit()
                        .putString(KEY_SALT, salt)
                        .putLong(KEY_FIRST_SEEN, System.currentTimeMillis())
                        .apply();
                return salt;
            } catch (Exception e) {
                CLog.e("Fingerprint salt access failed", e);
                return "riskengine";
            }
        }
    }

    /**
     * Compares the given ID against what was last stored, then records it.
     * Returns the continuity outcome so the report can state plainly whether
     * this device has been seen before and which layer changed.
     */
    public Continuity recordAndCompare(FingerprintId id) {
        SharedPreferences preferences = prefs();
        if (preferences == null || id == null) {
            return new Continuity(State.UNKNOWN, 0, 0);
        }
        synchronized (STORE_LOCK) {
            try {
                String previousHardware = preferences.getString(KEY_LAST_HARDWARE, "");
                String previousSystem = preferences.getString(KEY_LAST_SYSTEM, "");
                long firstSeen = preferences.getLong(KEY_FIRST_SEEN, 0L);
                int observations = preferences.getInt(KEY_OBSERVATIONS, 0);
                int nextObservations = observations == Integer.MAX_VALUE
                        ? Integer.MAX_VALUE : observations + 1;
                long effectiveFirstSeen = firstSeen == 0L
                        ? System.currentTimeMillis() : firstSeen;

                State state;
                if (previousHardware.isEmpty()) {
                    state = State.FIRST_OBSERVATION;
                } else if (!id.isHardwareLayerReliable()) {
                    // Do not claim a mismatch when this run simply collected less.
                    state = State.INCONCLUSIVE;
                } else if (previousHardware.equals(id.getHardwareId())) {
                    state = previousSystem.equals(id.getSystemId())
                            ? State.STABLE : State.SYSTEM_CHANGED;
                } else {
                    state = State.HARDWARE_CHANGED;
                }

                SharedPreferences.Editor editor = preferences.edit();
                editor.putInt(KEY_OBSERVATIONS, nextObservations);
                if (firstSeen == 0L) {
                    editor.putLong(KEY_FIRST_SEEN, effectiveFirstSeen);
                }
                // Only overwrite the baseline with a reliable measurement, so a
                // degraded run cannot erase a good one.
                if (id.isHardwareLayerReliable()) {
                    editor.putString(KEY_LAST_HARDWARE, id.getHardwareId());
                    editor.putString(KEY_LAST_SYSTEM, id.getSystemId());
                }
                editor.apply();

                return new Continuity(state, effectiveFirstSeen, nextObservations);
            } catch (Exception e) {
                CLog.e("Fingerprint continuity check failed", e);
                return new Continuity(State.UNKNOWN, 0, 0);
            }
        }
    }

    public enum State {
        /** No prior record; nothing to compare against. */
        FIRST_OBSERVATION,
        /** Both hardware and system layers match the previous observation. */
        STABLE,
        /** Same hardware, different system build. Normal after an OS update. */
        SYSTEM_CHANGED,
        /** Hardware layer differs. Different device, or spoofed hardware values. */
        HARDWARE_CHANGED,
        /** This run collected too few hardware inputs to compare meaningfully. */
        INCONCLUSIVE,
        /** Storage unavailable. */
        UNKNOWN
    }

    public static final class Continuity {
        private final State state;
        private final long firstSeenMs;
        private final int observationCount;

        Continuity(State state, long firstSeenMs, int observationCount) {
            this.state = state;
            this.firstSeenMs = firstSeenMs;
            this.observationCount = observationCount;
        }

        public State getState() { return state; }
        public long getFirstSeenMs() { return firstSeenMs; }
        public int getObservationCount() { return observationCount; }
    }
}
