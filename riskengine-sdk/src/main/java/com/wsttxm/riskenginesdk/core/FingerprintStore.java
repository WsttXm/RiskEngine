package com.wsttxm.riskenginesdk.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.UserManager;

import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.util.CLog;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Local persistence for the per-install fingerprint salt and per-domain
 * hardware bucket baseline.
 *
 * <p>Uses Device Protected (DE) storage for DirectBoot compatibility (guarding
 * one-time CE-&gt;DE migration behind {@link UserManager#isUserUnlocked()}),
 * wraps persisted values with hardware-backed AES-256-GCM via
 * {@link KeystoreBackingStore}, and detects cross-device cloning or local XML
 * tampering via {@code device_binding_broken}.
 *
 * <p>Stores ONLY anonymous encrypted installation salt and non-sensitive
 * hardware baseline digests — never user identity, account tokens, or PII.
 */
public final class FingerprintStore {
    public static final String PREFS_NAME = "riskengine_fp";
    private static final String KEY_SALT = "salt";
    private static final String KEY_ANCHOR_HARDWARE = "anchor_hw";
    private static final String KEY_ANCHOR_HW_BUCKETS = "anchor_hw_buckets";
    private static final String KEY_LAST_HARDWARE = "last_hw";
    private static final String KEY_LAST_HW_BUCKETS = "last_hw_buckets";
    private static final String KEY_LAST_SYSTEM = "last_sys";
    private static final String KEY_DRIFT_COUNT = "drift_count";
    private static final String KEY_FIRST_SEEN = "first_seen";
    private static final String KEY_OBSERVATIONS = "observations";
    private static final String KEY_KEYSTORE_BOUND = "keystore_bound";
    private static final String KEY_DE_MIGRATED = "de_migrated_v2";
    private static final Object STORE_LOCK = new Object();

    private final Context context;
    private final SharedPreferences overridePrefs;
    private final KeystoreBackingStore backingStore;
    private final Predicate<Context> unlockChecker;
    private volatile String ephemeralFallbackSalt;
    private volatile boolean migrationCompleted;

    public FingerprintStore(Context context) {
        this(context, KeystoreBackingStore.createDefault(context),
                FingerprintStore::defaultIsUserUnlocked);
    }

    public FingerprintStore(Context context, KeystoreBackingStore backingStore) {
        this(context, backingStore, FingerprintStore::defaultIsUserUnlocked);
    }

    /** Constructor allowing deterministic DirectBoot lock-state injection on JVM tests. */
    public FingerprintStore(Context context,
                            KeystoreBackingStore backingStore,
                            Predicate<Context> unlockChecker) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
        this.overridePrefs = null;
        this.backingStore = backingStore;
        this.unlockChecker = unlockChecker != null
                ? unlockChecker
                : FingerprintStore::defaultIsUserUnlocked;
    }

    /** Custom-backed constructor for deterministic JVM unit testing (unencrypted fallback). */
    public FingerprintStore(SharedPreferences preferences) {
        this(preferences, null);
    }

    /** Custom-backed constructor with explicit {@link KeystoreBackingStore} for JVM tests. */
    public FingerprintStore(SharedPreferences preferences, KeystoreBackingStore backingStore) {
        this.context = null;
        this.overridePrefs = preferences;
        this.backingStore = backingStore;
        this.unlockChecker = FingerprintStore::defaultIsUserUnlocked;
    }

    static boolean defaultIsUserUnlocked(Context context) {
        if (context == null) {
            return false;
        }
        try {
            UserManager userManager =
                    (UserManager) context.getSystemService(Context.USER_SERVICE);
            return userManager != null && userManager.isUserUnlocked();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.w("UserManager.isUserUnlocked check failed: " + e.getClass().getSimpleName());
            return false;
        }
    }

    private SharedPreferences resolvePrefsLocked() {
        if (overridePrefs != null) {
            return overridePrefs;
        }
        if (context == null) {
            return null;
        }

        Context deContext = safeCreateDeviceProtectedStorageContext(context);
        if (deContext == null) {
            // Never touch Credential Encrypted (CE) storage while the user is locked.
            if (!safeIsUserUnlocked(context)) {
                return null;
            }
            try {
                return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            } catch (Exception | LinkageError e) {
                CLog.w("Fallback CE SharedPreferences access failed: "
                        + e.getClass().getSimpleName());
                return null;
            }
        }

        SharedPreferences dePrefs;
        try {
            dePrefs = deContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        } catch (Exception | LinkageError e) {
            CLog.w("DE SharedPreferences access failed: " + e.getClass().getSimpleName());
            return null;
        }

        if (!migrationCompleted && !safeIsDeviceProtectedStorage(context)) {
            if (dePrefs.getBoolean(KEY_DE_MIGRATED, false)) {
                migrationCompleted = true;
            } else if (safeIsUserUnlocked(context)) {
                // Only migrate legacy CE preferences once after the user has unlocked.
                boolean persistMigratedMarker = false;
                if (hasPersistedFingerprintData(dePrefs)) {
                    persistMigratedMarker = true;
                } else {
                    try {
                        boolean moved = deContext.moveSharedPreferencesFrom(context, PREFS_NAME);
                        if (moved) {
                            dePrefs = deContext.getSharedPreferences(
                                    PREFS_NAME, Context.MODE_PRIVATE);
                            persistMigratedMarker = true;
                        } else {
                            CLog.w("CE->DE SharedPreferences migration returned false");
                        }
                    } catch (Exception | LinkageError e) {
                        CLog.w("CE->DE SharedPreferences migration failed: "
                                + e.getClass().getSimpleName());
                    }
                }
                if (persistMigratedMarker) {
                    try {
                        dePrefs.edit().putBoolean(KEY_DE_MIGRATED, true).commit();
                    } catch (Exception | LinkageError ignored) {
                        // Best-effort marker write.
                    }
                }
                migrationCompleted = true;
            }
        }
        return dePrefs;
    }

    private boolean safeIsUserUnlocked(Context target) {
        try {
            return unlockChecker.test(target);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return false;
        }
    }

    private static Context safeCreateDeviceProtectedStorageContext(Context target) {
        try {
            return target.createDeviceProtectedStorageContext();
        } catch (Exception | LinkageError e) {
            CLog.w("createDeviceProtectedStorageContext failed: "
                    + e.getClass().getSimpleName());
            return null;
        }
    }

    private static boolean safeIsDeviceProtectedStorage(Context target) {
        try {
            return target.isDeviceProtectedStorage();
        } catch (Exception | LinkageError e) {
            return false;
        }
    }

    private static boolean hasPersistedFingerprintData(SharedPreferences prefs) {
        if (prefs == null) {
            return false;
        }
        return prefs.contains(KEY_SALT)
                || prefs.contains(KEY_ANCHOR_HARDWARE)
                || prefs.contains(KEY_LAST_HARDWARE);
    }

    /** Returns the per-install salt, creating and synchronously persisting it on first use. */
    public String getOrCreateSalt() {
        synchronized (STORE_LOCK) {
            SharedPreferences preferences = resolvePrefsLocked();
            if (preferences == null) {
                return getEphemeralSalt();
            }
            try {
                boolean keystoreBound = preferences.getBoolean(KEY_KEYSTORE_BOUND, false);
                String rawSalt = preferences.getString(KEY_SALT, null);
                if (rawSalt != null && !rawSalt.isEmpty()) {
                    KeystoreBackingStore.UnwrapResult unwrapped =
                            readProtectedValue(rawSalt, KEY_SALT, keystoreBound);
                    if (unwrapped.isOk()
                            && unwrapped.getPlaintext() != null
                            && !unwrapped.getPlaintext().isEmpty()) {
                        return unwrapped.getPlaintext();
                    }
                    if (unwrapped.isDeviceBindingBroken()) {
                        // Do NOT overwrite damaged/cloned salt; preserve tamper evidence.
                        CLog.w("Fingerprint salt device binding broken: " + unwrapped.getReason());
                        return getEphemeralSalt();
                    }
                    CLog.w("Fingerprint salt temporarily unreadable: " + unwrapped.getReason());
                    return getEphemeralSalt();
                }

                if (keystoreBound || hasWrappedBaselineFields(preferences)) {
                    // Salt entry was deleted from a keystore-bound store (or cloned XML):
                    // never generate a replacement key or overwrite store state.
                    CLog.w("Fingerprint salt missing on keystore-bound store; preserving tamper evidence");
                    return getEphemeralSalt();
                }

                String salt = generateRandomHex(32);
                SharedPreferences.Editor editor = preferences.edit();
                boolean[] wrapped = new boolean[] {false};
                putProtectedString(editor, KEY_SALT, salt, true, wrapped);
                editor.putLong(KEY_FIRST_SEEN, System.currentTimeMillis());
                if (wrapped[0] && !hasPersistedBaselineFields(preferences)) {
                    editor.putBoolean(KEY_KEYSTORE_BOUND, true);
                }
                boolean persisted = editor.commit();
                if (!persisted) {
                    CLog.w("Fingerprint salt commit returned false");
                }
                return salt;
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                CLog.e("Fingerprint salt access failed", e);
                return getEphemeralSalt();
            }
        }
    }

    private static boolean hasPersistedBaselineFields(SharedPreferences prefs) {
        return prefs.contains(KEY_ANCHOR_HARDWARE)
                || prefs.contains(KEY_ANCHOR_HW_BUCKETS)
                || prefs.contains(KEY_LAST_HARDWARE)
                || prefs.contains(KEY_LAST_HW_BUCKETS)
                || prefs.contains(KEY_LAST_SYSTEM);
    }

    private static boolean hasWrappedBaselineFields(SharedPreferences prefs) {
        return KeystoreBackingStore.isWrapped(prefs.getString(KEY_ANCHOR_HARDWARE, null))
                || KeystoreBackingStore.isWrapped(prefs.getString(KEY_ANCHOR_HW_BUCKETS, null))
                || KeystoreBackingStore.isWrapped(prefs.getString(KEY_LAST_HARDWARE, null))
                || KeystoreBackingStore.isWrapped(prefs.getString(KEY_LAST_HW_BUCKETS, null))
                || KeystoreBackingStore.isWrapped(prefs.getString(KEY_LAST_SYSTEM, null));
    }

    private DevicePosture.KeystoreSecurityLevel currentSecurityLevel() {
        return backingStore == null
                ? DevicePosture.KeystoreSecurityLevel.UNKNOWN
                : backingStore.getSecurityLevel();
    }

    private KeystoreBackingStore.UnwrapResult readProtectedValue(
            String rawValue, String key, boolean keystoreBound) {
        if (rawValue == null || rawValue.isEmpty()) {
            return KeystoreBackingStore.UnwrapResult.notEncrypted("");
        }
        if (backingStore == null) {
            if (KeystoreBackingStore.isWrapped(rawValue)) {
                return KeystoreBackingStore.UnwrapResult.unavailable(
                        "keystore_backing_unavailable");
            }
            return KeystoreBackingStore.UnwrapResult.notEncrypted(rawValue);
        }
        if (KeystoreBackingStore.isWrapped(rawValue)) {
            return backingStore.unwrap(rawValue, key);
        }
        if (keystoreBound) {
            return KeystoreBackingStore.UnwrapResult.tampered(
                    "plaintext_downgrade_tamper:" + key);
        }
        return KeystoreBackingStore.UnwrapResult.notEncrypted(rawValue);
    }

    private boolean putProtectedString(SharedPreferences.Editor editor,
                                       String key,
                                       String plaintext,
                                       boolean allowPlaintextFallback,
                                       boolean[] wrappedOut) {
        if (plaintext == null || plaintext.isEmpty()) {
            editor.putString(key, "");
            return true;
        }
        if (backingStore != null) {
            String wrapped = backingStore.wrap(plaintext, key);
            if (wrapped != null) {
                editor.putString(key, wrapped);
                if (wrappedOut != null && wrappedOut.length > 0) {
                    wrappedOut[0] = true;
                }
                return true;
            }
        }
        if (!allowPlaintextFallback) {
            return false;
        }
        editor.putString(key, plaintext);
        return false;
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
     * Compares the given ID against the immutable anchor baseline using
     * intersection semantics, validates Keystore GCM device binding, and probes
     * the optional lockscreen/biometric sentinel.
     *
     * <p>Never auto-overwrites {@code anchor_hw} or persisted ciphertext on
     * {@code device_binding_broken} or hardware drift.
     */
    public Continuity recordAndCompare(FingerprintId id) {
        synchronized (STORE_LOCK) {
            boolean lockscreenReset = backingStore != null
                    && backingStore.probeLockscreenSentinel()
                    == KeystoreBackingStore.SentinelStatus.PERMANENTLY_INVALIDATED;

            SharedPreferences preferences = resolvePrefsLocked();
            if (preferences == null || id == null) {
                return new Continuity(State.UNKNOWN, 0, 0, 0, Collections.emptyList(),
                        false, "", currentSecurityLevel(), lockscreenReset);
            }
            try {
                boolean keystoreBound = preferences.getBoolean(KEY_KEYSTORE_BOUND, false);
                long firstSeen = preferences.getLong(KEY_FIRST_SEEN, 0L);
                int observations = preferences.getInt(KEY_OBSERVATIONS, 0);
                int driftCount = preferences.getInt(KEY_DRIFT_COUNT, 0);
                int nextObservations = observations == Integer.MAX_VALUE
                        ? Integer.MAX_VALUE : observations + 1;
                long effectiveFirstSeen = firstSeen == 0L
                        ? System.currentTimeMillis() : firstSeen;

                // Validate integrity of all persisted protected fields before comparison.
                String rawSalt = preferences.getString(KEY_SALT, null);
                if ((rawSalt == null || rawSalt.isEmpty())
                        && (keystoreBound || hasWrappedBaselineFields(preferences))) {
                    return brokenContinuity(effectiveFirstSeen, nextObservations, driftCount,
                            "salt_missing_tamper", currentSecurityLevel(), lockscreenReset);
                }
                KeystoreBackingStore.UnwrapResult saltRes =
                        readProtectedValue(rawSalt, KEY_SALT, keystoreBound);
                if (saltRes.isDeviceBindingBroken()) {
                    return brokenContinuity(effectiveFirstSeen, nextObservations, driftCount,
                            saltRes.getReason(), currentSecurityLevel(), lockscreenReset);
                }

                String rawAnchorHw = preferences.getString(KEY_ANCHOR_HARDWARE, "");
                KeystoreBackingStore.UnwrapResult anchorHwRes =
                        readProtectedValue(rawAnchorHw, KEY_ANCHOR_HARDWARE, keystoreBound);
                if (anchorHwRes.isDeviceBindingBroken()) {
                    return brokenContinuity(effectiveFirstSeen, nextObservations, driftCount,
                            anchorHwRes.getReason(), currentSecurityLevel(), lockscreenReset);
                }

                String rawAnchorBuckets = preferences.getString(KEY_ANCHOR_HW_BUCKETS, "");
                KeystoreBackingStore.UnwrapResult anchorBucketsRes =
                        readProtectedValue(rawAnchorBuckets, KEY_ANCHOR_HW_BUCKETS, keystoreBound);
                if (anchorBucketsRes.isDeviceBindingBroken()) {
                    return brokenContinuity(effectiveFirstSeen, nextObservations, driftCount,
                            anchorBucketsRes.getReason(), currentSecurityLevel(), lockscreenReset);
                }

                String rawLastHw = preferences.getString(KEY_LAST_HARDWARE, "");
                KeystoreBackingStore.UnwrapResult lastHwRes =
                        readProtectedValue(rawLastHw, KEY_LAST_HARDWARE, keystoreBound);
                if (lastHwRes.isDeviceBindingBroken()) {
                    return brokenContinuity(effectiveFirstSeen, nextObservations, driftCount,
                            lastHwRes.getReason(), currentSecurityLevel(), lockscreenReset);
                }

                String rawLastBuckets = preferences.getString(KEY_LAST_HW_BUCKETS, "");
                KeystoreBackingStore.UnwrapResult lastBucketsRes =
                        readProtectedValue(rawLastBuckets, KEY_LAST_HW_BUCKETS, keystoreBound);
                if (lastBucketsRes.isDeviceBindingBroken()) {
                    return brokenContinuity(effectiveFirstSeen, nextObservations, driftCount,
                            lastBucketsRes.getReason(), currentSecurityLevel(), lockscreenReset);
                }

                String rawLastSys = preferences.getString(KEY_LAST_SYSTEM, "");
                KeystoreBackingStore.UnwrapResult lastSysRes =
                        readProtectedValue(rawLastSys, KEY_LAST_SYSTEM, keystoreBound);
                if (lastSysRes.isDeviceBindingBroken()) {
                    return brokenContinuity(effectiveFirstSeen, nextObservations, driftCount,
                            lastSysRes.getReason(), currentSecurityLevel(), lockscreenReset);
                }

                if (!saltRes.isOk() || !anchorHwRes.isOk() || !anchorBucketsRes.isOk()
                        || !lastHwRes.isOk() || !lastBucketsRes.isOk() || !lastSysRes.isOk()) {
                    // Keystore temporarily unavailable while wrapped ciphertext exists:
                    // fail-safe to UNKNOWN without overwriting persisted baseline.
                    return new Continuity(State.UNKNOWN, effectiveFirstSeen, nextObservations,
                            driftCount, Collections.emptyList(), false, "",
                            currentSecurityLevel(), lockscreenReset);
                }

                String anchorHardware = anchorHwRes.getPlaintext();
                Map<String, String> anchorBuckets = decodeBuckets(anchorBucketsRes.getPlaintext());
                boolean migratedLegacyAnchor = false;
                if ((anchorHardware == null || anchorHardware.isEmpty())
                        && anchorBuckets.isEmpty()) {
                    String legacyHardware = lastHwRes.getPlaintext();
                    Map<String, String> legacyBuckets =
                            decodeBuckets(lastBucketsRes.getPlaintext());
                    if ((legacyHardware != null && !legacyHardware.isEmpty())
                            || !legacyBuckets.isEmpty()) {
                        anchorHardware = legacyHardware;
                        anchorBuckets = legacyBuckets;
                        migratedLegacyAnchor = true;
                    }
                }

                String previousSystem = lastSysRes.getPlaintext();
                ComparisonOutcome outcome = compare(
                        anchorHardware, anchorBuckets, previousSystem, id);

                int nextDriftCount = driftCount;
                SharedPreferences.Editor editor = preferences.edit();
                editor.putInt(KEY_OBSERVATIONS, nextObservations);
                if (firstSeen == 0L) {
                    editor.putLong(KEY_FIRST_SEEN, effectiveFirstSeen);
                }

                boolean allowPlaintextFallback = !keystoreBound;
                boolean allWritesWrapped = true;
                boolean upgradedSalt = false;
                if (backingStore != null
                        && saltRes.getStatus() == KeystoreBackingStore.UnwrapStatus.NOT_ENCRYPTED
                        && saltRes.getPlaintext() != null && !saltRes.getPlaintext().isEmpty()) {
                    boolean[] saltWrapped = new boolean[] {false};
                    allWritesWrapped &= putProtectedString(
                            editor, KEY_SALT, saltRes.getPlaintext(),
                            allowPlaintextFallback, saltWrapped);
                    upgradedSalt = saltWrapped[0];
                }

                boolean anchorWrappedNow = false;
                boolean needUpgradePlaintextAnchor = backingStore != null && !keystoreBound
                        && ((anchorHwRes.getStatus() == KeystoreBackingStore.UnwrapStatus.NOT_ENCRYPTED
                        && anchorHardware != null && !anchorHardware.isEmpty())
                        || (anchorBucketsRes.getStatus() == KeystoreBackingStore.UnwrapStatus.NOT_ENCRYPTED
                        && !anchorBuckets.isEmpty()));

                if (migratedLegacyAnchor || needUpgradePlaintextAnchor) {
                    boolean[] w1 = new boolean[] {false};
                    boolean[] w2 = new boolean[] {false};
                    allWritesWrapped &= putProtectedString(editor, KEY_ANCHOR_HARDWARE,
                            anchorHardware == null ? "" : anchorHardware,
                            allowPlaintextFallback, w1);
                    allWritesWrapped &= putProtectedString(editor, KEY_ANCHOR_HW_BUCKETS,
                            encodeBuckets(anchorBuckets),
                            allowPlaintextFallback, w2);
                    anchorWrappedNow = w1[0] || w2[0];
                }

                boolean wroteWrappedReliable = false;
                if (id.isHardwareLayerReliable()) {
                    boolean[] wLastHw = new boolean[] {false};
                    boolean[] wLastSys = new boolean[] {false};
                    boolean[] wLastBuckets = new boolean[] {false};
                    allWritesWrapped &= putProtectedString(
                            editor, KEY_LAST_HARDWARE, id.getHardwareId(),
                            allowPlaintextFallback, wLastHw);
                    allWritesWrapped &= putProtectedString(
                            editor, KEY_LAST_SYSTEM, id.getSystemId(),
                            allowPlaintextFallback, wLastSys);
                    allWritesWrapped &= putProtectedString(editor, KEY_LAST_HW_BUCKETS,
                            encodeBuckets(id.getHardwareBucketDigests()),
                            allowPlaintextFallback, wLastBuckets);
                    wroteWrappedReliable = wLastHw[0] || wLastSys[0] || wLastBuckets[0];

                    if (outcome.state == State.FIRST_OBSERVATION) {
                        boolean[] wAnchorHw = new boolean[] {false};
                        boolean[] wAnchorBuckets = new boolean[] {false};
                        allWritesWrapped &= putProtectedString(editor, KEY_ANCHOR_HARDWARE,
                                id.getHardwareId(), allowPlaintextFallback, wAnchorHw);
                        allWritesWrapped &= putProtectedString(editor, KEY_ANCHOR_HW_BUCKETS,
                                encodeBuckets(id.getHardwareBucketDigests()),
                                allowPlaintextFallback, wAnchorBuckets);
                        anchorWrappedNow = anchorWrappedNow || wAnchorHw[0] || wAnchorBuckets[0];
                    } else if (outcome.state == State.HARDWARE_CHANGED) {
                        nextDriftCount = driftCount == Integer.MAX_VALUE
                                ? Integer.MAX_VALUE : driftCount + 1;
                        editor.putInt(KEY_DRIFT_COUNT, nextDriftCount);
                    } else if (outcome.state == State.STABLE
                            || outcome.state == State.SYSTEM_CHANGED) {
                        Map<String, String> mergedAnchor = new LinkedHashMap<>(anchorBuckets);
                        boolean addedBucket = false;
                        for (Map.Entry<String, String> entry
                                : id.getHardwareBucketDigests().entrySet()) {
                            if (!mergedAnchor.containsKey(entry.getKey())) {
                                mergedAnchor.put(entry.getKey(), entry.getValue());
                                addedBucket = true;
                            }
                        }
                        if (addedBucket) {
                            boolean[] wMerged = new boolean[] {false};
                            allWritesWrapped &= putProtectedString(editor, KEY_ANCHOR_HW_BUCKETS,
                                    encodeBuckets(mergedAnchor), allowPlaintextFallback, wMerged);
                            anchorWrappedNow = anchorWrappedNow || wMerged[0];
                        }
                    }
                }

                // Never downgrade a keystore-bound store to plaintext on a transient wrap failure.
                if (keystoreBound && !allWritesWrapped) {
                    CLog.w("Transient Keystore wrap failure on bound store; preserving existing ciphertext");
                    return new Continuity(outcome.state, effectiveFirstSeen,
                            nextObservations, nextDriftCount, outcome.changedBuckets,
                            false, "", currentSecurityLevel(), lockscreenReset);
                }

                boolean saltEncryptedOrAbsent = saltRes.getStatus() == KeystoreBackingStore.UnwrapStatus.OK
                        || upgradedSalt
                        || rawSalt == null || rawSalt.isEmpty();
                boolean anchorEncryptedOrAbsent = anchorWrappedNow
                        || ((rawAnchorHw == null || rawAnchorHw.isEmpty()
                                || KeystoreBackingStore.isWrapped(rawAnchorHw))
                        && (rawAnchorBuckets == null || rawAnchorBuckets.isEmpty()
                                || KeystoreBackingStore.isWrapped(rawAnchorBuckets)));
                boolean lastEncryptedOrAbsent = wroteWrappedReliable
                        || ((rawLastHw == null || rawLastHw.isEmpty()
                                || KeystoreBackingStore.isWrapped(rawLastHw))
                        && (rawLastBuckets == null || rawLastBuckets.isEmpty()
                                || KeystoreBackingStore.isWrapped(rawLastBuckets))
                        && (rawLastSys == null || rawLastSys.isEmpty()
                                || KeystoreBackingStore.isWrapped(rawLastSys)));
                if (!keystoreBound
                        && allWritesWrapped
                        && (upgradedSalt || anchorWrappedNow || wroteWrappedReliable)
                        && saltEncryptedOrAbsent
                        && anchorEncryptedOrAbsent
                        && lastEncryptedOrAbsent) {
                    editor.putBoolean(KEY_KEYSTORE_BOUND, true);
                }

                editor.apply();

                return new Continuity(outcome.state, effectiveFirstSeen,
                        nextObservations, nextDriftCount, outcome.changedBuckets,
                        false, "", currentSecurityLevel(), lockscreenReset);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                CLog.e("Fingerprint continuity check failed", e);
                return new Continuity(State.UNKNOWN, 0, 0, 0, Collections.emptyList(),
                        false, "", currentSecurityLevel(), lockscreenReset);
            }
        }
    }

    private static Continuity brokenContinuity(long firstSeenMs,
                                               int observations,
                                               int driftCount,
                                               String reason,
                                               DevicePosture.KeystoreSecurityLevel ksLevel,
                                               boolean lockscreenReset) {
        CLog.w("Fingerprint device binding broken: " + reason);
        return new Continuity(State.DEVICE_BINDING_BROKEN, firstSeenMs, observations,
                driftCount, Collections.emptyList(), true, reason, ksLevel, lockscreenReset);
    }

    /**
     * Explicitly clears the immutable anchor baseline, last-observed hardware/system
     * state, observation counter, and drift counter while keeping a valid per-install
     * salt. If the persisted salt itself is unreadable due to broken device binding,
     * removes the corrupted salt as well so legitimate device replacement resets cleanly.
     */
    public void resetBaseline() {
        synchronized (STORE_LOCK) {
            SharedPreferences preferences = resolvePrefsLocked();
            if (preferences == null) return;
            try {
                boolean keystoreBound = preferences.getBoolean(KEY_KEYSTORE_BOUND, false);
                String rawSalt = preferences.getString(KEY_SALT, null);
                boolean saltCorrupted = false;
                if (rawSalt != null && !rawSalt.isEmpty()) {
                    KeystoreBackingStore.UnwrapResult saltRes =
                            readProtectedValue(rawSalt, KEY_SALT, keystoreBound);
                    saltCorrupted = saltRes.isDeviceBindingBroken();
                }

                SharedPreferences.Editor editor = preferences.edit()
                        .remove(KEY_ANCHOR_HARDWARE)
                        .remove(KEY_ANCHOR_HW_BUCKETS)
                        .remove(KEY_LAST_HARDWARE)
                        .remove(KEY_LAST_HW_BUCKETS)
                        .remove(KEY_LAST_SYSTEM)
                        .remove(KEY_DRIFT_COUNT)
                        .remove(KEY_FIRST_SEEN)
                        .remove(KEY_OBSERVATIONS);
                if (saltCorrupted) {
                    editor.remove(KEY_SALT).remove(KEY_KEYSTORE_BOUND);
                } else if (rawSalt == null || !KeystoreBackingStore.isWrapped(rawSalt)) {
                    editor.remove(KEY_KEYSTORE_BOUND);
                }
                boolean committed = editor.commit();
                if (!committed) {
                    CLog.w("Fingerprint baseline reset commit returned false");
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                CLog.e("Fingerprint baseline reset failed", e);
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
        DEVICE_BINDING_BROKEN,
        INCONCLUSIVE,
        UNKNOWN
    }

    public static final class Continuity {
        private final State state;
        private final long firstSeenMs;
        private final int observationCount;
        private final int driftCount;
        private final List<String> changedBuckets;
        private final boolean deviceBindingBroken;
        private final String deviceBindingReason;
        private final DevicePosture.KeystoreSecurityLevel keystoreSecurityLevel;
        private final boolean lockscreenOrBiometricReset;

        Continuity(State state, long firstSeenMs, int observationCount,
                   List<String> changedBuckets) {
            this(state, firstSeenMs, observationCount, 0, changedBuckets,
                    false, "", DevicePosture.KeystoreSecurityLevel.UNKNOWN, false);
        }

        Continuity(State state, long firstSeenMs, int observationCount,
                   int driftCount, List<String> changedBuckets) {
            this(state, firstSeenMs, observationCount, driftCount, changedBuckets,
                    false, "", DevicePosture.KeystoreSecurityLevel.UNKNOWN, false);
        }

        Continuity(State state,
                   long firstSeenMs,
                   int observationCount,
                   int driftCount,
                   List<String> changedBuckets,
                   boolean deviceBindingBroken,
                   String deviceBindingReason,
                   DevicePosture.KeystoreSecurityLevel keystoreSecurityLevel,
                   boolean lockscreenOrBiometricReset) {
            this.state = state;
            this.firstSeenMs = firstSeenMs;
            this.observationCount = observationCount;
            this.driftCount = Math.max(0, driftCount);
            this.changedBuckets = changedBuckets == null
                    ? Collections.emptyList()
                    : List.copyOf(changedBuckets);
            this.deviceBindingBroken = deviceBindingBroken;
            this.deviceBindingReason = deviceBindingReason == null ? "" : deviceBindingReason;
            this.keystoreSecurityLevel = keystoreSecurityLevel == null
                    ? DevicePosture.KeystoreSecurityLevel.UNKNOWN
                    : keystoreSecurityLevel;
            this.lockscreenOrBiometricReset = lockscreenOrBiometricReset;
        }

        public State getState() { return state; }
        public long getFirstSeenMs() { return firstSeenMs; }
        public int getObservationCount() { return observationCount; }
        public int getDriftCount() { return driftCount; }
        public List<String> getChangedBuckets() { return changedBuckets; }
        public boolean isDeviceBindingBroken() { return deviceBindingBroken; }
        public String getDeviceBindingReason() { return deviceBindingReason; }
        public DevicePosture.KeystoreSecurityLevel getKeystoreSecurityLevel() {
            return keystoreSecurityLevel;
        }
        public boolean isLockscreenOrBiometricReset() { return lockscreenOrBiometricReset; }
    }
}
