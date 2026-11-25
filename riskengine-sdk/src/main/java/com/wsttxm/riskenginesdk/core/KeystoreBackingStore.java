package com.wsttxm.riskenginesdk.core;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.security.keystore.UserNotAuthenticatedException;

import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.util.CLog;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Hardware-backed AES-256-GCM wrapping store over {@code AndroidKeyStore}.
 *
 * <p>Prefers StrongBox-backed keys and automatically falls back to TEE when
 * {@link StrongBoxUnavailableException} is thrown, recording the actual
 * {@link DevicePosture.KeystoreSecurityLevel} via {@link KeyInfo}.
 *
 * <p>Detects cross-device cloning and local XML tampering: if wrapped ciphertext
 * exists on disk while the hardware-bound key is missing or GCM authentication
 * fails, {@link UnwrapResult#isDeviceBindingBroken()} returns {@code true}.
 * Also probes an optional lockscreen/biometric sentinel key to surface
 * {@code lockscreen_or_biometric_reset} posture telemetry on
 * {@link KeyPermanentlyInvalidatedException}.
 */
public final class KeystoreBackingStore {
    public static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    public static final String WRAP_KEY_ALIAS = "riskengine_fp_wrap_key";
    public static final String SENTINEL_KEY_ALIAS = "riskengine_fp_lock_sentinel";
    public static final String ENVELOPE_PREFIX = "v2gcm:";

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH_BITS / 8;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public enum UnwrapStatus {
        OK,
        NOT_ENCRYPTED,
        KEY_MISSING,
        TAMPERED_OR_AUTH_FAILED,
        UNAVAILABLE
    }

    public enum SentinelStatus {
        INTACT,
        PERMANENTLY_INVALIDATED,
        NOT_CONFIGURED,
        UNAVAILABLE
    }

    public static final class UnwrapResult {
        private final UnwrapStatus status;
        private final String plaintext;
        private final String reason;

        private UnwrapResult(UnwrapStatus status, String plaintext, String reason) {
            this.status = status;
            this.plaintext = plaintext;
            this.reason = reason == null ? "" : reason;
        }

        public static UnwrapResult ok(String plaintext) {
            return new UnwrapResult(UnwrapStatus.OK, plaintext, "");
        }

        public static UnwrapResult notEncrypted(String plaintext) {
            return new UnwrapResult(UnwrapStatus.NOT_ENCRYPTED, plaintext, "");
        }

        public static UnwrapResult keyMissing(String reason) {
            return new UnwrapResult(UnwrapStatus.KEY_MISSING, null, reason);
        }

        public static UnwrapResult tampered(String reason) {
            return new UnwrapResult(UnwrapStatus.TAMPERED_OR_AUTH_FAILED, null, reason);
        }

        public static UnwrapResult unavailable(String reason) {
            return new UnwrapResult(UnwrapStatus.UNAVAILABLE, null, reason);
        }

        public UnwrapStatus getStatus() {
            return status;
        }

        public String getPlaintext() {
            return plaintext;
        }

        public String getReason() {
            return reason;
        }

        public boolean isOk() {
            return status == UnwrapStatus.OK || status == UnwrapStatus.NOT_ENCRYPTED;
        }

        public boolean isDeviceBindingBroken() {
            return status == UnwrapStatus.KEY_MISSING
                    || status == UnwrapStatus.TAMPERED_OR_AUTH_FAILED;
        }
    }

    /** Abstraction over AndroidKeyStore operations for deterministic JVM unit tests. */
    public interface KeyProvider {
        /** Returns the existing key for {@code alias}, or {@code null} if absent. */
        SecretKey loadKey(String alias) throws Exception;

        /** Generates a 256-bit AES-GCM key, requesting StrongBox when {@code strongBoxBacked} is true. */
        SecretKey generateKey(String alias, boolean strongBoxBacked) throws Exception;

        /** Resolves the effective hardware/software security level of {@code key}. */
        DevicePosture.KeystoreSecurityLevel querySecurityLevel(
                SecretKey key, boolean createdWithStrongBox);

        /**
         * Returns {@code true} when the underlying JCE provider expects a caller-generated
         * 12-byte GCM IV (e.g. standard JCE {@code SecretKeySpec}); AndroidKeyStore with
         * {@code setRandomizedEncryptionRequired(true)} generates its own hardware IV.
         */
        default boolean callerProvidesIv() {
            return false;
        }

        /**
         * Probes the optional lockscreen/biometric sentinel key. Implementations may
         * either return {@link SentinelStatus#PERMANENTLY_INVALIDATED} or throw
         * {@link KeyPermanentlyInvalidatedException}.
         */
        default SentinelStatus probeSentinelKey(String alias) throws Exception {
            return SentinelStatus.UNAVAILABLE;
        }
    }

    private final KeyProvider keyProvider;
    private final Object keyLock = new Object();
    private volatile DevicePosture.KeystoreSecurityLevel securityLevel =
            DevicePosture.KeystoreSecurityLevel.UNKNOWN;
    private volatile boolean strongBoxFallbackTriggered;

    public KeystoreBackingStore(KeyProvider keyProvider) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider must not be null");
    }

    public static KeystoreBackingStore createDefault(Context context) {
        return new KeystoreBackingStore(new AndroidKeyStoreKeyProvider(context));
    }

    public static boolean isWrapped(String value) {
        return value != null && value.startsWith(ENVELOPE_PREFIX);
    }

    public DevicePosture.KeystoreSecurityLevel getSecurityLevel() {
        return securityLevel;
    }

    public boolean wasStrongBoxFallbackTriggered() {
        return strongBoxFallbackTriggered;
    }

    /**
     * Encrypts {@code plaintext} with AES-256-GCM (random 12-byte IV, 128-bit tag)
     * and optional AAD binding. Returns {@code null} when Keystore is unavailable so
     * callers can degrade gracefully without crashing.
     */
    public String wrap(String plaintext, String aad) {
        if (plaintext == null) {
            return null;
        }
        try {
            SecretKey key = getOrCreateWrapKey();
            if (key == null) {
                return null;
            }
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            byte[] iv;
            if (keyProvider.callerProvidesIv()) {
                iv = new byte[GCM_IV_LENGTH_BYTES];
                SECURE_RANDOM.nextBytes(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key);
                iv = cipher.getIV();
                if (iv == null || iv.length != GCM_IV_LENGTH_BYTES) {
                    iv = new byte[GCM_IV_LENGTH_BYTES];
                    SECURE_RANDOM.nextBytes(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key,
                            new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
                }
            }
            if (aad != null && !aad.isEmpty()) {
                cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            }
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
            return ENVELOPE_PREFIX
                    + encoder.encodeToString(iv)
                    + ":"
                    + encoder.encodeToString(ciphertext);
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.w("Keystore wrap failed: " + e.getClass().getSimpleName());
            return null;
        }
    }

    /**
     * Unwraps a persisted value. Plaintext values without {@link #ENVELOPE_PREFIX}
     * return {@link UnwrapStatus#NOT_ENCRYPTED} for v1 backward compatibility.
     * Wrapped values with missing keys or invalid GCM tags return
     * {@link UnwrapResult#isDeviceBindingBroken()} == {@code true} without creating
     * or overwriting any key.
     */
    public UnwrapResult unwrap(String storedValue, String aad) {
        if (storedValue == null) {
            return UnwrapResult.notEncrypted(null);
        }
        if (!isWrapped(storedValue)) {
            return UnwrapResult.notEncrypted(storedValue);
        }

        String body = storedValue.substring(ENVELOPE_PREFIX.length());
        int sep = body.indexOf(':');
        if (sep <= 0 || sep + 1 >= body.length() || body.indexOf(':', sep + 1) >= 0) {
            return UnwrapResult.tampered("cipher_envelope_malformed");
        }
        byte[] iv;
        byte[] ciphertext;
        try {
            Base64.Decoder decoder = Base64.getDecoder();
            iv = decoder.decode(body.substring(0, sep));
            ciphertext = decoder.decode(body.substring(sep + 1));
        } catch (IllegalArgumentException e) {
            return UnwrapResult.tampered("cipher_base64_malformed");
        }
        if (iv.length != GCM_IV_LENGTH_BYTES || ciphertext.length < GCM_TAG_LENGTH_BYTES) {
            return UnwrapResult.tampered("cipher_length_invalid");
        }

        SecretKey key;
        try {
            key = loadExistingWrapKey();
        } catch (KeyStoreException | NoSuchProviderException e) {
            securityLevel = DevicePosture.KeystoreSecurityLevel.UNAVAILABLE;
            return UnwrapResult.unavailable("keystore_provider_unavailable");
        } catch (UnrecoverableKeyException | InvalidKeyException e) {
            if (isKeyPermanentlyInvalidated(e)) {
                return UnwrapResult.keyMissing("keystore_key_invalidated");
            }
            return UnwrapResult.keyMissing("keystore_key_unusable");
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            if (isKeyPermanentlyInvalidated(e)) {
                return UnwrapResult.keyMissing("keystore_key_invalidated");
            }
            if (isKeystoreProviderUnavailable(e)) {
                securityLevel = DevicePosture.KeystoreSecurityLevel.UNAVAILABLE;
                return UnwrapResult.unavailable("keystore_provider_unavailable");
            }
            CLog.w("Keystore key load failed: " + e.getClass().getSimpleName());
            return UnwrapResult.unavailable("keystore_load_failed");
        }

        if (key == null) {
            return UnwrapResult.keyMissing("keystore_key_missing");
        }

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            if (aad != null && !aad.isEmpty()) {
                cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            }
            byte[] plainBytes = cipher.doFinal(ciphertext);
            return UnwrapResult.ok(new String(plainBytes, StandardCharsets.UTF_8));
        } catch (AEADBadTagException e) {
            return UnwrapResult.tampered("gcm_auth_tag_failed");
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            return UnwrapResult.tampered("gcm_decrypt_failed");
        } catch (UserNotAuthenticatedException e) {
            return UnwrapResult.unavailable("keystore_user_not_authenticated");
        } catch (InvalidKeyException e) {
            if (isKeyPermanentlyInvalidated(e)) {
                return UnwrapResult.keyMissing("keystore_key_invalidated");
            }
            if (isUserNotAuthenticated(e)) {
                return UnwrapResult.unavailable("keystore_user_not_authenticated");
            }
            return UnwrapResult.tampered("gcm_invalid_key");
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            if (isKeyPermanentlyInvalidated(e)) {
                return UnwrapResult.keyMissing("keystore_key_invalidated");
            }
            if (isUserNotAuthenticated(e)) {
                return UnwrapResult.unavailable("keystore_user_not_authenticated");
            }
            CLog.w("Keystore unwrap failed: " + e.getClass().getSimpleName());
            return UnwrapResult.unavailable("keystore_unwrap_error");
        }
    }

    /**
     * Probes the optional lockscreen/biometric sentinel key. Never throws; converts
     * {@link KeyPermanentlyInvalidatedException} into
     * {@link SentinelStatus#PERMANENTLY_INVALIDATED}.
     */
    public SentinelStatus probeLockscreenSentinel() {
        try {
            SentinelStatus status = keyProvider.probeSentinelKey(SENTINEL_KEY_ALIAS);
            return status == null ? SentinelStatus.UNAVAILABLE : status;
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            if (isKeyPermanentlyInvalidated(e)) {
                return SentinelStatus.PERMANENTLY_INVALIDATED;
            }
            CLog.d("Sentinel probe unavailable: " + e.getClass().getSimpleName());
            return SentinelStatus.UNAVAILABLE;
        }
    }

    private SecretKey loadExistingWrapKey() throws Exception {
        synchronized (keyLock) {
            SecretKey existing = keyProvider.loadKey(WRAP_KEY_ALIAS);
            if (existing != null) {
                updateSecurityLevel(existing, false);
            }
            return existing;
        }
    }

    /**
     * Loads the existing wrapping key, or creates one with StrongBox -> TEE fallback.
     * Never called during {@link #unwrap} so missing keys are never silently recreated.
     */
    SecretKey getOrCreateWrapKey() {
        synchronized (keyLock) {
            try {
                SecretKey existing = keyProvider.loadKey(WRAP_KEY_ALIAS);
                if (existing != null) {
                    updateSecurityLevel(existing, false);
                    return existing;
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                if (isKeystoreProviderUnavailable(e)) {
                    securityLevel = DevicePosture.KeystoreSecurityLevel.UNAVAILABLE;
                    return null;
                }
                CLog.w("Existing wrap key load failed: " + e.getClass().getSimpleName());
            }

            // Attempt StrongBox first; degrade to TEE on StrongBoxUnavailableException.
            try {
                SecretKey strongBoxKey = keyProvider.generateKey(WRAP_KEY_ALIAS, true);
                if (strongBoxKey != null) {
                    updateSecurityLevel(strongBoxKey, true);
                    return strongBoxKey;
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                if (isKeystoreProviderUnavailable(e)) {
                    securityLevel = DevicePosture.KeystoreSecurityLevel.UNAVAILABLE;
                    return null;
                }
                if (isStrongBoxUnavailable(e)) {
                    strongBoxFallbackTriggered = true;
                    CLog.i("StrongBox unavailable for fingerprint wrap key; falling back to TEE");
                } else {
                    strongBoxFallbackTriggered = true;
                    CLog.w("StrongBox key generation failed (" + e.getClass().getSimpleName()
                            + "); falling back to TEE");
                }
            }

            try {
                SecretKey teeKey = keyProvider.generateKey(WRAP_KEY_ALIAS, false);
                if (teeKey != null) {
                    updateSecurityLevel(teeKey, false);
                    return teeKey;
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                CLog.w("TEE wrap key generation failed: " + e.getClass().getSimpleName());
            }
            securityLevel = DevicePosture.KeystoreSecurityLevel.UNAVAILABLE;
            return null;
        }
    }

    private void updateSecurityLevel(SecretKey key, boolean createdWithStrongBox) {
        try {
            DevicePosture.KeystoreSecurityLevel resolved =
                    keyProvider.querySecurityLevel(key, createdWithStrongBox);
            if (resolved != null && resolved != DevicePosture.KeystoreSecurityLevel.UNKNOWN) {
                securityLevel = resolved;
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.d("KeyInfo security level query failed: " + e.getClass().getSimpleName());
        }
    }

    static boolean isStrongBoxUnavailable(Throwable throwable) {
        Throwable cur = throwable;
        int depth = 0;
        while (cur != null && depth++ < 8) {
            if (cur instanceof StrongBoxUnavailableException) {
                return true;
            }
            if ("StrongBoxUnavailableException".equals(cur.getClass().getSimpleName())) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    static boolean isKeyPermanentlyInvalidated(Throwable throwable) {
        Throwable cur = throwable;
        int depth = 0;
        while (cur != null && depth++ < 8) {
            if (cur instanceof KeyPermanentlyInvalidatedException) {
                return true;
            }
            if ("KeyPermanentlyInvalidatedException".equals(cur.getClass().getSimpleName())) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    static boolean isUserNotAuthenticated(Throwable throwable) {
        Throwable cur = throwable;
        int depth = 0;
        while (cur != null && depth++ < 8) {
            if (cur instanceof UserNotAuthenticatedException) {
                return true;
            }
            if ("UserNotAuthenticatedException".equals(cur.getClass().getSimpleName())) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    private static boolean isKeystoreProviderUnavailable(Throwable throwable) {
        Throwable cur = throwable;
        int depth = 0;
        while (cur != null && depth++ < 8) {
            if (cur instanceof NoSuchProviderException) {
                return true;
            }
            if (cur instanceof KeyStoreException) {
                String msg = cur.getMessage();
                if (msg != null && msg.contains(ANDROID_KEYSTORE)) {
                    return true;
                }
            }
            cur = cur.getCause();
        }
        return false;
    }

    /** Production {@link KeyProvider} backed by {@code AndroidKeyStore}. */
    private static final class AndroidKeyStoreKeyProvider implements KeyProvider {
        private final Context context;

        AndroidKeyStoreKeyProvider(Context context) {
            Context app = context == null ? null : context.getApplicationContext();
            this.context = app != null ? app : context;
        }

        @Override
        public SecretKey loadKey(String alias) throws Exception {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (!ks.containsAlias(alias)) {
                return null;
            }
            Key key = ks.getKey(alias, null);
            return key instanceof SecretKey ? (SecretKey) key : null;
        }

        @Override
        public SecretKey generateKey(String alias, boolean strongBoxBacked) throws Exception {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(AES_KEY_SIZE_BITS)
                    .setRandomizedEncryptionRequired(true);
            if (strongBoxBacked) {
                builder.setIsStrongBoxBacked(true);
            }
            keyGenerator.init(builder.build());
            return keyGenerator.generateKey();
        }

        @Override
        public DevicePosture.KeystoreSecurityLevel querySecurityLevel(
                SecretKey key, boolean createdWithStrongBox) {
            if (key == null) {
                return DevicePosture.KeystoreSecurityLevel.UNKNOWN;
            }
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(
                        key.getAlgorithm(), ANDROID_KEYSTORE);
                KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
                if (keyInfo == null) {
                    return DevicePosture.KeystoreSecurityLevel.UNKNOWN;
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    int level = keyInfo.getSecurityLevel();
                    if (level == KeyProperties.SECURITY_LEVEL_STRONGBOX) {
                        return DevicePosture.KeystoreSecurityLevel.STRONGBOX;
                    }
                    if (level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                            || level == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE) {
                        return DevicePosture.KeystoreSecurityLevel.TEE;
                    }
                    if (level == KeyProperties.SECURITY_LEVEL_SOFTWARE) {
                        return DevicePosture.KeystoreSecurityLevel.SOFTWARE;
                    }
                    return DevicePosture.KeystoreSecurityLevel.UNKNOWN;
                }
                if (createdWithStrongBox) {
                    return DevicePosture.KeystoreSecurityLevel.STRONGBOX;
                }
                return isInsideSecureHardwareLegacy(keyInfo)
                        ? DevicePosture.KeystoreSecurityLevel.TEE
                        : DevicePosture.KeystoreSecurityLevel.SOFTWARE;
            } catch (Exception | LinkageError e) {
                return DevicePosture.KeystoreSecurityLevel.UNKNOWN;
            }
        }

        @SuppressWarnings("deprecation")
        private static boolean isInsideSecureHardwareLegacy(KeyInfo keyInfo) {
            return keyInfo.isInsideSecureHardware();
        }

        @Override
        public SentinelStatus probeSentinelKey(String alias) {
            try {
                KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
                ks.load(null);
                if (ks.containsAlias(alias)) {
                    Key key = ks.getKey(alias, null);
                    if (!(key instanceof SecretKey)) {
                        return SentinelStatus.UNAVAILABLE;
                    }
                    try {
                        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                        cipher.init(Cipher.ENCRYPT_MODE, (SecretKey) key);
                        return SentinelStatus.INTACT;
                    } catch (KeyPermanentlyInvalidatedException e) {
                        return SentinelStatus.PERMANENTLY_INVALIDATED;
                    } catch (UserNotAuthenticatedException e) {
                        // Key is still valid; only user authentication is required to use it.
                        return SentinelStatus.INTACT;
                    } catch (InvalidKeyException e) {
                        return isKeyPermanentlyInvalidated(e)
                                ? SentinelStatus.PERMANENTLY_INVALIDATED
                                : SentinelStatus.UNAVAILABLE;
                    }
                }

                // Only create the sentinel when the device currently has a secure lockscreen.
                if (context == null) {
                    return SentinelStatus.NOT_CONFIGURED;
                }
                KeyguardManager km = (KeyguardManager)
                        context.getSystemService(Context.KEYGUARD_SERVICE);
                if (km == null || !km.isDeviceSecure()) {
                    return SentinelStatus.NOT_CONFIGURED;
                }
                try {
                    KeyGenerator kg = KeyGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
                    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setKeySize(AES_KEY_SIZE_BITS)
                            .setUserAuthenticationRequired(true)
                            .setInvalidatedByBiometricEnrollment(true)
                            .setUserAuthenticationParameters(
                                    0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                            .build();
                    kg.init(spec);
                    kg.generateKey();
                    return SentinelStatus.INTACT;
                } catch (InvalidAlgorithmParameterException
                        | IllegalStateException
                        | ProviderException
                        | IllegalArgumentException e) {
                    // Device has lockscreen PIN/pattern without enrolled strong biometrics.
                    return SentinelStatus.NOT_CONFIGURED;
                }
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                if (isKeyPermanentlyInvalidated(e)) {
                    return SentinelStatus.PERMANENTLY_INVALIDATED;
                }
                return SentinelStatus.UNAVAILABLE;
            }
        }
    }
}
