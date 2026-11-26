package com.wsttxm.riskenginesdk.collector.java_layer;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.FingerprintHasher;
import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.DevicePosture;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Zero-permission collector capturing JCA security providers and non-threat
 * device security hygiene posture (lockscreen, storage encryption, hardware
 * keystore capability, biometric readiness, developer options, and ADB state).
 */
public class SecurityPostureCollector extends BaseCollector {

    public SecurityPostureCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "security_posture";
    }

    @Override
    protected void collect(CollectorResult result) {
        collectSecurityProviders(result);

        if (context != null) {
            collectLockscreenStatus(result);
            collectStorageEncryption(result);
            collectKeystoreCapability(result);
            collectBiometricStatus(result);
            collectDeveloperAndAdbSettings(result);
        }

        if (result.getValues().isEmpty()) {
            result.markUnsupported("security_posture_unavailable");
        }
    }

    private void collectSecurityProviders(CollectorResult result) {
        SafeExecutor.SafeResult<List<String>> safe = SafeExecutor.safe(() -> {
            Provider[] providers = Security.getProviders();
            if (providers == null || providers.length == 0) {
                return Collections.emptyList();
            }
            List<String> items = new ArrayList<>(providers.length);
            for (Provider provider : providers) {
                if (provider == null || provider.getName() == null) {
                    continue;
                }
                String info = provider.getInfo() == null ? "" : provider.getInfo().trim();
                items.add(provider.getName().trim() + ":" + info);
            }
            Collections.sort(items);
            return items;
        });
        List<String> items = safe.getOrNull();
        if (items != null && !items.isEmpty()) {
            result.addValue("providers_hash",
                    FingerprintHasher.sha256Utf8(String.join("|", items)));
            result.addValue("provider_count", String.valueOf(items.size()));
        }
    }

    private void collectLockscreenStatus(CollectorResult result) {
        SafeExecutor.SafeResult<Boolean> safe = SafeExecutor.safeWithTimeoutOrInline(
                SafeExecutor.TIMEOUT_SHORT_MS, () -> {
                    KeyguardManager km = (KeyguardManager)
                            context.getSystemService(Context.KEYGUARD_SERVICE);
                    return km == null ? null : km.isDeviceSecure();
                });
        if (safe.isSuccess() && safe.getOrNull() != null) {
            result.addValue("device_secure", String.valueOf(safe.getOrNull()));
        }
    }

    private void collectStorageEncryption(CollectorResult result) {
        SafeExecutor.SafeResult<DevicePosture.StorageEncryptionStatus> safe =
                SafeExecutor.safeWithTimeoutOrInline(SafeExecutor.TIMEOUT_SHORT_MS, () -> {
                    DevicePolicyManager dpm = (DevicePolicyManager)
                            context.getSystemService(Context.DEVICE_POLICY_SERVICE);
                    if (dpm == null) {
                        return null;
                    }
                    return mapEncryptionStatus(dpm.getStorageEncryptionStatus());
                });
        if (safe.isSuccess() && safe.getOrNull() != null) {
            result.addValue("storage_encryption", safe.getOrNull().name());
        }
    }

    private void collectKeystoreCapability(CollectorResult result) {
        SafeExecutor.SafeResult<DevicePosture.KeystoreSecurityLevel> safe =
                SafeExecutor.safeWithTimeoutOrInline(SafeExecutor.TIMEOUT_SHORT_MS, () -> {
                    PackageManager pm = context.getPackageManager();
                    if (pm != null && pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                        return DevicePosture.KeystoreSecurityLevel.STRONGBOX;
                    }
                    if (pm != null && Build.VERSION.SDK_INT >= 31
                            && pm.hasSystemFeature("android.hardware.hardware_keystore")) {
                        return DevicePosture.KeystoreSecurityLevel.TEE;
                    }
                    try {
                        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                        if (ks != null) {
                            return DevicePosture.KeystoreSecurityLevel.TEE;
                        }
                    } catch (Exception | LinkageError ignored) {
                        // Fall through to UNAVAILABLE below.
                    }
                    return DevicePosture.KeystoreSecurityLevel.UNAVAILABLE;
                });
        if (safe.isSuccess() && safe.getOrNull() != null) {
            result.addValue("keystore_level", safe.getOrNull().name());
        }
    }

    private void collectBiometricStatus(CollectorResult result) {
        SafeExecutor.SafeResult<DevicePosture.BiometricStatus> safe =
                SafeExecutor.safeWithTimeoutOrInline(SafeExecutor.TIMEOUT_SHORT_MS, () -> {
                    DevicePosture.BiometricStatus permitted = queryBiometricManagerIfPermitted();
                    if (permitted != null) {
                        return permitted;
                    }
                    PackageManager pm = context.getPackageManager();
                    if (pm == null) {
                        return null;
                    }
                    boolean hasBioHw = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
                            || pm.hasSystemFeature(PackageManager.FEATURE_FACE)
                            || pm.hasSystemFeature(PackageManager.FEATURE_IRIS);
                    return hasBioHw
                            ? DevicePosture.BiometricStatus.UNAVAILABLE
                            : DevicePosture.BiometricStatus.NO_HARDWARE;
                });
        if (safe.isSuccess() && safe.getOrNull() != null) {
            result.addValue("biometric_status", safe.getOrNull().name());
        }
    }

    /**
     * Queries {@link BiometricManager} only when the host app already declares
     * {@code USE_BIOMETRIC}; SDK AAR itself declares zero permissions.
     */
    @SuppressLint("MissingPermission")
    private DevicePosture.BiometricStatus queryBiometricManagerIfPermitted() {
        if (context.checkSelfPermission(Manifest.permission.USE_BIOMETRIC)
                != PackageManager.PERMISSION_GRANTED) {
            return null;
        }
        BiometricManager bm = context.getSystemService(BiometricManager.class);
        if (bm == null) {
            return null;
        }
        int code = bm.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.BIOMETRIC_WEAK);
        return mapBiometricCode(code);
    }

    private void collectDeveloperAndAdbSettings(CollectorResult result) {
        SafeExecutor.SafeResult<Void> safe = SafeExecutor.safe(() -> {
            ContentResolver cr = context.getContentResolver();
            if (cr == null) {
                return null;
            }
            int dev = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1);
            if (dev >= 0) {
                result.addValue("dev_mode", String.valueOf(dev != 0));
            }
            int adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, -1);
            if (adb >= 0) {
                result.addValue("adb_enabled", String.valueOf(adb != 0));
            }
            return null;
        });
        // Ignore failures; unavailable settings remain omitted.
        safe.isSuccess();
    }

    public static DevicePosture.StorageEncryptionStatus mapEncryptionStatus(int status) {
        switch (status) {
            case DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED:
                return DevicePosture.StorageEncryptionStatus.UNSUPPORTED;
            case DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE:
                return DevicePosture.StorageEncryptionStatus.INACTIVE;
            case DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY:
                return DevicePosture.StorageEncryptionStatus.ACTIVE_DEFAULT_KEY;
            case DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE:
                return DevicePosture.StorageEncryptionStatus.ACTIVE;
            case DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER:
                return DevicePosture.StorageEncryptionStatus.ACTIVE_PER_USER;
            default:
                return DevicePosture.StorageEncryptionStatus.UNKNOWN;
        }
    }

    public static DevicePosture.BiometricStatus mapBiometricCode(int code) {
        switch (code) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return DevicePosture.BiometricStatus.READY;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return DevicePosture.BiometricStatus.NONE_ENROLLED;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                return DevicePosture.BiometricStatus.NO_HARDWARE;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                return DevicePosture.BiometricStatus.HARDWARE_UNAVAILABLE;
            default:
                return DevicePosture.BiometricStatus.UNAVAILABLE;
        }
    }

    /** Constructs a {@link DevicePosture} snapshot from collected {@link DeviceFingerprint} results. */
    public static DevicePosture fromFingerprint(DeviceFingerprint fingerprint) {
        if (fingerprint == null) {
            return DevicePosture.empty();
        }
        CollectorResult postureResult = fingerprint.getResults().get("security_posture");
        CollectorResult adbResult = fingerprint.getResults().get("adb_state");
        return toDevicePosture(postureResult, adbResult);
    }

    public static DevicePosture toDevicePosture(CollectorResult postureResult,
                                                CollectorResult adbResult) {
        DevicePosture.Builder builder = new DevicePosture.Builder();
        if (postureResult != null && postureResult.getStatus() == CollectorResult.Status.SUCCESS) {
            Map<String, String> values = postureResult.getValues();
            builder.setDeviceSecure(parseNullableBoolean(values.get("device_secure")));
            builder.setStorageEncryptionStatus(parseEnum(
                    DevicePosture.StorageEncryptionStatus.class,
                    values.get("storage_encryption"),
                    DevicePosture.StorageEncryptionStatus.UNKNOWN));
            builder.setKeystoreSecurityLevel(parseEnum(
                    DevicePosture.KeystoreSecurityLevel.class,
                    values.get("keystore_level"),
                    DevicePosture.KeystoreSecurityLevel.UNKNOWN));
            builder.setBiometricStatus(parseEnum(
                    DevicePosture.BiometricStatus.class,
                    values.get("biometric_status"),
                    DevicePosture.BiometricStatus.UNKNOWN));
            builder.setDeveloperOptionsEnabled(parseNullableBoolean(values.get("dev_mode")));
            builder.setAdbEnabled(parseNullableBoolean(values.get("adb_enabled")));
            if ("true".equalsIgnoreCase(values.get("lockscreen_or_biometric_reset"))) {
                builder.setLockscreenOrBiometricReset(true);
            }
            builder.setEvaluatedAtMs(postureResult.getTimestampMs());
        }
        if (adbResult != null && adbResult.getStatus() == CollectorResult.Status.SUCCESS) {
            Map<String, String> adbVals = adbResult.getValues();
            if (postureResult == null || !postureResult.getValues().containsKey("adb_enabled")) {
                String enabled = adbVals.get("adb_enabled");
                if ("1".equals(enabled) || "true".equalsIgnoreCase(enabled)) {
                    builder.setAdbEnabled(Boolean.TRUE);
                } else if ("0".equals(enabled) || "false".equalsIgnoreCase(enabled)) {
                    builder.setAdbEnabled(Boolean.FALSE);
                }
            }
        }
        return builder.build();
    }

    private static Boolean parseNullableBoolean(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        if ("true".equalsIgnoreCase(raw.trim()) || "1".equals(raw.trim())) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(raw.trim()) || "0".equals(raw.trim())) {
            return Boolean.FALSE;
        }
        return null;
    }

    private static <E extends Enum<E>> E parseEnum(Class<E> enumType, String raw, E fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Enum.valueOf(enumType, raw.trim());
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }
}
