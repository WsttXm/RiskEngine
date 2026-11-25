package com.wsttxm.riskenginesdk.model;

import java.util.Objects;

/**
 * Immutable snapshot of non-threat device security hygiene posture.
 *
 * <p>Evaluated separately from threat detection so host apps can observe lockscreen,
 * storage encryption, hardware keystore, biometric readiness, and developer/ADB state
 * without conflating missing security hygiene with active compromise.
 */
public final class DevicePosture {

    public enum StorageEncryptionStatus {
        UNSUPPORTED,
        INACTIVE,
        ACTIVE_DEFAULT_KEY,
        ACTIVE,
        ACTIVE_PER_USER,
        UNKNOWN
    }

    public enum KeystoreSecurityLevel {
        STRONGBOX,
        TEE,
        SOFTWARE,
        UNAVAILABLE,
        UNKNOWN
    }

    public enum BiometricStatus {
        READY,
        NONE_ENROLLED,
        NO_HARDWARE,
        HARDWARE_UNAVAILABLE,
        UNAVAILABLE,
        UNKNOWN
    }

    private final Boolean deviceSecure;
    private final StorageEncryptionStatus storageEncryptionStatus;
    private final KeystoreSecurityLevel keystoreSecurityLevel;
    private final BiometricStatus biometricStatus;
    private final Boolean developerOptionsEnabled;
    private final Boolean adbEnabled;
    private final Boolean systemVpn;
    private final Boolean unofficialStore;
    private final boolean lockscreenOrBiometricReset;
    private final long evaluatedAtMs;

    private DevicePosture(Builder builder) {
        this.deviceSecure = builder.deviceSecure;
        this.storageEncryptionStatus = builder.storageEncryptionStatus == null
                ? StorageEncryptionStatus.UNKNOWN
                : builder.storageEncryptionStatus;
        this.keystoreSecurityLevel = builder.keystoreSecurityLevel == null
                ? KeystoreSecurityLevel.UNKNOWN
                : builder.keystoreSecurityLevel;
        this.biometricStatus = builder.biometricStatus == null
                ? BiometricStatus.UNKNOWN
                : builder.biometricStatus;
        this.developerOptionsEnabled = builder.developerOptionsEnabled;
        this.adbEnabled = builder.adbEnabled;
        this.systemVpn = builder.systemVpn;
        this.unofficialStore = builder.unofficialStore;
        this.lockscreenOrBiometricReset = builder.lockscreenOrBiometricReset;
        this.evaluatedAtMs = builder.evaluatedAtMs > 0
                ? builder.evaluatedAtMs
                : System.currentTimeMillis();
    }

    public static DevicePosture empty() {
        return new Builder().build();
    }

    /** Tri-state lockscreen security status ({@code null} when unavailable). */
    public Boolean getDeviceSecure() {
        return deviceSecure;
    }

    /** Convenience boolean returning {@code true} only when lockscreen security is confirmed. */
    public boolean isDeviceSecure() {
        return Boolean.TRUE.equals(deviceSecure);
    }

    public StorageEncryptionStatus getStorageEncryptionStatus() {
        return storageEncryptionStatus;
    }

    public boolean isStorageEncrypted() {
        return storageEncryptionStatus == StorageEncryptionStatus.ACTIVE
                || storageEncryptionStatus == StorageEncryptionStatus.ACTIVE_DEFAULT_KEY
                || storageEncryptionStatus == StorageEncryptionStatus.ACTIVE_PER_USER;
    }

    public KeystoreSecurityLevel getKeystoreSecurityLevel() {
        return keystoreSecurityLevel;
    }

    public boolean isHardwareKeystoreBacked() {
        return keystoreSecurityLevel == KeystoreSecurityLevel.STRONGBOX
                || keystoreSecurityLevel == KeystoreSecurityLevel.TEE;
    }

    public BiometricStatus getBiometricStatus() {
        return biometricStatus;
    }

    /** Tri-state developer options status ({@code null} when unavailable). */
    public Boolean getDeveloperOptionsEnabled() {
        return developerOptionsEnabled;
    }

    public boolean isDeveloperOptionsEnabled() {
        return Boolean.TRUE.equals(developerOptionsEnabled);
    }

    /** Tri-state ADB enabled status ({@code null} when unavailable). */
    public Boolean getAdbEnabled() {
        return adbEnabled;
    }

    public boolean isAdbEnabled() {
        return Boolean.TRUE.equals(adbEnabled);
    }

    /** Tri-state system VPN status populated from {@code network_risk} ({@code null} when unknown). */
    public Boolean getSystemVpn() {
        return systemVpn;
    }

    public boolean isSystemVpn() {
        return Boolean.TRUE.equals(systemVpn);
    }

    /** Tri-state unofficial installer store status populated from {@code app_integrity} ({@code null} when unknown). */
    public Boolean getUnofficialStore() {
        return unofficialStore;
    }

    public boolean isUnofficialStore() {
        return Boolean.TRUE.equals(unofficialStore);
    }

    public boolean isLockscreenOrBiometricReset() {
        return lockscreenOrBiometricReset;
    }

    public long getEvaluatedAtMs() {
        return evaluatedAtMs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DevicePosture)) return false;
        DevicePosture that = (DevicePosture) o;
        return lockscreenOrBiometricReset == that.lockscreenOrBiometricReset
                && evaluatedAtMs == that.evaluatedAtMs
                && Objects.equals(deviceSecure, that.deviceSecure)
                && storageEncryptionStatus == that.storageEncryptionStatus
                && keystoreSecurityLevel == that.keystoreSecurityLevel
                && biometricStatus == that.biometricStatus
                && Objects.equals(developerOptionsEnabled, that.developerOptionsEnabled)
                && Objects.equals(adbEnabled, that.adbEnabled)
                && Objects.equals(systemVpn, that.systemVpn)
                && Objects.equals(unofficialStore, that.unofficialStore);
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceSecure, storageEncryptionStatus, keystoreSecurityLevel,
                biometricStatus, developerOptionsEnabled, adbEnabled,
                systemVpn, unofficialStore, lockscreenOrBiometricReset, evaluatedAtMs);
    }

    @Override
    public String toString() {
        return "DevicePosture{"
                + "deviceSecure=" + deviceSecure
                + ", storageEncryptionStatus=" + storageEncryptionStatus
                + ", keystoreSecurityLevel=" + keystoreSecurityLevel
                + ", biometricStatus=" + biometricStatus
                + ", developerOptionsEnabled=" + developerOptionsEnabled
                + ", adbEnabled=" + adbEnabled
                + ", systemVpn=" + systemVpn
                + ", unofficialStore=" + unofficialStore
                + ", lockscreenOrBiometricReset=" + lockscreenOrBiometricReset
                + ", evaluatedAtMs=" + evaluatedAtMs
                + '}';
    }

    public static final class Builder {
        private Boolean deviceSecure;
        private StorageEncryptionStatus storageEncryptionStatus = StorageEncryptionStatus.UNKNOWN;
        private KeystoreSecurityLevel keystoreSecurityLevel = KeystoreSecurityLevel.UNKNOWN;
        private BiometricStatus biometricStatus = BiometricStatus.UNKNOWN;
        private Boolean developerOptionsEnabled;
        private Boolean adbEnabled;
        private Boolean systemVpn;
        private Boolean unofficialStore;
        private boolean lockscreenOrBiometricReset;
        private long evaluatedAtMs;

        public Builder setDeviceSecure(Boolean deviceSecure) {
            this.deviceSecure = deviceSecure;
            return this;
        }

        public Builder setStorageEncryptionStatus(StorageEncryptionStatus status) {
            this.storageEncryptionStatus = status;
            return this;
        }

        public Builder setKeystoreSecurityLevel(KeystoreSecurityLevel level) {
            this.keystoreSecurityLevel = level;
            return this;
        }

        public Builder setBiometricStatus(BiometricStatus status) {
            this.biometricStatus = status;
            return this;
        }

        public Builder setDeveloperOptionsEnabled(Boolean enabled) {
            this.developerOptionsEnabled = enabled;
            return this;
        }

        public Builder setAdbEnabled(Boolean enabled) {
            this.adbEnabled = enabled;
            return this;
        }

        public Builder setSystemVpn(Boolean systemVpn) {
            this.systemVpn = systemVpn;
            return this;
        }

        public Builder setUnofficialStore(Boolean unofficialStore) {
            this.unofficialStore = unofficialStore;
            return this;
        }

        public Builder setLockscreenOrBiometricReset(boolean reset) {
            this.lockscreenOrBiometricReset = reset;
            return this;
        }

        public Builder setEvaluatedAtMs(long evaluatedAtMs) {
            this.evaluatedAtMs = evaluatedAtMs;
            return this;
        }

        public DevicePosture build() {
            return new DevicePosture(this);
        }
    }
}
