package com.wsttxm.riskenginesdk;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** Immutable configuration for a RiskEngine instance. */
public final class RiskEngineConfig {
    private static final long MAX_COLLECT_TIMEOUT_MS = 120_000;

    /** Built-in official app store installer presets used when no custom override is configured. */
    public static final Set<String> DEFAULT_TRUSTED_INSTALLER_PACKAGES =
            Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
                    "com.android.vending",              // Google Play
                    "com.huawei.appmarket",             // Huawei AppGallery
                    "com.hihonor.appmarket",            // Honor App Market
                    "com.xiaomi.market",                // Xiaomi GetApps
                    "com.heytap.market",                // OPPO / OnePlus / realme HeyTap Market
                    "com.oppo.market",                  // Legacy OPPO Market
                    "com.oneplus.market",               // OnePlus App Market
                    "com.bbk.appstore",                 // vivo App Store
                    "com.sec.android.app.samsungapps",  // Samsung Galaxy Store
                    "com.meizu.mstore",                 // Meizu App Store
                    "com.amazon.venezia"                // Amazon Appstore
            )));

    private final boolean enableRoot;
    private final boolean enableHookDetection;
    private final boolean enableEmulatorDetection;
    private final boolean enableDebugDetection;
    private final boolean enableCloudPhoneDetection;
    private final boolean enableCustomRomDetection;
    private final boolean enableAdbDetection;
    private final boolean enableAppIntegrityDetection;
    private final boolean enableMultiInstanceDetection;
    private final boolean enableNetworkRiskDetection;
    private final boolean enableLocationRiskDetection;
    private final boolean enableScreenAndFraudDetection;
    private final boolean enableThreatAppDetection;
    private final boolean enableAntiDumpable;
    private final boolean enablePeriodicMonitor;
    private final boolean enableIsolatedProcessProbe;
    private final boolean enableTeeAttestation;
    private final boolean debugLog;
    private final long collectTimeoutMs;
    private final PrivacyProfile privacyProfile;
    private final CollectScene collectScene;
    private final boolean collectAndroidId;
    private final boolean collectBootId;
    private final boolean collectDrmId;
    private final FingerprintVersion fingerprintVersion;
    private final FingerprintStability fingerprintStability;
    private final FingerprintHasher fingerprintHasher;
    private final String expectedPackageName;
    private final Set<String> expectedSigningCertSha256Base64;
    private final Set<String> trustedInstallerPackages;
    private final boolean hasCustomTrustedInstallerPackages;
    private final Set<String> additionalThreatPackages;
    private final ThreatAppPolicy threatAppPolicy;
    private final RiskPolicy riskPolicy;
    private final boolean hasCustomRiskPolicy;

    private RiskEngineConfig(Builder builder) {
        this.enableRoot = builder.enableRoot;
        this.enableHookDetection = builder.enableHookDetection;
        this.enableEmulatorDetection = builder.enableEmulatorDetection;
        this.enableDebugDetection = builder.enableDebugDetection;
        this.enableCloudPhoneDetection = builder.enableCloudPhoneDetection;
        this.enableCustomRomDetection = builder.enableCustomRomDetection;
        this.enableAdbDetection = builder.enableAdbDetection;
        this.enableAppIntegrityDetection = builder.enableAppIntegrityDetection;
        this.enableMultiInstanceDetection = builder.enableMultiInstanceDetection;
        this.enableNetworkRiskDetection = builder.enableNetworkRiskDetection;
        this.enableLocationRiskDetection = builder.enableLocationRiskDetection;
        this.enableScreenAndFraudDetection = builder.enableScreenAndFraudDetection;
        this.enableThreatAppDetection = builder.enableThreatAppDetection;
        this.enableAntiDumpable = builder.enableAntiDumpable;
        this.enablePeriodicMonitor = builder.enablePeriodicMonitor;
        this.enableIsolatedProcessProbe = builder.enableIsolatedProcessProbe;
        this.enableTeeAttestation = builder.enableTeeAttestation;
        this.debugLog = builder.debugLog;
        this.collectTimeoutMs = builder.collectTimeoutMs;
        this.privacyProfile = builder.privacyProfile;
        this.hasCustomRiskPolicy = builder.customRiskPolicy != null;
        if (builder.customRiskPolicy != null) {
            this.riskPolicy = builder.customRiskPolicy;
            this.collectScene = builder.customRiskPolicy.getBaseScene();
        } else {
            this.collectScene = builder.collectScene;
            this.riskPolicy = RiskPolicy.forScene(this.collectScene);
        }
        this.collectAndroidId = builder.collectAndroidId != null
                ? builder.collectAndroidId
                : builder.privacyProfile != PrivacyProfile.MINIMAL;
        this.collectBootId = builder.collectBootId != null
                ? builder.collectBootId
                : builder.privacyProfile == PrivacyProfile.DIAGNOSTIC;
        this.collectDrmId = builder.collectDrmId != null
                ? builder.collectDrmId
                : builder.privacyProfile == PrivacyProfile.DIAGNOSTIC;
        this.fingerprintVersion = builder.fingerprintVersion.resolve();
        this.fingerprintStability = builder.fingerprintStability;
        this.fingerprintHasher = builder.fingerprintHasher;
        this.expectedPackageName = builder.expectedPackageName;
        this.expectedSigningCertSha256Base64 = builder.expectedSigningCertSha256Base64.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(
                        new LinkedHashSet<>(builder.expectedSigningCertSha256Base64));
        this.hasCustomTrustedInstallerPackages = builder.customTrustedInstallerPackages != null;
        this.trustedInstallerPackages = builder.customTrustedInstallerPackages != null
                ? Collections.unmodifiableSet(
                        new LinkedHashSet<>(builder.customTrustedInstallerPackages))
                : DEFAULT_TRUSTED_INSTALLER_PACKAGES;
        this.additionalThreatPackages = builder.additionalThreatPackages.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(
                        new LinkedHashSet<>(builder.additionalThreatPackages));
        this.threatAppPolicy = builder.threatAppPolicy != null
                ? builder.threatAppPolicy
                : ThreatAppPolicy.DEFAULT;
    }

    public static final class Builder {
        private boolean enableRoot = true;
        private boolean enableHookDetection = true;
        private boolean enableEmulatorDetection = true;
        private boolean enableDebugDetection = true;
        private boolean enableCloudPhoneDetection = true;
        private boolean enableCustomRomDetection = true;
        private boolean enableAdbDetection = true;
        private boolean enableAppIntegrityDetection = true;
        private boolean enableMultiInstanceDetection = true;
        private boolean enableNetworkRiskDetection = true;
        private boolean enableLocationRiskDetection = true;
        private boolean enableScreenAndFraudDetection = true;
        private boolean enableThreatAppDetection = true;
        private boolean enableAntiDumpable = false;
        private boolean enablePeriodicMonitor = true;
        private boolean enableIsolatedProcessProbe = true;
        private boolean enableTeeAttestation = true;
        private boolean debugLog;
        private long collectTimeoutMs = 10_000;
        private PrivacyProfile privacyProfile = PrivacyProfile.BALANCED;
        private CollectScene collectScene = CollectScene.STANDARD;
        private RiskPolicy customRiskPolicy;
        private Boolean collectAndroidId;
        private Boolean collectBootId;
        private Boolean collectDrmId;
        private FingerprintVersion fingerprintVersion = FingerprintVersion.V2;
        private FingerprintStability fingerprintStability = FingerprintStability.OPTIMAL;
        private FingerprintHasher fingerprintHasher = FingerprintHasher.SHA256;
        private String expectedPackageName;
        private final Set<String> expectedSigningCertSha256Base64 = new LinkedHashSet<>();
        private Set<String> customTrustedInstallerPackages;
        private final Set<String> additionalThreatPackages = new LinkedHashSet<>();
        private ThreatAppPolicy threatAppPolicy = ThreatAppPolicy.DEFAULT;

        public Builder enableRoot(boolean value) { enableRoot = value; return this; }
        public Builder enableHookDetection(boolean value) { enableHookDetection = value; return this; }
        public Builder enableEmulatorDetection(boolean value) { enableEmulatorDetection = value; return this; }
        public Builder enableDebugDetection(boolean value) { enableDebugDetection = value; return this; }
        public Builder enableCloudPhoneDetection(boolean value) { enableCloudPhoneDetection = value; return this; }
        public Builder enableCustomRomDetection(boolean value) { enableCustomRomDetection = value; return this; }
        public Builder enableAdbDetection(boolean value) { enableAdbDetection = value; return this; }
        public Builder enableAppIntegrityDetection(boolean value) {
            enableAppIntegrityDetection = value;
            return this;
        }
        public Builder enableMultiInstanceDetection(boolean value) {
            enableMultiInstanceDetection = value;
            return this;
        }
        public Builder enableNetworkRiskDetection(boolean value) {
            enableNetworkRiskDetection = value;
            return this;
        }
        public Builder enableLocationRiskDetection(boolean value) {
            enableLocationRiskDetection = value;
            return this;
        }
        public Builder enableScreenAndFraudDetection(boolean value) {
            enableScreenAndFraudDetection = value;
            return this;
        }
        public Builder enableThreatAppDetection(boolean value) {
            enableThreatAppDetection = value;
            return this;
        }

        /**
         * Opt-in {@code prctl(PR_SET_DUMPABLE, 0)} hardening against non-root ptrace attach.
         * Defaults to {@code false} because setting dumpable=0 can interfere with some
         * ptrace-based 3rd-party crash reporters (e.g. legacy Breakpad/Bugly).
         */
        public Builder enableAntiDumpable(boolean value) {
            enableAntiDumpable = value;
            return this;
        }

        /** Controls the native background periodic monitor thread (defaults to {@code true}). */
        public Builder enablePeriodicMonitor(boolean value) {
            enablePeriodicMonitor = value;
            return this;
        }

        /**
         * Enables the on-demand {@code android:isolatedProcess="true"} cross-process probe
         * (e.g. selective unmount detection in {@code POSTPONED} pass; defaults to {@code true}).
         */
        public Builder enableIsolatedProcessProbe(boolean value) {
            enableIsolatedProcessProbe = value;
            return this;
        }

        /**
         * Enables hardware TEE / StrongBox Key Attestation and {@code tee_integrity} probes
         * in the {@code POSTPONED} tier (defaults to {@code true}).
         */
        public Builder enableTeeAttestation(boolean value) {
            enableTeeAttestation = value;
            return this;
        }

        public Builder debugLog(boolean value) { debugLog = value; return this; }
        public Builder privacyProfile(PrivacyProfile value) {
            if (value == null) throw new IllegalArgumentException("privacyProfile must not be null");
            privacyProfile = value;
            return this;
        }
        public Builder collectScene(CollectScene value) {
            if (value == null) throw new IllegalArgumentException("collectScene must not be null");
            collectScene = value;
            return this;
        }

        /**
         * Attaches an immutable local {@link RiskPolicy} to customize dimension weights,
         * action thresholds, per-family modes/multipliers, and hard-trigger suppressions.
         */
        public Builder riskPolicy(RiskPolicy policy) {
            if (policy == null) throw new IllegalArgumentException("riskPolicy must not be null");
            customRiskPolicy = policy;
            return this;
        }
        public Builder collectAndroidId(boolean value) { collectAndroidId = value; return this; }
        public Builder collectBootId(boolean value) { collectBootId = value; return this; }
        public Builder collectDrmId(boolean value) { collectDrmId = value; return this; }

        public Builder fingerprintVersion(FingerprintVersion value) {
            if (value == null) throw new IllegalArgumentException("fingerprintVersion must not be null");
            fingerprintVersion = value;
            return this;
        }

        public Builder fingerprintStability(FingerprintStability value) {
            if (value == null) throw new IllegalArgumentException("fingerprintStability must not be null");
            fingerprintStability = value;
            return this;
        }

        public Builder fingerprintHasher(FingerprintHasher value) {
            if (value == null) throw new IllegalArgumentException("fingerprintHasher must not be null");
            fingerprintHasher = value;
            return this;
        }

        /** Pins the host's hardcoded expected application package name for anti-repackaging checks. */
        public Builder expectedPackageName(String packageName) {
            if (packageName == null || packageName.isBlank()) {
                throw new IllegalArgumentException("expectedPackageName must not be blank");
            }
            expectedPackageName = packageName.trim();
            return this;
        }

        /**
         * Pins one or more trusted APK signing certificate SHA-256 digests encoded as Base64
         * (supports multi-channel release keys and APK v3/v3.1 key rotation).
         */
        public Builder expectedSigningCertSha256Base64(String... sha256Base64List) {
            if (sha256Base64List == null) {
                throw new IllegalArgumentException(
                        "expectedSigningCertSha256Base64 must not be null");
            }
            expectedSigningCertSha256Base64.clear();
            for (String entry : sha256Base64List) {
                if (entry != null && !entry.isBlank()) {
                    expectedSigningCertSha256Base64.add(entry.trim());
                }
            }
            return this;
        }

        /**
         * Overrides the built-in official installer store preset list with an explicit
         * set of trusted installer package names.
         */
        public Builder trustedInstallerPackages(String... installerPackages) {
            if (installerPackages == null) {
                throw new IllegalArgumentException("trustedInstallerPackages must not be null");
            }
            Set<String> override = new LinkedHashSet<>();
            for (String entry : installerPackages) {
                if (entry != null && !entry.isBlank()) {
                    override.add(entry.trim());
                }
            }
            customTrustedInstallerPackages = override;
            return this;
        }

        /**
         * Adds host-specified threat package names to inspect alongside the curated built-in
         * catalog (cumulative across calls; merged into {@link #getEffectiveThreatAppPolicy()}).
         */
        public Builder additionalThreatPackages(String... packages) {
            if (packages == null) {
                throw new IllegalArgumentException("additionalThreatPackages must not be null");
            }
            for (String entry : packages) {
                if (entry != null && !entry.isBlank()) {
                    additionalThreatPackages.add(entry.trim());
                }
            }
            return this;
        }

        /**
         * Configures custom {@code threat_apps} detection rules (custom packages, custom
         * certificate SHA-256 digests, dangerous permission combos, and HMA probe toggles).
         */
        public Builder threatAppPolicy(ThreatAppPolicy policy) {
            if (policy == null) {
                throw new IllegalArgumentException("threatAppPolicy must not be null");
            }
            this.threatAppPolicy = policy;
            return this;
        }

        public Builder collectTimeout(long timeoutMs) {
            if (timeoutMs <= 0 || timeoutMs > MAX_COLLECT_TIMEOUT_MS) {
                throw new IllegalArgumentException(
                        "collectTimeout must be between 1 and "
                                + MAX_COLLECT_TIMEOUT_MS + " milliseconds");
            }
            collectTimeoutMs = timeoutMs;
            return this;
        }

        public RiskEngineConfig build() {
            return new RiskEngineConfig(this);
        }
    }

    public boolean isEnableRoot() { return enableRoot; }
    public boolean isEnableHookDetection() { return enableHookDetection; }
    public boolean isEnableEmulatorDetection() { return enableEmulatorDetection; }
    public boolean isEnableDebugDetection() { return enableDebugDetection; }
    public boolean isEnableCloudPhoneDetection() { return enableCloudPhoneDetection; }
    public boolean isEnableCustomRomDetection() { return enableCustomRomDetection; }
    public boolean isEnableAdbDetection() { return enableAdbDetection; }
    public boolean isEnableAppIntegrityDetection() { return enableAppIntegrityDetection; }
    public boolean isEnableMultiInstanceDetection() { return enableMultiInstanceDetection; }
    public boolean isEnableNetworkRiskDetection() { return enableNetworkRiskDetection; }
    public boolean isEnableLocationRiskDetection() { return enableLocationRiskDetection; }
    public boolean isEnableScreenAndFraudDetection() { return enableScreenAndFraudDetection; }
    public boolean isEnableThreatAppDetection() { return enableThreatAppDetection; }
    public boolean isEnableAntiDumpable() { return enableAntiDumpable; }
    public boolean isEnablePeriodicMonitor() { return enablePeriodicMonitor; }
    public boolean isEnableIsolatedProcessProbe() { return enableIsolatedProcessProbe; }
    public boolean isEnableTeeAttestation() { return enableTeeAttestation; }
    public boolean isDebugLog() { return debugLog; }
    public long getCollectTimeoutMs() { return collectTimeoutMs; }
    public PrivacyProfile getPrivacyProfile() { return privacyProfile; }
    public CollectScene getCollectScene() { return collectScene; }
    public boolean isCollectAndroidId() { return collectAndroidId; }
    public boolean isCollectBootId() { return collectBootId; }
    public boolean isCollectDrmId() { return collectDrmId; }
    public FingerprintVersion getFingerprintVersion() { return fingerprintVersion; }
    public FingerprintStability getFingerprintStability() { return fingerprintStability; }
    public FingerprintHasher getFingerprintHasher() { return fingerprintHasher; }
    public String getExpectedPackageName() { return expectedPackageName; }
    public Set<String> getExpectedSigningCertSha256Base64() {
        return expectedSigningCertSha256Base64;
    }
    public Set<String> getTrustedInstallerPackages() { return trustedInstallerPackages; }
    public boolean hasCustomTrustedInstallerPackages() {
        return hasCustomTrustedInstallerPackages;
    }
    public Set<String> getAdditionalThreatPackages() {
        return additionalThreatPackages;
    }
    public ThreatAppPolicy getThreatAppPolicy() {
        return threatAppPolicy;
    }
    public ThreatAppPolicy getEffectiveThreatAppPolicy() {
        return additionalThreatPackages.isEmpty()
                ? threatAppPolicy
                : threatAppPolicy.withAdditionalPackages(additionalThreatPackages);
    }

    /**
     * Returns the configured local {@link RiskPolicy}, or the built-in scene preset derived from
     * {@link #getCollectScene()} when no custom policy was explicitly attached.
     */
    public RiskPolicy getRiskPolicy() {
        return riskPolicy;
    }

    /** Returns {@code true} when a custom {@link RiskPolicy} was explicitly attached. */
    public boolean hasCustomRiskPolicy() {
        return hasCustomRiskPolicy;
    }

    RiskPolicy resolveRiskPolicy(CollectScene sceneOverride) {
        if (sceneOverride == null) {
            return riskPolicy;
        }
        return hasCustomRiskPolicy
                ? riskPolicy.withBaseScene(sceneOverride)
                : RiskPolicy.forScene(sceneOverride);
    }
}
