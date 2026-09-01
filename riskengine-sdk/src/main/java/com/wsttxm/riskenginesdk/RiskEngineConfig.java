package com.wsttxm.riskenginesdk;

/** Immutable configuration for a RiskEngine instance. */
public final class RiskEngineConfig {
    private static final long MAX_COLLECT_TIMEOUT_MS = 120_000;

    private final boolean enableRoot;
    private final boolean enableHookDetection;
    private final boolean enableEmulatorDetection;
    private final boolean enableSandboxDetection;
    private final boolean enableDebugDetection;
    private final boolean enableCloudPhoneDetection;
    private final boolean enableCustomRomDetection;
    private final boolean enableAdbDetection;
    private final boolean debugLog;
    private final long collectTimeoutMs;
    private final PrivacyProfile privacyProfile;
    private final CollectScene collectScene;
    private final boolean collectAndroidId;
    private final boolean collectBootId;
    private final boolean collectDrmId;

    private RiskEngineConfig(Builder builder) {
        this.enableRoot = builder.enableRoot;
        this.enableHookDetection = builder.enableHookDetection;
        this.enableEmulatorDetection = builder.enableEmulatorDetection;
        this.enableSandboxDetection = builder.enableSandboxDetection;
        this.enableDebugDetection = builder.enableDebugDetection;
        this.enableCloudPhoneDetection = builder.enableCloudPhoneDetection;
        this.enableCustomRomDetection = builder.enableCustomRomDetection;
        this.enableAdbDetection = builder.enableAdbDetection;
        this.debugLog = builder.debugLog;
        this.collectTimeoutMs = builder.collectTimeoutMs;
        this.privacyProfile = builder.privacyProfile;
        this.collectScene = builder.collectScene;
        this.collectAndroidId = builder.collectAndroidId != null
                ? builder.collectAndroidId
                : builder.privacyProfile != PrivacyProfile.MINIMAL;
        this.collectBootId = builder.collectBootId != null
                ? builder.collectBootId
                : builder.privacyProfile == PrivacyProfile.DIAGNOSTIC;
        this.collectDrmId = builder.collectDrmId != null
                ? builder.collectDrmId
                : builder.privacyProfile == PrivacyProfile.DIAGNOSTIC;
    }

    public static final class Builder {
        private boolean enableRoot = true;
        private boolean enableHookDetection = true;
        private boolean enableEmulatorDetection = true;
        private boolean enableSandboxDetection = true;
        private boolean enableDebugDetection = true;
        private boolean enableCloudPhoneDetection = true;
        private boolean enableCustomRomDetection = true;
        private boolean enableAdbDetection = true;
        private boolean debugLog;
        private long collectTimeoutMs = 10_000;
        private PrivacyProfile privacyProfile = PrivacyProfile.BALANCED;
        private CollectScene collectScene = CollectScene.STANDARD;
        private Boolean collectAndroidId;
        private Boolean collectBootId;
        private Boolean collectDrmId;

        public Builder enableRoot(boolean value) { enableRoot = value; return this; }
        public Builder enableHookDetection(boolean value) { enableHookDetection = value; return this; }
        public Builder enableEmulatorDetection(boolean value) { enableEmulatorDetection = value; return this; }
        public Builder enableSandboxDetection(boolean value) { enableSandboxDetection = value; return this; }
        public Builder enableDebugDetection(boolean value) { enableDebugDetection = value; return this; }
        public Builder enableCloudPhoneDetection(boolean value) { enableCloudPhoneDetection = value; return this; }
        public Builder enableCustomRomDetection(boolean value) { enableCustomRomDetection = value; return this; }
        public Builder enableAdbDetection(boolean value) { enableAdbDetection = value; return this; }
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
        public Builder collectAndroidId(boolean value) { collectAndroidId = value; return this; }
        public Builder collectBootId(boolean value) { collectBootId = value; return this; }
        public Builder collectDrmId(boolean value) { collectDrmId = value; return this; }

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
    public boolean isEnableSandboxDetection() { return enableSandboxDetection; }
    public boolean isEnableDebugDetection() { return enableDebugDetection; }
    public boolean isEnableCloudPhoneDetection() { return enableCloudPhoneDetection; }
    public boolean isEnableCustomRomDetection() { return enableCustomRomDetection; }
    public boolean isEnableAdbDetection() { return enableAdbDetection; }
    public boolean isDebugLog() { return debugLog; }
    public long getCollectTimeoutMs() { return collectTimeoutMs; }
    public PrivacyProfile getPrivacyProfile() { return privacyProfile; }
    public CollectScene getCollectScene() { return collectScene; }
    public boolean isCollectAndroidId() { return collectAndroidId; }
    public boolean isCollectBootId() { return collectBootId; }
    public boolean isCollectDrmId() { return collectDrmId; }
}
