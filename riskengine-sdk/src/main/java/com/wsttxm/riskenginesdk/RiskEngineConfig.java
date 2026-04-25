package com.wsttxm.riskenginesdk;

public class RiskEngineConfig {
    private boolean enableRoot = true;
    private boolean enableHookDetection = true;
    private boolean enableEmulatorDetection = true;
    private boolean enableSandboxDetection = true;
    private boolean enableDebugDetection = true;
    private boolean enableCloudPhoneDetection = true;
    private boolean enableCustomRomDetection = true;
    private boolean debugLog = false;
    private long collectTimeoutMs = 10000;

    private RiskEngineConfig() {}

    public static class Builder {
        private final RiskEngineConfig config = new RiskEngineConfig();

        public Builder enableRoot(boolean v) { config.enableRoot = v; return this; }
        public Builder enableHookDetection(boolean v) { config.enableHookDetection = v; return this; }
        public Builder enableEmulatorDetection(boolean v) { config.enableEmulatorDetection = v; return this; }
        public Builder enableSandboxDetection(boolean v) { config.enableSandboxDetection = v; return this; }
        public Builder enableDebugDetection(boolean v) { config.enableDebugDetection = v; return this; }
        public Builder enableCloudPhoneDetection(boolean v) { config.enableCloudPhoneDetection = v; return this; }
        public Builder enableCustomRomDetection(boolean v) { config.enableCustomRomDetection = v; return this; }
        public Builder debugLog(boolean v) { config.debugLog = v; return this; }
        public Builder collectTimeout(long ms) { config.collectTimeoutMs = ms; return this; }

        public RiskEngineConfig build() { return config; }
    }

    public boolean isEnableRoot() { return enableRoot; }
    public boolean isEnableHookDetection() { return enableHookDetection; }
    public boolean isEnableEmulatorDetection() { return enableEmulatorDetection; }
    public boolean isEnableSandboxDetection() { return enableSandboxDetection; }
    public boolean isEnableDebugDetection() { return enableDebugDetection; }
    public boolean isEnableCloudPhoneDetection() { return enableCloudPhoneDetection; }
    public boolean isEnableCustomRomDetection() { return enableCustomRomDetection; }
    public boolean isDebugLog() { return debugLog; }
    public long getCollectTimeoutMs() { return collectTimeoutMs; }
}
