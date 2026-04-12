package org.wstt.riskengineserver.dto;

import com.google.gson.annotations.SerializedName;

/**
 * 服务端返回给SDK的配置响应
 */
public class ServerConfigResponse {

    @SerializedName("collect_interval")
    private long collectInterval = 300000;

    @SerializedName("enabled_detectors")
    private String[] enabledDetectors;

    @SerializedName("kill_switch")
    private boolean killSwitch = false;

    private String status = "ok";

    public long getCollectInterval() { return collectInterval; }
    public void setCollectInterval(long collectInterval) { this.collectInterval = collectInterval; }

    public String[] getEnabledDetectors() { return enabledDetectors; }
    public void setEnabledDetectors(String[] enabledDetectors) { this.enabledDetectors = enabledDetectors; }

    public boolean isKillSwitch() { return killSwitch; }
    public void setKillSwitch(boolean killSwitch) { this.killSwitch = killSwitch; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
