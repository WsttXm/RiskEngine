package org.wstt.riskengineserver.dto;

import java.util.List;

/**
 * SDK上报的RiskReport数据传输对象, 与SDK端RiskReport结构一致
 */
public class RiskReportDTO {
    private DeviceFingerprintDTO fingerprint;
    private List<DetectionResultDTO> detections;
    private long timestampMs;
    private String sdkVersion;
    private String overallRiskLevel;
    private int riskScore;
    private int maxRiskScore;
    private int warningCount;
    private int dangerCount;

    public DeviceFingerprintDTO getFingerprint() { return fingerprint; }
    public void setFingerprint(DeviceFingerprintDTO fingerprint) { this.fingerprint = fingerprint; }

    public List<DetectionResultDTO> getDetections() { return detections; }
    public void setDetections(List<DetectionResultDTO> detections) { this.detections = detections; }

    public long getTimestampMs() { return timestampMs; }
    public void setTimestampMs(long timestampMs) { this.timestampMs = timestampMs; }

    public String getSdkVersion() { return sdkVersion; }
    public void setSdkVersion(String sdkVersion) { this.sdkVersion = sdkVersion; }

    public String getOverallRiskLevel() { return overallRiskLevel; }
    public void setOverallRiskLevel(String overallRiskLevel) { this.overallRiskLevel = overallRiskLevel; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public int getMaxRiskScore() { return maxRiskScore; }
    public void setMaxRiskScore(int maxRiskScore) { this.maxRiskScore = maxRiskScore; }

    public int getWarningCount() { return warningCount; }
    public void setWarningCount(int warningCount) { this.warningCount = warningCount; }

    public int getDangerCount() { return dangerCount; }
    public void setDangerCount(int dangerCount) { this.dangerCount = dangerCount; }
}
