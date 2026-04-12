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
}
