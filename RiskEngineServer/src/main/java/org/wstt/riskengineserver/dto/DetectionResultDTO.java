package org.wstt.riskengineserver.dto;

/**
 * 检测结果DTO, 对应SDK端DetectionResult
 */
public class DetectionResultDTO {
    private String detectorName;
    private String riskLevel;
    private String evidence;
    private long timestampMs;

    public String getDetectorName() { return detectorName; }
    public void setDetectorName(String detectorName) { this.detectorName = detectorName; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public long getTimestampMs() { return timestampMs; }
    public void setTimestampMs(long timestampMs) { this.timestampMs = timestampMs; }
}
