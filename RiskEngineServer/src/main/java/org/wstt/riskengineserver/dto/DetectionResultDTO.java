package org.wstt.riskengineserver.dto;

import java.util.List;

/**
 * 检测结果DTO, 对应SDK端DetectionResult
 */
public class DetectionResultDTO {
    private String detectorName;
    private String riskLevel;
    private String status;
    private int score;
    private int maxScore;
    private boolean warnOnly;
    private List<String> details;
    private String evidence;
    private long timestampMs;

    public String getDetectorName() { return detectorName; }
    public void setDetectorName(String detectorName) { this.detectorName = detectorName; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getScore() { return score; }
    public void setScore(int score) { this.score = score; }

    public int getMaxScore() { return maxScore; }
    public void setMaxScore(int maxScore) { this.maxScore = maxScore; }

    public boolean isWarnOnly() { return warnOnly; }
    public void setWarnOnly(boolean warnOnly) { this.warnOnly = warnOnly; }

    public List<String> getDetails() { return details; }
    public void setDetails(List<String> details) { this.details = details; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public long getTimestampMs() { return timestampMs; }
    public void setTimestampMs(long timestampMs) { this.timestampMs = timestampMs; }
}
