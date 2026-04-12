package com.wsttxm.riskenginesdk.model;

public class DetectionResult {
    private final String detectorName;
    private final RiskLevel riskLevel;
    private final String evidence;
    private final long timestampMs;

    public DetectionResult(String detectorName, RiskLevel riskLevel, String evidence) {
        this.detectorName = detectorName;
        this.riskLevel = riskLevel;
        this.evidence = evidence;
        this.timestampMs = System.currentTimeMillis();
    }

    public String getDetectorName() { return detectorName; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public String getEvidence() { return evidence; }
    public long getTimestampMs() { return timestampMs; }
}
