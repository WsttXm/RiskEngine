package org.wstt.riskengineserver.dto;

import java.util.Map;

/**
 * 采集器结果DTO, 对应SDK端CollectorResult
 */
public class CollectorResultDTO {
    private String fieldName;
    private Map<String, String> values;
    private boolean consistent;
    private String canonicalValue;
    private long timestampMs;

    public String getFieldName() { return fieldName; }
    public void setFieldName(String fieldName) { this.fieldName = fieldName; }

    public Map<String, String> getValues() { return values; }
    public void setValues(Map<String, String> values) { this.values = values; }

    public boolean isConsistent() { return consistent; }
    public void setConsistent(boolean consistent) { this.consistent = consistent; }

    public String getCanonicalValue() { return canonicalValue; }
    public void setCanonicalValue(String canonicalValue) { this.canonicalValue = canonicalValue; }

    public long getTimestampMs() { return timestampMs; }
    public void setTimestampMs(long timestampMs) { this.timestampMs = timestampMs; }
}
