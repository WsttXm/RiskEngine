package com.wsttxm.riskenginesdk.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class CollectorResult {
    private final String fieldName;
    private final Map<String, String> values;
    private boolean consistent;
    private String canonicalValue;
    private final long timestampMs;

    public CollectorResult(String fieldName) {
        this.fieldName = fieldName;
        this.values = new LinkedHashMap<>();
        this.timestampMs = System.currentTimeMillis();
        this.consistent = true;
    }

    public void addValue(String method, String value) {
        values.put(method, value);
        updateConsistency();
    }

    private void updateConsistency() {
        if (values.isEmpty()) return;
        String first = null;
        consistent = true;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String v = entry.getValue();
            if (v == null || v.isEmpty()) continue;
            if (first == null) {
                first = v;
                canonicalValue = v;
            } else if (!first.equals(v)) {
                consistent = false;
            }
        }
        if (canonicalValue == null && !values.isEmpty()) {
            for (String v : values.values()) {
                if (v != null && !v.isEmpty()) {
                    canonicalValue = v;
                    break;
                }
            }
        }
    }

    public String getFieldName() { return fieldName; }
    public Map<String, String> getValues() { return values; }
    public boolean isConsistent() { return consistent; }
    public String getCanonicalValue() { return canonicalValue; }
    public long getTimestampMs() { return timestampMs; }
}
