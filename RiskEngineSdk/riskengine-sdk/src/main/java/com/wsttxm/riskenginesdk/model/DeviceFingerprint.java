package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DeviceFingerprint {
    private final Map<String, CollectorResult> results = new LinkedHashMap<>();
    private final List<String> inconsistentFields = new ArrayList<>();

    public void addResult(CollectorResult result) {
        results.put(result.getFieldName(), result);
        if (!result.isConsistent()) {
            inconsistentFields.add(result.getFieldName());
        }
    }

    public Map<String, CollectorResult> getResults() { return results; }
    public List<String> getInconsistentFields() { return inconsistentFields; }

    public String getValue(String fieldName) {
        CollectorResult r = results.get(fieldName);
        return r != null ? r.getCanonicalValue() : null;
    }

    public boolean hasInconsistency() {
        return !inconsistentFields.isEmpty();
    }
}
