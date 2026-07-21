package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class DeviceFingerprint {
    private final Map<String, CollectorResult> results = new LinkedHashMap<>();
    private final List<String> inconsistentFields = new ArrayList<>();
    private transient boolean frozen;

    public void addResult(CollectorResult result) {
        if (frozen) {
            throw new IllegalStateException("DeviceFingerprint is part of an immutable report");
        }
        Objects.requireNonNull(result, "result must not be null");
        inconsistentFields.removeIf(result.getFieldName()::equals);
        results.put(result.getFieldName(), result);
        if (!result.isConsistent()) {
            inconsistentFields.add(result.getFieldName());
        }
    }

    public Map<String, CollectorResult> getResults() { return Collections.unmodifiableMap(results); }
    public List<String> getInconsistentFields() { return Collections.unmodifiableList(inconsistentFields); }

    public String getValue(String fieldName) {
        CollectorResult r = results.get(fieldName);
        return r != null ? r.getCanonicalValue() : null;
    }

    public boolean hasInconsistency() {
        return !inconsistentFields.isEmpty();
    }

    void freeze() {
        if (frozen) {
            return;
        }
        for (CollectorResult result : results.values()) {
            result.freeze();
        }
        frozen = true;
    }
}
