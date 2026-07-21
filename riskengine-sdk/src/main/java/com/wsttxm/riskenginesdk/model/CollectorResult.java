package com.wsttxm.riskenginesdk.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class CollectorResult {
    public enum Status {
        SUCCESS,
        EMPTY,
        ERROR,
        UNSUPPORTED
    }

    private final String fieldName;
    private final Map<String, String> values;
    private final boolean compareSources;
    private boolean consistent;
    private String canonicalValue;
    private Status status;
    private String error;
    private transient boolean frozen;
    private final long timestampMs;

    /** Creates a result containing independent attributes. */
    public CollectorResult(String fieldName) {
        this(fieldName, false);
    }

    /**
     * @param compareSources true only when every value is an observation of the
     *                       same semantic field obtained through a different source.
     */
    public CollectorResult(String fieldName, boolean compareSources) {
        if (fieldName == null || fieldName.isBlank()) {
            throw new IllegalArgumentException("fieldName must not be blank");
        }
        this.fieldName = fieldName;
        this.compareSources = compareSources;
        this.values = new LinkedHashMap<>();
        this.timestampMs = System.currentTimeMillis();
        this.consistent = true;
        this.status = Status.SUCCESS;
    }

    public void addValue(String method, String value) {
        ensureMutable();
        if (method == null || method.isBlank()) {
            throw new IllegalArgumentException("method must not be blank");
        }
        if (value == null || value.isBlank()) {
            return;
        }
        values.put(method, value);
        if (status == Status.EMPTY) {
            status = Status.SUCCESS;
        }
        updateConsistency();
    }

    public void finish() {
        ensureMutable();
        if (status == Status.SUCCESS && values.isEmpty()) {
            status = Status.EMPTY;
        }
    }

    public void markError(Throwable throwable) {
        ensureMutable();
        status = Status.ERROR;
        error = throwable == null ? "unknown" : throwable.getClass().getSimpleName();
    }

    public void markError(String reason) {
        ensureMutable();
        status = Status.ERROR;
        error = reason == null || reason.isBlank() ? "unknown" : reason;
    }

    public void markUnsupported(String reason) {
        ensureMutable();
        status = Status.UNSUPPORTED;
        error = reason == null || reason.isBlank() ? "unsupported" : reason;
    }

    private void updateConsistency() {
        canonicalValue = null;
        consistent = true;
        for (String value : values.values()) {
            if (value == null || value.isEmpty()) {
                continue;
            }
            if (canonicalValue == null) {
                canonicalValue = value;
            } else if (compareSources && !canonicalValue.equals(value)) {
                consistent = false;
            }
        }
    }

    void freeze() {
        frozen = true;
    }

    private void ensureMutable() {
        if (frozen) {
            throw new IllegalStateException("CollectorResult is part of an immutable report");
        }
    }

    public String getFieldName() { return fieldName; }
    public Map<String, String> getValues() { return Collections.unmodifiableMap(values); }
    public boolean isCompareSources() { return compareSources; }
    public boolean isConsistent() { return consistent; }
    public String getCanonicalValue() { return canonicalValue; }
    public Status getStatus() { return status; }
    public String getError() { return error; }
    public long getTimestampMs() { return timestampMs; }
}
