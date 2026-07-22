package com.wsttxm.riskenginesdk.core;

/** Typed result for a shared low-level signal. */
public final class SignalResult<T> {
    public enum Status { SUCCESS, EMPTY, UNAVAILABLE, ERROR }

    private final Status status;
    private final T value;
    private final String failureReason;
    private final long timestampMs;

    private SignalResult(Status status, T value, String failureReason) {
        this.status = status;
        this.value = value;
        this.failureReason = failureReason;
        this.timestampMs = System.currentTimeMillis();
    }

    public static <T> SignalResult<T> success(T value) {
        return new SignalResult<>(Status.SUCCESS, value, null);
    }

    public static <T> SignalResult<T> empty(T value) {
        return new SignalResult<>(Status.EMPTY, value, null);
    }

    public static <T> SignalResult<T> unavailable(String reason) {
        return new SignalResult<>(Status.UNAVAILABLE, null, reason);
    }

    public static <T> SignalResult<T> error(String reason) {
        return new SignalResult<>(Status.ERROR, null, reason);
    }

    public Status getStatus() { return status; }
    public T getValue() { return value; }
    public String getFailureReason() { return failureReason; }
    public long getTimestampMs() { return timestampMs; }
    public boolean isSuccess() { return status == Status.SUCCESS || status == Status.EMPTY; }
}
