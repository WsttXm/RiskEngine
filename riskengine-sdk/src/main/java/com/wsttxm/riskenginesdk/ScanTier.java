package com.wsttxm.riskenginesdk;

/**
 * Latency and scheduling tier for detectors and collectors.
 *
 * <ul>
 *   <li>{@link #CRITICAL}: P95 &lt; 20ms, zero heavy IPC / disk I/O / keygen, 150ms per-task timeout.</li>
 *   <li>{@link #FAST}: P95 &lt; 100ms, concurrent worker pool with shared snapshot, 1000ms per-task timeout.</li>
 *   <li>{@link #POSTPONED}: Background/heavy checks (TEE/MediaDrm/EGL/timing), 3000ms per-task timeout.</li>
 * </ul>
 */
public enum ScanTier {
    CRITICAL(0, 150L),
    FAST(1, 1_000L),
    POSTPONED(2, 3_000L);

    private final int priority;
    private final long defaultTimeoutMs;

    ScanTier(int priority, long defaultTimeoutMs) {
        this.priority = priority;
        this.defaultTimeoutMs = defaultTimeoutMs;
    }

    /** Execution order priority (lower executes earlier). */
    public int getPriority() {
        return priority;
    }

    /** Default per-task {@code SafeExecutor.safeWithTimeout} budget in milliseconds. */
    public long getDefaultTimeoutMs() {
        return defaultTimeoutMs;
    }
}
