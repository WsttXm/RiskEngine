package com.wsttxm.riskenginesdk.model;

/**
 * Describes whether a detector was actually able to execute its checks.
 * This is deliberately independent from {@link DetectionStatus}, which
 * describes the risk presentation of the signals that were found.
 */
public enum DetectionExecutionStatus {
    SAFE,
    RISK,
    PARTIAL,
    UNAVAILABLE,
    DISABLED,
    TIMEOUT,
    ERROR
}
