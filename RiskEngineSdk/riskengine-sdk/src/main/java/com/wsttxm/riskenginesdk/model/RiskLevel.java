package com.wsttxm.riskenginesdk.model;

public enum RiskLevel {
    SAFE(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    DEADLY(4);

    private final int value;

    RiskLevel(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
