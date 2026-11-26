package com.wsttxm.riskenginesdk;

/**
 * Stability vs. uniqueness tradeoff for {@link FingerprintVersion#V2} composition.
 *
 * <ul>
 *   <li>{@link #STABLE}: Physical hardware layer only (most resilient across reinstall and OS OTA).</li>
 *   <li>{@link #OPTIMAL}: Hardware + system + zero-permission high-entropy signals (default).</li>
 *   <li>{@link #UNIQUE}: Maximum discrimination, incorporating authorized volatile identifiers.</li>
 * </ul>
 */
public enum FingerprintStability {
    STABLE(0),
    OPTIMAL(1),
    UNIQUE(2);

    private final int level;

    FingerprintStability(int level) {
        this.level = level;
    }

    public int getLevel() {
        return level;
    }

    /** Returns true if a signal tagged with {@code signalStability} is included at this level. */
    public boolean includes(FingerprintStability signalStability) {
        if (signalStability == null) {
            return false;
        }
        return this.level >= signalStability.level;
    }
}
