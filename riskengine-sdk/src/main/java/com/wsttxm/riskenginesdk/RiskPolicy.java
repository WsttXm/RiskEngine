package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.RiskScoringEngine;
import com.wsttxm.riskenginesdk.model.RiskAction;
import com.wsttxm.riskenginesdk.model.RiskDimension;

import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable host-configurable local risk policy layered on top of a built-in {@link CollectScene}
 * preset.
 *
 * <p>Allows host applications to customize per-dimension weight multipliers, action score
 * thresholds, the {@code HIGH}-level disposition action, per-family handling overrides
 * ({@link FamilyMode#ALLOWLIST}, {@link FamilyMode#INFORMATIONAL_ONLY}, or custom multipliers),
 * and selective Hard Trigger suppressions without requiring a backend service.</p>
 */
public final class RiskPolicy {

    /** Per-Evidence Family override mode. */
    public enum FamilyMode {
        /** Follow the active scene and scoring defaults (or a custom family multiplier). */
        DEFAULT,
        /** Completely ignore the family so it scores 0 and triggers no correlation or hard trigger. */
        ALLOWLIST,
        /** Keep evidence visible as informational (0 score, LOW if only informational, ALLOW). */
        INFORMATIONAL_ONLY
    }

    private static final Map<CollectScene, RiskPolicy> SCENE_PRESETS;
    static {
        EnumMap<CollectScene, RiskPolicy> presets = new EnumMap<>(CollectScene.class);
        for (CollectScene scene : CollectScene.values()) {
            presets.put(scene, new Builder(scene).build());
        }
        SCENE_PRESETS = presets;
    }

    private final CollectScene baseScene;
    private final Map<RiskDimension, Double> dimensionWeights;
    private final int challengeThreshold;
    private final int restrictThreshold;
    private final int blockThreshold;
    private final RiskAction highAction;
    private final Map<String, FamilyMode> familyModes;
    private final Map<String, Double> familyMultipliers;
    private final Set<String> suppressedHardTriggers;

    private RiskPolicy(Builder builder) {
        this.baseScene = builder.baseScene;
        EnumMap<RiskDimension, Double> weights = new EnumMap<>(RiskDimension.class);
        for (RiskDimension dim : RiskDimension.values()) {
            Double w = builder.dimensionWeights.get(dim);
            weights.put(dim, w == null ? 1.0d : w);
        }
        this.dimensionWeights = Collections.unmodifiableMap(weights);
        this.challengeThreshold = builder.challengeThreshold;
        this.restrictThreshold = builder.restrictThreshold;
        this.blockThreshold = builder.blockThreshold;
        this.highAction = builder.highAction;
        this.familyModes = builder.familyModes.isEmpty()
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(builder.familyModes));
        this.familyMultipliers = builder.familyMultipliers.isEmpty()
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(builder.familyMultipliers));
        this.suppressedHardTriggers = builder.suppressedHardTriggers.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(new LinkedHashSet<>(builder.suppressedHardTriggers));
    }

    /** Returns the immutable default {@link RiskPolicy} preset for {@code scene}. */
    public static RiskPolicy forScene(CollectScene scene) {
        if (scene == null) {
            throw new IllegalArgumentException("scene must not be null");
        }
        return SCENE_PRESETS.get(scene);
    }

    /** Creates a {@link Builder} initialized with the defaults of {@code scene}. */
    public static Builder builder(CollectScene scene) {
        return new Builder(scene);
    }

    public CollectScene getBaseScene() {
        return baseScene;
    }

    public Map<RiskDimension, Double> getDimensionWeights() {
        return dimensionWeights;
    }

    public double getDimensionWeight(RiskDimension dimension) {
        if (dimension == null) {
            return 1.0d;
        }
        Double value = dimensionWeights.get(dimension);
        return value == null ? 1.0d : value;
    }

    public int getChallengeThreshold() {
        return challengeThreshold;
    }

    public int getRestrictThreshold() {
        return restrictThreshold;
    }

    public int getBlockThreshold() {
        return blockThreshold;
    }

    public RiskAction getHighAction() {
        return highAction;
    }

    public Map<String, FamilyMode> getFamilyModes() {
        return familyModes;
    }

    public FamilyMode getFamilyMode(String family) {
        if (family == null || family.isBlank()) {
            return FamilyMode.DEFAULT;
        }
        FamilyMode mode = familyModes.get(family.trim().toLowerCase(Locale.ROOT));
        return mode == null ? FamilyMode.DEFAULT : mode;
    }

    public Map<String, Double> getFamilyMultipliers() {
        return familyMultipliers;
    }

    public double getFamilyMultiplier(String family) {
        if (family == null || family.isBlank()) {
            return 1.0d;
        }
        Double value = familyMultipliers.get(family.trim().toLowerCase(Locale.ROOT));
        return value == null ? 1.0d : value;
    }

    public Set<String> getSuppressedHardTriggers() {
        return suppressedHardTriggers;
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    RiskPolicy withBaseScene(CollectScene scene) {
        if (scene == null || scene == this.baseScene) {
            return this;
        }
        Builder copy = new Builder(this);
        copy.baseScene = scene;
        return copy.build();
    }

    public static final class Builder {
        private CollectScene baseScene;
        private final EnumMap<RiskDimension, Double> dimensionWeights =
                new EnumMap<>(RiskDimension.class);
        private int challengeThreshold;
        private int restrictThreshold;
        private int blockThreshold;
        private RiskAction highAction;
        private final Map<String, FamilyMode> familyModes = new LinkedHashMap<>();
        private final Map<String, Double> familyMultipliers = new LinkedHashMap<>();
        private final Set<String> suppressedHardTriggers = new LinkedHashSet<>();

        private Builder(CollectScene scene) {
            if (scene == null) {
                throw new IllegalArgumentException("scene must not be null");
            }
            this.baseScene = scene;
            for (RiskDimension dim : RiskDimension.values()) {
                this.dimensionWeights.put(dim, 1.0d);
            }
            this.challengeThreshold = RiskScoringEngine.MEDIUM_THRESHOLD;
            this.restrictThreshold = RiskScoringEngine.HIGH_THRESHOLD;
            this.blockThreshold = RiskScoringEngine.DEADLY_THRESHOLD;
            this.highAction = scene == CollectScene.PAYMENT
                    ? RiskAction.BLOCK
                    : RiskAction.RESTRICT;
        }

        private Builder(RiskPolicy source) {
            this.baseScene = source.baseScene;
            this.dimensionWeights.putAll(source.dimensionWeights);
            this.challengeThreshold = source.challengeThreshold;
            this.restrictThreshold = source.restrictThreshold;
            this.blockThreshold = source.blockThreshold;
            this.highAction = source.highAction;
            this.familyModes.putAll(source.familyModes);
            this.familyMultipliers.putAll(source.familyMultipliers);
            this.suppressedHardTriggers.addAll(source.suppressedHardTriggers);
        }

        /** Sets the weight multiplier for a {@link RiskDimension} (finite, {@code >= 0.0}). */
        public Builder dimensionWeight(RiskDimension dimension, double weight) {
            if (dimension == null) {
                throw new IllegalArgumentException("dimension must not be null");
            }
            validateNonNegativeFinite(weight, "dimension weight");
            dimensionWeights.put(dimension, weight);
            return this;
        }

        /**
         * Overrides the normalized 0–100 score thresholds for {@code CHALLENGE},
         * {@code RESTRICT} (or {@link #highAction(RiskAction)}), and {@code BLOCK} action
         * recommendations without altering the fixed {@code RiskLevel} bands
         * ({@code 0 / 1–29 / 30–59 / 60–84 / 85–100}). Must satisfy
         * {@code 1 <= challengeThreshold < restrictThreshold < blockThreshold <= 100}.
         */
        public Builder actionThresholds(int challengeThreshold,
                                        int restrictThreshold,
                                        int blockThreshold) {
            if (challengeThreshold < RiskScoringEngine.LOW_THRESHOLD
                    || blockThreshold > RiskScoringEngine.MAX_SCORE
                    || challengeThreshold >= restrictThreshold
                    || restrictThreshold >= blockThreshold) {
                throw new IllegalArgumentException(
                        "actionThresholds must satisfy 1 <= challenge < restrict < block <= 100");
            }
            this.challengeThreshold = challengeThreshold;
            this.restrictThreshold = restrictThreshold;
            this.blockThreshold = blockThreshold;
            return this;
        }

        /** Overrides the {@link RiskAction} recommended when overall level is {@code HIGH}. */
        public Builder highAction(RiskAction action) {
            if (action == null) {
                throw new IllegalArgumentException("highAction must not be null");
            }
            this.highAction = action;
            return this;
        }

        /** Completely ignores {@code family} (0 score, no correlation rules, no hard triggers). */
        public Builder allowlistFamily(String family) {
            return familyMode(family, FamilyMode.ALLOWLIST);
        }

        /** Keeps {@code family} visible as informational-only (0 score, ALLOW action). */
        public Builder informationalOnlyFamily(String family) {
            return familyMode(family, FamilyMode.INFORMATIONAL_ONLY);
        }

        /** Sets the {@link FamilyMode} for an Evidence Family. */
        public Builder familyMode(String family, FamilyMode mode) {
            String key = normalizeFamilyKey(family);
            if (mode == null) {
                throw new IllegalArgumentException("family mode must not be null");
            }
            if (mode == FamilyMode.DEFAULT) {
                familyModes.remove(key);
            } else {
                familyModes.put(key, mode);
                familyMultipliers.remove(key);
            }
            return this;
        }

        /**
         * Sets a custom score multiplier for an Evidence Family (finite, {@code >= 0.0}).
         * Clears any prior {@link FamilyMode#ALLOWLIST} or {@link FamilyMode#INFORMATIONAL_ONLY}
         * override on the same family.
         */
        public Builder familyMultiplier(String family, double multiplier) {
            String key = normalizeFamilyKey(family);
            validateNonNegativeFinite(multiplier, "family multiplier");
            familyModes.remove(key);
            familyMultipliers.put(key, multiplier);
            return this;
        }

        /** Suppresses a Hard Trigger by exact code or prefix (e.g. {@code "inline_hook:"}). */
        public Builder suppressHardTrigger(String hardTriggerCode) {
            if (hardTriggerCode == null || hardTriggerCode.isBlank()) {
                throw new IllegalArgumentException("hardTriggerCode must not be blank");
            }
            suppressedHardTriggers.add(hardTriggerCode.trim());
            return this;
        }

        public RiskPolicy build() {
            return new RiskPolicy(this);
        }

        private static String normalizeFamilyKey(String family) {
            if (family == null || family.isBlank()) {
                throw new IllegalArgumentException("family must not be blank");
            }
            return family.trim().toLowerCase(Locale.ROOT);
        }

        private static void validateNonNegativeFinite(double value, String label) {
            if (!Double.isFinite(value) || value < 0.0d) {
                throw new IllegalArgumentException(label + " must be finite and >= 0.0");
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RiskPolicy)) return false;
        RiskPolicy that = (RiskPolicy) o;
        return challengeThreshold == that.challengeThreshold
                && restrictThreshold == that.restrictThreshold
                && blockThreshold == that.blockThreshold
                && baseScene == that.baseScene
                && highAction == that.highAction
                && dimensionWeights.equals(that.dimensionWeights)
                && familyModes.equals(that.familyModes)
                && familyMultipliers.equals(that.familyMultipliers)
                && suppressedHardTriggers.equals(that.suppressedHardTriggers);
    }

    @Override
    public int hashCode() {
        return Objects.hash(baseScene, dimensionWeights, challengeThreshold, restrictThreshold,
                blockThreshold, highAction, familyModes, familyMultipliers, suppressedHardTriggers);
    }

    @Override
    public String toString() {
        return "RiskPolicy{scene=" + baseScene
                + ", thresholds=[" + challengeThreshold + "," + restrictThreshold + ","
                + blockThreshold + "]"
                + ", highAction=" + highAction
                + ", familyModes=" + familyModes.size()
                + ", familyMultipliers=" + familyMultipliers.size()
                + ", suppressedHardTriggers=" + suppressedHardTriggers.size()
                + '}';
    }
}
