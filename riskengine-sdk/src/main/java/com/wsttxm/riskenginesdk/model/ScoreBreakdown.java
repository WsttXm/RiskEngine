package com.wsttxm.riskenginesdk.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Auditable, item-by-item explanation showing how each evidence family, corroboration lift,
 * correlation rule, and hard trigger floor contributed to the normalized 0–100 risk score.
 */
public final class ScoreBreakdown {

    public enum Category {
        FAMILY,
        CORROBORATION_LIFT,
        CORRELATION_RULE,
        HARD_TRIGGER_FLOOR
    }

    public static final class Entry {
        private final Category category;
        private final String key;
        private final RiskDimension dimension;
        private final int points;
        private final String source;

        public Entry(Category category,
                     String key,
                     RiskDimension dimension,
                     int points,
                     String source) {
            this.category = Objects.requireNonNull(category, "category must not be null");
            this.key = key == null ? "" : key;
            this.dimension = dimension;
            this.points = points;
            this.source = source == null ? "" : source;
        }

        public Category getCategory() {
            return category;
        }

        public String getKey() {
            return key;
        }

        /** Associated dimension, or null for cross-dimension hard-trigger floors. */
        public RiskDimension getDimension() {
            return dimension;
        }

        public int getPoints() {
            return points;
        }

        public String getSource() {
            return source;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Entry)) return false;
            Entry other = (Entry) o;
            return points == other.points
                    && category == other.category
                    && key.equals(other.key)
                    && dimension == other.dimension
                    && source.equals(other.source);
        }

        @Override
        public int hashCode() {
            return Objects.hash(category, key, dimension, points, source);
        }

        @Override
        public String toString() {
            return category + ":" + key + "=" + points
                    + (dimension != null ? "(" + dimension + ")" : "")
                    + (source.isEmpty() ? "" : "[" + source + "]");
        }
    }

    private final List<Entry> entries;
    private final int preFloorScore;
    private final int finalScore;

    public ScoreBreakdown(List<Entry> entries, int preFloorScore, int finalScore) {
        if (entries == null || entries.isEmpty()) {
            this.entries = Collections.emptyList();
        } else {
            List<Entry> copy = new ArrayList<>(entries.size());
            for (Entry entry : entries) {
                copy.add(Objects.requireNonNull(entry, "entries must not contain null"));
            }
            this.entries = Collections.unmodifiableList(copy);
        }
        this.preFloorScore = Math.max(0, Math.min(100, preFloorScore));
        this.finalScore = Math.max(0, Math.min(100, finalScore));
    }

    public List<Entry> getEntries() {
        return entries;
    }

    public int getPreFloorScore() {
        return preFloorScore;
    }

    public int getFinalScore() {
        return finalScore;
    }

    public boolean isEmpty() {
        return entries.isEmpty();
    }

    @Override
    public String toString() {
        return "ScoreBreakdown{preFloorScore=" + preFloorScore
                + ", finalScore=" + finalScore
                + ", entries=" + entries + '}';
    }
}
