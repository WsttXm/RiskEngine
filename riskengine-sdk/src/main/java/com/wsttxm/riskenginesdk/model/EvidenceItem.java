package com.wsttxm.riskenginesdk.model;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * First-class immutable structured evidence entry attached to a {@link DetectionResult}.
 *
 * <p>Preserves full backwards compatibility with {@link DetectionResult#getDetails()} while
 * giving host backends and UI formatters structured fields plus automatic multi-source merge
 * metadata (e.g. {@code mergedSources = {JAVA, NATIVE}}).
 */
public final class EvidenceItem {

    public enum SourceLayer {
        JAVA,
        NATIVE,
        ISOLATED,
        HARDWARE,
        CORRELATION
    }

    public enum Rank {
        STRONG(3),
        MEDIUM(2),
        WEAK(1),
        INFO(0);

        private final int severity;

        Rank(int severity) {
            this.severity = severity;
        }

        public int getSeverity() {
            return severity;
        }

        public static Rank highest(Rank a, Rank b) {
            if (a == null) return b == null ? INFO : b;
            if (b == null) return a;
            return a.severity >= b.severity ? a : b;
        }
    }

    private final String code;
    private final SourceLayer primarySource;
    private final Set<SourceLayer> mergedSources;
    private final String location;
    private final String value;
    private final String evidenceFamily;
    private final Rank rank;

    public EvidenceItem(String code,
                        SourceLayer primarySource,
                        String location,
                        String value,
                        String evidenceFamily,
                        Rank rank) {
        this(code, primarySource, null, location, value, evidenceFamily, rank);
    }

    public EvidenceItem(String code,
                        SourceLayer primarySource,
                        Set<SourceLayer> mergedSources,
                        String location,
                        String value,
                        String evidenceFamily,
                        Rank rank) {
        this.code = (code == null || code.isBlank()) ? "unknown" : code.trim();
        this.primarySource = primarySource == null ? SourceLayer.JAVA : primarySource;
        EnumSet<SourceLayer> sources = EnumSet.of(this.primarySource);
        if (mergedSources != null) {
            for (SourceLayer layer : mergedSources) {
                if (layer != null) {
                    sources.add(layer);
                }
            }
        }
        this.mergedSources = Collections.unmodifiableSet(sources);
        this.location = location == null ? "" : location;
        this.value = value == null ? "" : value;
        this.evidenceFamily = (evidenceFamily == null || evidenceFamily.isBlank())
                ? null
                : evidenceFamily.trim();
        this.rank = rank == null ? Rank.INFO : rank;
    }

    public String getCode() {
        return code;
    }

    public SourceLayer getPrimarySource() {
        return primarySource;
    }

    public Set<SourceLayer> getMergedSources() {
        return mergedSources;
    }

    public String getLocation() {
        return location;
    }

    public String getValue() {
        return value;
    }

    public String getEvidenceFamily() {
        return evidenceFamily;
    }

    public Rank getRank() {
        return rank;
    }

    /**
     * Merges another corroborating {@link EvidenceItem} sharing the same {@code (code, location)}.
     * Preserves the union of {@code mergedSources} and keeps the highest {@link Rank}.
     */
    public EvidenceItem mergeWith(EvidenceItem other) {
        if (other == null) {
            return this;
        }
        EnumSet<SourceLayer> combined = EnumSet.copyOf(this.mergedSources);
        combined.addAll(other.mergedSources);
        Rank highestRank = Rank.highest(this.rank, other.rank);
        SourceLayer chosenPrimary = other.rank.getSeverity() > this.rank.getSeverity()
                ? other.primarySource
                : this.primarySource;
        String chosenValue;
        if (this.value.isEmpty()) {
            chosenValue = other.value;
        } else if (other.value.isEmpty()) {
            chosenValue = this.value;
        } else {
            chosenValue = other.rank.getSeverity() > this.rank.getSeverity()
                    ? other.value
                    : this.value;
        }
        String chosenFamily = this.evidenceFamily != null
                ? this.evidenceFamily
                : other.evidenceFamily;
        return new EvidenceItem(
                this.code,
                chosenPrimary,
                combined,
                this.location,
                chosenValue,
                chosenFamily,
                highestRank);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EvidenceItem)) return false;
        EvidenceItem that = (EvidenceItem) o;
        return code.equals(that.code)
                && primarySource == that.primarySource
                && mergedSources.equals(that.mergedSources)
                && location.equals(that.location)
                && value.equals(that.value)
                && Objects.equals(evidenceFamily, that.evidenceFamily)
                && rank == that.rank;
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, primarySource, mergedSources, location, value,
                evidenceFamily, rank);
    }

    @Override
    public String toString() {
        return "EvidenceItem{code='" + code
                + "', primarySource=" + primarySource
                + ", mergedSources=" + mergedSources
                + ", location='" + location
                + "', value='" + value
                + "', family=" + evidenceFamily
                + ", rank=" + rank + '}';
    }
}
