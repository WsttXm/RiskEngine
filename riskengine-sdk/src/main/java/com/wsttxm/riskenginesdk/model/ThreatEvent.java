package com.wsttxm.riskenginesdk.model;

import com.wsttxm.riskenginesdk.ScanTier;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable high-priority threat event pushed to host listeners during tiered scans
 * or periodic runtime tamper monitoring.
 */
public final class ThreatEvent {

    private final String detectorName;
    private final RiskLevel riskLevel;
    private final ScanTier scanTier;
    private final int score;
    private final String evidence;
    private final List<String> details;
    private final List<EvidenceItem> evidenceItems;
    private final Set<String> evidenceFamilies;
    private final boolean runtimeTamper;
    private final long timestampMs;

    public ThreatEvent(String detectorName,
                       RiskLevel riskLevel,
                       ScanTier scanTier,
                       int score,
                       String evidence,
                       List<String> details,
                       List<EvidenceItem> evidenceItems,
                       Set<String> evidenceFamilies,
                       boolean runtimeTamper,
                       long timestampMs) {
        this.detectorName = (detectorName == null || detectorName.isBlank())
                ? "unknown"
                : detectorName;
        this.riskLevel = riskLevel == null ? RiskLevel.UNKNOWN : riskLevel;
        this.scanTier = scanTier == null ? ScanTier.FAST : scanTier;
        this.score = Math.max(0, score);
        this.details = copyStrings(details);
        this.evidenceItems = copyEvidenceItems(evidenceItems);
        this.evidenceFamilies = deriveFamilies(evidenceFamilies, this.evidenceItems);
        this.evidence = (evidence == null || evidence.isEmpty())
                ? String.join("; ", this.details)
                : evidence;
        this.runtimeTamper = runtimeTamper;
        this.timestampMs = timestampMs > 0 ? timestampMs : System.currentTimeMillis();
    }

    public static ThreatEvent fromDetectionResult(DetectionResult result, boolean runtimeTamper) {
        Objects.requireNonNull(result, "result must not be null");
        return new ThreatEvent(
                result.getDetectorName(),
                result.getRiskLevel(),
                result.getScanTier(),
                result.getScore(),
                result.getEvidence(),
                result.getDetails(),
                result.getEvidenceItems(),
                null,
                runtimeTamper,
                result.getTimestampMs()
        );
    }

    public String getDetectorName() {
        return detectorName;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public ScanTier getScanTier() {
        return scanTier;
    }

    public int getScore() {
        return score;
    }

    public String getEvidence() {
        return evidence;
    }

    public List<String> getDetails() {
        return details;
    }

    public List<EvidenceItem> getEvidenceItems() {
        return evidenceItems;
    }

    public Set<String> getEvidenceFamilies() {
        return evidenceFamilies;
    }

    public boolean isRuntimeTamper() {
        return runtimeTamper;
    }

    public long getTimestampMs() {
        return timestampMs;
    }

    private static List<String> copyStrings(List<String> input) {
        if (input == null || input.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> copy = new ArrayList<>(input.size());
        for (String item : input) {
            if (item != null && !item.isBlank()) {
                copy.add(item);
            }
        }
        return Collections.unmodifiableList(copy);
    }

    private static List<EvidenceItem> copyEvidenceItems(List<EvidenceItem> input) {
        if (input == null || input.isEmpty()) {
            return Collections.emptyList();
        }
        List<EvidenceItem> copy = new ArrayList<>(input.size());
        for (EvidenceItem item : input) {
            if (item != null) {
                copy.add(item);
            }
        }
        return Collections.unmodifiableList(copy);
    }

    private static Set<String> deriveFamilies(Set<String> explicit, List<EvidenceItem> items) {
        Set<String> merged = new LinkedHashSet<>();
        if (explicit != null) {
            for (String family : explicit) {
                if (family != null && !family.isBlank()) {
                    merged.add(family.trim());
                }
            }
        }
        for (EvidenceItem item : items) {
            String family = item.getEvidenceFamily();
            if (family != null && !family.isBlank()) {
                merged.add(family);
            }
        }
        return merged.isEmpty() ? Collections.emptySet() : Collections.unmodifiableSet(merged);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ThreatEvent)) return false;
        ThreatEvent that = (ThreatEvent) o;
        return score == that.score
                && runtimeTamper == that.runtimeTamper
                && timestampMs == that.timestampMs
                && detectorName.equals(that.detectorName)
                && riskLevel == that.riskLevel
                && scanTier == that.scanTier
                && evidence.equals(that.evidence)
                && details.equals(that.details)
                && evidenceItems.equals(that.evidenceItems)
                && evidenceFamilies.equals(that.evidenceFamilies);
    }

    @Override
    public int hashCode() {
        return Objects.hash(detectorName, riskLevel, scanTier, score, evidence,
                details, evidenceItems, evidenceFamilies, runtimeTamper, timestampMs);
    }

    @Override
    public String toString() {
        return "ThreatEvent{"
                + "detectorName='" + detectorName + '\''
                + ", riskLevel=" + riskLevel
                + ", scanTier=" + scanTier
                + ", score=" + score
                + ", runtimeTamper=" + runtimeTamper
                + ", evidenceFamilies=" + evidenceFamilies
                + '}';
    }
}
