package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.RiskPolicy;
import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskAction;
import com.wsttxm.riskenginesdk.model.RiskDimension;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.ScoreBreakdown;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Deterministic normalized 0–100 multidimensional local risk scoring engine (ADR-0002).
 *
 * <p>Implements order-independent family-max aggregation, bounded cross-layer / cross-domain
 * Corroboration Lift (+0.06, capped at 0.95), per-dimension Noisy-OR fusion with a pure-LOW
 * dimension cap (&lt;= 35), weighted cross-dimension + Correlation Rule (C1–C10) Noisy-OR,
 * unified Hard Trigger resolution with a 95–100 score floor, and tiered Assessment Confidence
 * (CRITICAL=3, FAST=2, POSTPONED=1).</p>
 */
public final class RiskScoringEngine {

    public static final int LOW_THRESHOLD = 1;
    public static final int MEDIUM_THRESHOLD = 30;
    public static final int HIGH_THRESHOLD = 60;
    public static final int DEADLY_THRESHOLD = 85;
    public static final int MAX_SCORE = 100;
    public static final int PURE_LOW_DIMENSION_CAP = 35;
    public static final int MIN_CONFIDENCE_FOR_SAFE = 70;
    public static final int HARD_TRIGGER_FLOOR_BASE = 95;

    private static final double CORROBORATION_LIFT = 0.06d;
    private static final double CORROBORATION_CAP = 0.95d;
    private static final String CORROBORATING_MARKER = "deduped:corroborating_evidence";

    // Smooth monotonic mapping from internal 0..10 detector score to [0.00, 0.92].
    private static final double[] SCORE_TO_PROB = {
            0.00d, // 0: SAFE
            0.10d, // 1: LOW
            0.18d, // 2: LOW
            0.26d, // 3: LOW
            0.38d, // 4: MEDIUM
            0.46d, // 5: MEDIUM
            0.54d, // 6: MEDIUM
            0.64d, // 7: HIGH
            0.72d, // 8: HIGH
            0.78d, // 9: HIGH
            0.92d  // 10: DEADLY
    };

    private RiskScoringEngine() {}

    /** Immutable scoring result consumed by {@code RiskReport} and {@code TierReport}. */
    public static final class Evaluation {
        public final int riskScore;
        public final RiskLevel overallRiskLevel;
        public final RiskAction recommendedAction;
        public final Map<RiskDimension, Integer> dimensionScores;
        public final ScoreBreakdown scoreBreakdown;
        public final List<String> hardTriggers;
        public final int confidencePercent;

        Evaluation(int riskScore,
                   RiskLevel overallRiskLevel,
                   RiskAction recommendedAction,
                   Map<RiskDimension, Integer> dimensionScores,
                   ScoreBreakdown scoreBreakdown,
                   List<String> hardTriggers,
                   int confidencePercent) {
            this.riskScore = riskScore;
            this.overallRiskLevel = overallRiskLevel;
            this.recommendedAction = recommendedAction;
            this.dimensionScores = dimensionScores;
            this.scoreBreakdown = scoreBreakdown;
            this.hardTriggers = hardTriggers;
            this.confidencePercent = confidencePercent;
        }
    }

    private static final class ConfidenceOutcome {
        final int percent;
        final boolean unknown;

        ConfidenceOutcome(int percent, boolean unknown) {
            this.percent = percent;
            this.unknown = unknown;
        }
    }

    private static final class FamilyAggregate {
        final String family;
        final RiskDimension dimension;
        int maxScore;
        RiskLevel maxLevel = RiskLevel.SAFE;
        String primarySource = "";
        final Set<String> domains = new HashSet<>();
        final EnumSet<EvidenceItem.SourceLayer> layers = EnumSet.noneOf(EvidenceItem.SourceLayer.class);

        FamilyAggregate(String family, RiskDimension dimension) {
            this.family = family;
            this.dimension = dimension;
        }

        void mergePrimary(int score, RiskLevel level, String detectorName) {
            if (score > maxScore
                    || (score == maxScore && level.getValue() > maxLevel.getValue())
                    || (score == maxScore && level == maxLevel
                            && (primarySource.isEmpty() || detectorName.compareTo(primarySource) < 0))) {
                maxScore = score;
                maxLevel = level;
                primarySource = detectorName;
            }
        }
    }

    public static Evaluation evaluate(DeviceFingerprint fingerprint,
                                      List<DetectionResult> detections,
                                      CollectScene scene) {
        CollectScene effectiveScene = scene == null ? CollectScene.STANDARD : scene;
        return evaluate(fingerprint, detections, RiskPolicy.forScene(effectiveScene));
    }

    /** Evaluates detections under an explicit local {@link RiskPolicy}. */
    public static Evaluation evaluate(DeviceFingerprint fingerprint,
                                      List<DetectionResult> detections,
                                      RiskPolicy policy) {
        RiskPolicy effective = policy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : policy;
        return evaluateInternal(fingerprint, detections, effective, null, false);
    }

    /** Evaluates a staged {@code TierReport} on the exact same 0–100 scoring scale. */
    public static Evaluation evaluateTier(List<DetectionResult> detections, CollectScene scene) {
        CollectScene effectiveScene = scene == null ? CollectScene.STANDARD : scene;
        return evaluateTier(null, detections, RiskPolicy.forScene(effectiveScene));
    }

    /** Evaluates a staged {@code TierReport} under an explicit local {@link RiskPolicy}. */
    public static Evaluation evaluateTier(List<DetectionResult> detections, RiskPolicy policy) {
        return evaluateTier(null, detections, policy);
    }

    /**
     * Evaluates a staged {@code TierReport} for {@code tier} under an explicit local
     * {@link RiskPolicy}, applying scene/family policy rules, family-max deduplication,
     * normalized scoring, and tiered Assessment Confidence consistently with {@link #evaluate}.
     */
    public static Evaluation evaluateTier(ScanTier tier,
                                          List<DetectionResult> detections,
                                          RiskPolicy policy) {
        RiskPolicy effective = policy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : policy;
        List<DetectionResult> normalized = detections == null || detections.isEmpty()
                ? Collections.<DetectionResult>emptyList()
                : CorrelationEngine.dedupeFamilies(
                        CorrelationEngine.applyPolicy(detections, effective));
        return evaluateInternal(null, normalized, effective, tier, true);
    }

    /**
     * Policy-ready internal scoring seam shared by default evaluation and {@link RiskPolicy}.
     */
    static Evaluation evaluateInternal(DeviceFingerprint fingerprint,
                                       List<DetectionResult> detections,
                                       RiskPolicy policy,
                                       ScanTier tierOverride,
                                       boolean tierMode) {
        RiskPolicy effectivePolicy = policy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : policy;
        List<DetectionResult> safeDetections = detections == null
                ? Collections.<DetectionResult>emptyList()
                : detections;
        boolean hasFamilyModes = !effectivePolicy.getFamilyModes().isEmpty();

        // Stage 1: Order-independent family-max aggregation + correlation rule collection
        Map<String, FamilyAggregate> families = new HashMap<>();
        Map<String, Double> correlationRules = new HashMap<>();
        boolean hasMultiSourceDetection = false;
        boolean hasInformationalWarningOrDanger = false;

        for (DetectionResult det : safeDetections) {
            if (det == null) continue;
            String name = det.getDetectorName();
            if ("multi_source_validation".equals(name)) {
                hasMultiSourceDetection = true;
            }
            if ("signal_correlation".equals(name)) {
                if (!det.isInformational()) {
                    collectCorrelationRules(det, correlationRules, effectivePolicy);
                }
                if ((det.getStatus() == DetectionStatus.WARNING || det.getStatus() == DetectionStatus.DANGER)
                        && (!hasFamilyModes || hasAnyNonAllowlistedCorrelationRule(det, effectivePolicy))) {
                    hasInformationalWarningOrDanger = true;
                }
                continue;
            }
            if (hasFamilyModes && isEntirelyAllowlisted(det, effectivePolicy)) {
                continue;
            }
            if (det.getStatus() == DetectionStatus.WARNING || det.getStatus() == DetectionStatus.DANGER) {
                hasInformationalWarningOrDanger = true;
            }
            boolean isPrimaryActionable = !det.isInformational() && det.getScore() > 0;
            boolean isCorroboratingDuplicate = det.isInformational()
                    && det.getScore() > 0
                    && det.getDetails().contains(CORROBORATING_MARKER);
            if (!isPrimaryActionable && !isCorroboratingDuplicate) {
                continue;
            }
            recordDetectorFamilies(det, isPrimaryActionable, families, effectivePolicy);
        }

        if (!tierMode && fingerprint != null && fingerprint.hasInconsistency() && !hasMultiSourceDetection) {
            RiskPolicy.FamilyMode hwMode = effectivePolicy.getFamilyMode("hw_spoof");
            if (hwMode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY) {
                hasInformationalWarningOrDanger = true;
            } else if (hwMode != RiskPolicy.FamilyMode.ALLOWLIST) {
                FamilyAggregate agg = getOrCreateFamily(families, "hw_spoof");
                agg.mergePrimary(4, RiskLevel.MEDIUM, "multi_source_validation");
                agg.domains.add("multi_source_validation");
                agg.layers.add(EvidenceItem.SourceLayer.JAVA);
            }
        }

        // Stage 2 & 3A: Corroboration Lift + Per-Dimension Noisy-OR + Pure-LOW cap (<= 35)
        RiskDimension[] allDims = RiskDimension.values();
        int dimCount = allDims.length;
        double[] dimSurvival = new double[dimCount];
        boolean[] dimHasMediumOrHigher = new boolean[dimCount];
        List<List<ScoreBreakdown.Entry>> dimEntries = new ArrayList<>(dimCount);
        for (int i = 0; i < dimCount; i++) {
            dimSurvival[i] = 1.0d;
            dimEntries.add(new ArrayList<ScoreBreakdown.Entry>());
        }

        List<String> sortedFamilies = new ArrayList<>(families.keySet());
        Collections.sort(sortedFamilies);
        for (String familyKey : sortedFamilies) {
            FamilyAggregate agg = families.get(familyKey);
            if (agg.maxScore <= 0) {
                continue;
            }
            double multiplier = Math.max(0.0d, effectivePolicy.getFamilyMultiplier(agg.family));
            if (multiplier <= 0.0d) {
                continue;
            }

            double rawBaseProb = scoreToProbability(agg.maxScore);
            boolean corroborated = agg.layers.size() >= 2 || agg.domains.size() >= 2;
            double rawCorroboratedProb = corroborated
                    ? Math.min(CORROBORATION_CAP, rawBaseProb + CORROBORATION_LIFT)
                    : rawBaseProb;
            double baseProb = multiplier == 1.0d
                    ? rawBaseProb
                    : weightedNoisyOr(rawBaseProb, multiplier);
            double effectiveProb = multiplier == 1.0d
                    ? rawCorroboratedProb
                    : weightedNoisyOr(rawCorroboratedProb, multiplier);

            int dimIdx = agg.dimension.ordinal();
            List<ScoreBreakdown.Entry> entriesForDim = dimEntries.get(dimIdx);
            entriesForDim.add(new ScoreBreakdown.Entry(
                    ScoreBreakdown.Category.FAMILY,
                    agg.family,
                    agg.dimension,
                    (int) Math.round(baseProb * 100.0d),
                    agg.primarySource));
            if (corroborated && effectiveProb > baseProb) {
                int liftPts = Math.max(1, (int) Math.round((effectiveProb - baseProb) * 100.0d));
                String liftSource;
                if (agg.layers.size() >= 2) {
                    liftSource = "layers:" + joinLayers(agg.layers);
                } else {
                    List<String> sortedDomains = new ArrayList<>(agg.domains);
                    Collections.sort(sortedDomains);
                    liftSource = "domains:" + String.join(",", sortedDomains);
                }
                entriesForDim.add(new ScoreBreakdown.Entry(
                        ScoreBreakdown.Category.CORROBORATION_LIFT,
                        agg.family,
                        agg.dimension,
                        liftPts,
                        liftSource));
            }

            if (agg.maxLevel.getValue() >= RiskLevel.MEDIUM.getValue()) {
                dimHasMediumOrHigher[dimIdx] = true;
            }
            dimSurvival[dimIdx] *= (1.0d - effectiveProb);
        }

        Map<RiskDimension, Integer> dimensionScores = new LinkedHashMap<>(dimCount);
        double totalSurvival = 1.0d;
        List<ScoreBreakdown.Entry> breakdownEntries = new ArrayList<>();

        for (int i = 0; i < dimCount; i++) {
            RiskDimension dim = allDims[i];
            double dimProb = 1.0d - dimSurvival[i];
            int dimScore = toNormalizedScore(dimProb);
            if (dimScore > PURE_LOW_DIMENSION_CAP && !dimHasMediumOrHigher[i]) {
                dimScore = PURE_LOW_DIMENSION_CAP;
                dimProb = PURE_LOW_DIMENSION_CAP / 100.0d;
            }
            dimensionScores.put(dim, dimScore);
            breakdownEntries.addAll(dimEntries.get(i));

            if (dimProb > 0.0d) {
                double weight = Math.max(0.0d, effectivePolicy.getDimensionWeight(dim));
                if (weight > 0.0d) {
                    double weightedDimProb = weight == 1.0d ? dimProb : weightedNoisyOr(dimProb, weight);
                    totalSurvival *= (1.0d - weightedDimProb);
                }
            }
        }

        // Stage 3B: Cross-domain Correlation Rules (C1–C10)
        List<String> sortedRules = new ArrayList<>(correlationRules.keySet());
        Collections.sort(sortedRules);
        for (String ruleKey : sortedRules) {
            double ruleProb = correlationRules.get(ruleKey);
            if (ruleProb <= 0.0d) continue;
            totalSurvival *= (1.0d - ruleProb);
            CorrelationRuleMeta ruleMeta = lookupCorrelationRule(ruleKey);
            RiskDimension ruleDim = ruleMeta != null ? ruleMeta.dimension : RiskDimension.ENVIRONMENT;
            breakdownEntries.add(new ScoreBreakdown.Entry(
                    ScoreBreakdown.Category.CORRELATION_RULE,
                    ruleKey,
                    ruleDim,
                    (int) Math.round(ruleProb * 100.0d),
                    "signal_correlation"));
        }

        int preFloorScore = toNormalizedScore(1.0d - totalSurvival);

        // Stage 3C: Authoritative Hard Triggers & 95–100 Floor
        List<String> hardTriggers = extractHardTriggers(safeDetections, effectivePolicy);
        int finalScore = preFloorScore;
        if (!hardTriggers.isEmpty()) {
            int floor = Math.min(MAX_SCORE, HARD_TRIGGER_FLOOR_BASE + (hardTriggers.size() - 1) * 2);
            finalScore = Math.max(preFloorScore, floor);
            breakdownEntries.add(new ScoreBreakdown.Entry(
                    ScoreBreakdown.Category.HARD_TRIGGER_FLOOR,
                    String.join(",", hardTriggers),
                    null,
                    Math.max(0, finalScore - preFloorScore),
                    "hard_trigger"));
        }

        ScoreBreakdown breakdown = new ScoreBreakdown(breakdownEntries, preFloorScore, finalScore);

        // Stage 4: Tiered Assessment Confidence, RiskLevel & RiskAction
        ConfidenceOutcome confState = computeAssessmentConfidence(
                tierMode ? null : fingerprint, safeDetections, tierOverride);
        int confidencePercent = confState.percent;
        boolean shouldMarkUnknown = confState.unknown;

        RiskLevel overallLevel;
        if (!hardTriggers.isEmpty()) {
            overallLevel = RiskLevel.DEADLY;
        } else if (finalScore >= DEADLY_THRESHOLD) {
            overallLevel = RiskLevel.DEADLY;
        } else if (finalScore >= HIGH_THRESHOLD) {
            overallLevel = RiskLevel.HIGH;
        } else if (finalScore >= MEDIUM_THRESHOLD) {
            overallLevel = RiskLevel.MEDIUM;
        } else if (finalScore >= LOW_THRESHOLD) {
            overallLevel = RiskLevel.LOW;
        } else if (shouldMarkUnknown) {
            overallLevel = RiskLevel.UNKNOWN;
        } else if (hasInformationalWarningOrDanger) {
            overallLevel = RiskLevel.LOW;
        } else {
            overallLevel = RiskLevel.SAFE;
        }

        RiskAction action = recommendAction(
                overallLevel,
                finalScore,
                !hardTriggers.isEmpty(),
                effectivePolicy);

        return new Evaluation(
                finalScore,
                overallLevel,
                action,
                Collections.unmodifiableMap(dimensionScores),
                breakdown,
                hardTriggers,
                confidencePercent);
    }

    /**
     * Authoritative Hard Trigger resolver shared by {@code RiskReport} and
     * {@code SignedEnvelopeSigner}. Returns a deterministic, sorted, deduplicated list.
     */
    public static List<String> extractHardTriggers(List<DetectionResult> detections) {
        return extractHardTriggers(detections, null);
    }

    static List<String> extractHardTriggers(List<DetectionResult> detections, RiskPolicy policy) {
        if (detections == null || detections.isEmpty()) {
            return Collections.emptyList();
        }
        boolean hasModes = policy != null && !policy.getFamilyModes().isEmpty();
        Set<String> suppressedCodes = policy == null ? null : policy.getSuppressedHardTriggers();
        Set<String> triggers = new LinkedHashSet<>();
        for (DetectionResult det : detections) {
            if (det == null
                    || det.isInformational()
                    || det.getRiskLevel().getValue() < RiskLevel.HIGH.getValue()) {
                continue;
            }
            String name = det.getDetectorName();
            String fallback = EvidenceFamily.fallbackFamilyForDetector(name);
            for (String detail : det.getDetails()) {
                if (detail == null) continue;
                String norm = detail.startsWith("native:")
                        ? detail.substring("native:".length())
                        : detail;
                boolean matched = false;
                if (startsWithAny(norm,
                        "inline_hook:", "got_hook:", "text_mismatch", "late_text_mismatch",
                        "jni_self_hook:", "fn_prologue_hook:", "late_wx_self",
                        "memfd_private_elf:", "late_memfd_elf", "art_native_cleared:")) {
                    matched = true;
                } else if ("hook_framework".equals(name)
                        && startsWithAny(norm,
                                "frida_pid_port", "maps:frida", "maps:gadget",
                                "fd:linjector", "late_frida_fd")) {
                    matched = true;
                } else if ("app_integrity".equals(name)
                        && startsWithAny(norm,
                                "apk_sig_mismatch", "pkg_name_mismatch",
                                "apk_native_java_sig_conflict")) {
                    matched = true;
                } else if ("consistency".equals(name)
                        && norm.startsWith("vbmeta_empty_input_digest")) {
                    matched = true;
                } else if ("tee_integrity".equals(name)
                        && startsWithAny(norm,
                                "tee_grant_chain_split",
                                "tee_binder_ioctl_hook",
                                "tee_keybox_revoked")) {
                    matched = true;
                } else if ("signal_correlation".equals(name)
                        && startsWithAny(norm, "C3:", "C6:", "C8:")) {
                    if (!hasModes || !isCorrelationRuleSuppressedByFamily(norm, policy)) {
                        triggers.add(norm);
                    }
                    continue;
                }
                if (matched) {
                    if (!hasModes || !isTokenFamilySuppressed(norm, fallback, policy)) {
                        triggers.add(norm);
                    }
                }
            }
            if ("tee_integrity".equals(name)
                    && (!hasModes || policy.getFamilyMode("tee_tamper")
                            == RiskPolicy.FamilyMode.DEFAULT)) {
                for (EvidenceItem item : det.getEvidenceItems()) {
                    if (item == null) continue;
                    String code = item.getCode();
                    if ("tee_grant_chain_split".equals(code)
                            || "tee_binder_ioctl_hook".equals(code)
                            || "tee_keybox_revoked".equals(code)) {
                        triggers.add(code);
                    }
                }
            }
        }
        if (triggers.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> sorted = new ArrayList<>(triggers.size());
        for (String token : triggers) {
            if (!isSuppressed(token, suppressedCodes)) {
                sorted.add(token);
            }
        }
        if (sorted.isEmpty()) {
            return Collections.emptyList();
        }
        Collections.sort(sorted);
        return Collections.unmodifiableList(sorted);
    }

    private static boolean isSuppressed(String token, Set<String> suppressedCodes) {
        if (suppressedCodes == null || suppressedCodes.isEmpty()) {
            return false;
        }
        for (String rule : suppressedCodes) {
            if (rule == null || rule.isBlank()) continue;
            if (token.equals(rule) || token.startsWith(rule)) {
                return true;
            }
        }
        return false;
    }

    /** Caps an internal 0..10 detector score according to the highest remaining {@link EvidenceItem.Rank}. */
    static int capScoreForRank(int score, EvidenceItem.Rank rank) {
        if (rank == EvidenceItem.Rank.INFO) {
            return 0;
        }
        if (rank == EvidenceItem.Rank.WEAK) {
            return Math.min(score, 2);
        }
        if (rank == EvidenceItem.Rank.MEDIUM) {
            return Math.min(score, 4);
        }
        return score;
    }

    /** Caps a {@link RiskLevel} according to the highest remaining {@link EvidenceItem.Rank}. */
    static RiskLevel capLevelForRank(RiskLevel level, EvidenceItem.Rank rank) {
        if (rank == EvidenceItem.Rank.INFO || rank == EvidenceItem.Rank.WEAK) {
            return RiskLevel.LOW;
        }
        if (rank == EvidenceItem.Rank.MEDIUM
                && level.getValue() > RiskLevel.MEDIUM.getValue()) {
            return RiskLevel.MEDIUM;
        }
        return level;
    }

    private static void recordDetectorFamilies(DetectionResult det,
                                               boolean isPrimaryActionable,
                                               Map<String, FamilyAggregate> families,
                                               RiskPolicy policy) {
        String detectorName = det.getDetectorName();
        List<EvidenceItem> items = det.getEvidenceItems();
        Set<String> resolvedFamilies = EvidenceFamily.families(det.getDetails(), items);
        if (resolvedFamilies.isEmpty()) {
            resolvedFamilies = Collections.singleton(
                    EvidenceFamily.fallbackFamilyForDetector(detectorName));
        }

        Map<String, EvidenceItem.Rank> familyMaxRank = new HashMap<>();
        Map<String, EnumSet<EvidenceItem.SourceLayer>> familyItemLayers = new HashMap<>();
        EvidenceItem.Rank overallItemMaxRank = EvidenceItem.Rank.INFO;

        for (EvidenceItem item : items) {
            if (item == null) continue;
            String f = item.getEvidenceFamily();
            if (f == null || f.isBlank()) {
                f = EvidenceFamily.familyOf(item.getCode());
            } else {
                f = f.trim();
            }
            if (f == null) continue;

            overallItemMaxRank = EvidenceItem.Rank.highest(overallItemMaxRank, item.getRank());
            familyMaxRank.put(f, EvidenceItem.Rank.highest(familyMaxRank.get(f), item.getRank()));

            EnumSet<EvidenceItem.SourceLayer> set = familyItemLayers.get(f);
            if (set == null) {
                set = EnumSet.noneOf(EvidenceItem.SourceLayer.class);
                familyItemLayers.put(f, set);
            }
            for (EvidenceItem.SourceLayer layer : item.getMergedSources()) {
                if (layer != EvidenceItem.SourceLayer.CORRELATION) {
                    set.add(layer);
                }
            }
        }

        boolean multiFamily = resolvedFamilies.size() > 1;
        boolean hasNonInfoItems = overallItemMaxRank.getSeverity() > EvidenceItem.Rank.INFO.getSeverity();

        for (String family : resolvedFamilies) {
            if (policy.getFamilyMode(family) != RiskPolicy.FamilyMode.DEFAULT) {
                continue;
            }
            EvidenceItem.Rank fRank = familyMaxRank.get(family);
            if (multiFamily && hasNonInfoItems && fRank == EvidenceItem.Rank.INFO) {
                continue;
            }

            FamilyAggregate agg = getOrCreateFamily(families, family);
            agg.domains.add(detectorName);

            EnumSet<EvidenceItem.SourceLayer> itemLayers = familyItemLayers.get(family);
            if (itemLayers != null && !itemLayers.isEmpty()) {
                agg.layers.addAll(itemLayers);
            } else {
                inferLayersFromDetails(det.getDetails(), family, resolvedFamilies.size() == 1, agg.layers);
            }

            if (isPrimaryActionable) {
                int effectiveScore = det.getScore();
                RiskLevel effectiveLevel = det.getRiskLevel();
                if (multiFamily && hasNonInfoItems && fRank != null
                        && fRank.getSeverity() < overallItemMaxRank.getSeverity()) {
                    effectiveScore = capScoreForRank(effectiveScore, fRank);
                    effectiveLevel = capLevelForRank(effectiveLevel, fRank);
                }
                agg.mergePrimary(effectiveScore, effectiveLevel, detectorName);
            }
        }
    }

    private static void inferLayersFromDetails(List<String> details,
                                               String targetFamily,
                                               boolean singleFamilyDetector,
                                               EnumSet<EvidenceItem.SourceLayer> out) {
        for (String detail : details) {
            if (detail == null || CORROBORATING_MARKER.equals(detail)) continue;
            if (!singleFamilyDetector) {
                String inferred = EvidenceFamily.familyOf(detail);
                if (!targetFamily.equals(inferred)) continue;
            }
            if (detail.startsWith("native:")) {
                out.add(EvidenceItem.SourceLayer.NATIVE);
            } else {
                out.add(EvidenceItem.SourceLayer.JAVA);
            }
        }
    }

    private static FamilyAggregate getOrCreateFamily(Map<String, FamilyAggregate> map, String family) {
        FamilyAggregate agg = map.get(family);
        if (agg == null) {
            RiskDimension dim = EvidenceFamily.dimensionOf(family);
            if (dim == null) {
                dim = RiskDimension.ENVIRONMENT;
            }
            agg = new FamilyAggregate(family, dim);
            map.put(family, agg);
        }
        return agg;
    }

    private static void collectCorrelationRules(DetectionResult det,
                                                Map<String, Double> out,
                                                RiskPolicy policy) {
        for (String detail : det.getDetails()) {
            if (detail == null || detail.isBlank()) continue;
            if (isCorrelationRuleSuppressedByFamily(detail, policy)) continue;
            CorrelationRuleMeta meta = lookupCorrelationRule(detail);
            double prob = meta == null ? 0.0d : meta.probability;
            if (prob > 0.0d) {
                Double prev = out.get(detail);
                if (prev == null || prob > prev) {
                    out.put(detail, prob);
                }
            }
        }
    }

    private static boolean isEntirelyAllowlisted(DetectionResult det, RiskPolicy policy) {
        Set<String> fams = EvidenceFamily.families(det.getDetails(), det.getEvidenceItems());
        if (fams.isEmpty()) {
            return policy.getFamilyMode(
                    EvidenceFamily.fallbackFamilyForDetector(det.getDetectorName()))
                    == RiskPolicy.FamilyMode.ALLOWLIST;
        }
        for (String fam : fams) {
            if (policy.getFamilyMode(fam) != RiskPolicy.FamilyMode.ALLOWLIST) {
                return false;
            }
        }
        return true;
    }

    private static boolean isTokenFamilySuppressed(String token,
                                                   String fallbackFamily,
                                                   RiskPolicy policy) {
        String fam = EvidenceFamily.familyOf(token);
        if (fam == null) {
            fam = fallbackFamily;
        }
        return policy.getFamilyMode(fam) != RiskPolicy.FamilyMode.DEFAULT;
    }

    private static boolean hasAnyNonAllowlistedCorrelationRule(DetectionResult det,
                                                             RiskPolicy policy) {
        for (String detail : det.getDetails()) {
            if (detail != null && !detail.isBlank()
                    && !isCorrelationRuleAllowlisted(detail, policy)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCorrelationRuleAllowlisted(String ruleToken, RiskPolicy policy) {
        CorrelationRuleMeta meta = lookupCorrelationRule(ruleToken);
        if (meta == null) return false;
        for (String fam : meta.families) {
            if (policy.getFamilyMode(fam) == RiskPolicy.FamilyMode.ALLOWLIST) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCorrelationRuleSuppressedByFamily(String ruleToken, RiskPolicy policy) {
        if (policy == null || policy.getFamilyModes().isEmpty()) {
            return false;
        }
        CorrelationRuleMeta meta = lookupCorrelationRule(ruleToken);
        if (meta == null) return false;
        for (String fam : meta.families) {
            if (policy.getFamilyMode(fam) != RiskPolicy.FamilyMode.DEFAULT) {
                return true;
            }
        }
        return false;
    }

    private static final class CorrelationRuleMeta {
        final String prefix;
        final double probability;
        final RiskDimension dimension;
        final String[] families;

        CorrelationRuleMeta(String prefix,
                            double probability,
                            RiskDimension dimension,
                            String... families) {
            this.prefix = prefix;
            this.probability = probability;
            this.dimension = dimension;
            this.families = families;
        }
    }

    private static final CorrelationRuleMeta[] CORRELATION_RULES = {
            new CorrelationRuleMeta("C1:", 0.38d, RiskDimension.ENVIRONMENT, "emulator"),
            new CorrelationRuleMeta("C2:", 0.45d, RiskDimension.ENVIRONMENT, "emulator"),
            new CorrelationRuleMeta("C3:", 0.90d, RiskDimension.TAMPERING, "hook_integrity", "frida"),
            new CorrelationRuleMeta("C4:", 0.60d, RiskDimension.PRIVILEGE, "root_fw"),
            new CorrelationRuleMeta("C5:", 0.00d, RiskDimension.PRIVILEGE, "prop_tamper"),
            new CorrelationRuleMeta("C6:", 0.90d, RiskDimension.TAMPERING, "hook_integrity"),
            new CorrelationRuleMeta("C7:", 0.18d, RiskDimension.ENVIRONMENT, "emulator"),
            new CorrelationRuleMeta("C8:", 0.90d, RiskDimension.PRIVILEGE, "boot_integrity"),
            new CorrelationRuleMeta("C9:", 0.64d, RiskDimension.PRIVILEGE, "root_fw"),
            new CorrelationRuleMeta("C10:", 0.64d, RiskDimension.FRAUD_CONTEXT, "fraud_context", "screen_control")
    };

    private static CorrelationRuleMeta lookupCorrelationRule(String ruleToken) {
        if (ruleToken == null || ruleToken.isBlank()) {
            return null;
        }
        String upper = ruleToken.toUpperCase(Locale.ROOT);
        for (CorrelationRuleMeta meta : CORRELATION_RULES) {
            if (upper.startsWith(meta.prefix)) {
                return meta;
            }
        }
        return null;
    }

    private static ConfidenceOutcome computeAssessmentConfidence(DeviceFingerprint fingerprint,
                                                                 List<DetectionResult> detections,
                                                                 ScanTier tierOverride) {
        double totalWeight = 0.0d;
        double completedWeight = 0.0d;
        boolean criticalFailed = false;
        int availableDomains = 0;
        int totalDomains = 0;

        for (DetectionResult det : detections) {
            if (det == null) continue;
            String name = det.getDetectorName();
            if ("signal_correlation".equals(name)
                    || "fingerprint_continuity".equals(name)
                    || "multi_source_validation".equals(name)
                    || name.startsWith("collector:")) {
                continue;
            }
            DetectionExecutionStatus exec = det.getExecutionStatus();
            if (exec == DetectionExecutionStatus.DISABLED) {
                continue;
            }
            ScanTier tier = tierOverride != null ? tierOverride : resolveEffectiveTier(det);
            double weight = tier == ScanTier.CRITICAL ? 3.0d : (tier == ScanTier.POSTPONED ? 1.0d : 2.0d);
            totalWeight += weight;
            totalDomains++;
            if (exec == DetectionExecutionStatus.SAFE || exec == DetectionExecutionStatus.RISK) {
                completedWeight += weight;
                availableDomains++;
            } else if (exec == DetectionExecutionStatus.PARTIAL) {
                int attempted = det.getChecksAttempted();
                int succeeded = det.getChecksSucceeded();
                if (attempted > 0 && succeeded <= 0) {
                    if (tier == ScanTier.CRITICAL) {
                        criticalFailed = true;
                    }
                } else {
                    double partialFactor = (attempted > 0 && succeeded < attempted)
                            ? ((double) succeeded / attempted)
                            : 0.5d;
                    completedWeight += weight * partialFactor;
                    availableDomains++;
                }
            } else {
                // ERROR, TIMEOUT, or UNAVAILABLE
                if (tier == ScanTier.CRITICAL) {
                    criticalFailed = true;
                }
            }
        }

        // Only fall back to CollectorResult entries when no Detection Domains were attempted.
        if (totalDomains == 0) {
            Set<String> fingerprintCollectors = new HashSet<>();
            if (fingerprint != null) {
                for (CollectorResult result : fingerprint.getResults().values()) {
                    if (result == null) continue;
                    String fieldName = result.getFieldName();
                    if (isSyntheticCollector(fieldName)) continue;
                    CollectorResult.Status status = result.getStatus();
                    if (status == CollectorResult.Status.UNSUPPORTED
                            || status == CollectorResult.Status.EMPTY) {
                        continue;
                    }
                    fingerprintCollectors.add(fieldName);
                    totalWeight += 1.0d;
                    totalDomains++;
                    if (status == CollectorResult.Status.SUCCESS) {
                        completedWeight += 1.0d;
                        availableDomains++;
                    }
                }
            }
            for (DetectionResult det : detections) {
                if (det == null) continue;
                String name = det.getDetectorName();
                if (!name.startsWith("collector:")) continue;
                String collectorField = name.substring("collector:".length());
                if (fingerprintCollectors.contains(collectorField)) continue;
                totalWeight += 1.0d;
                totalDomains++;
                DetectionExecutionStatus exec = det.getExecutionStatus();
                if (exec == DetectionExecutionStatus.SAFE || exec == DetectionExecutionStatus.RISK) {
                    completedWeight += 1.0d;
                    availableDomains++;
                }
            }
        }

        int percent = totalWeight == 0.0d
                ? 100
                : (int) Math.round((completedWeight * 100.0d) / totalWeight);
        boolean allUnavailable = totalDomains > 0 && availableDomains == 0;
        boolean unknown = criticalFailed || allUnavailable || percent < MIN_CONFIDENCE_FOR_SAFE;
        return new ConfidenceOutcome(percent, unknown);
    }

    private static ScanTier resolveEffectiveTier(DetectionResult det) {
        ScanTier declared = det.getScanTier();
        if (declared != null && declared != ScanTier.FAST) {
            return declared;
        }
        String name = det.getDetectorName();
        if ("hook_framework".equals(name) || "debug".equals(name) || "app_integrity".equals(name)) {
            return ScanTier.CRITICAL;
        }
        if ("tee_integrity".equals(name) || "threat_apps".equals(name)) {
            return ScanTier.POSTPONED;
        }
        return ScanTier.FAST;
    }

    private static boolean isSyntheticCollector(String fieldName) {
        return "hook_memory_signals".equals(fieldName)
                || "runtime_integrity_score_inputs".equals(fieldName)
                || "fingerprint_id".equals(fieldName);
    }

    private static RiskAction recommendAction(RiskLevel level,
                                              int finalScore,
                                              boolean hasHardTrigger,
                                              RiskPolicy policy) {
        if (level == null || level == RiskLevel.UNKNOWN) {
            return RiskAction.REVIEW;
        }
        if (hasHardTrigger || level == RiskLevel.DEADLY) {
            return RiskAction.BLOCK;
        }
        if (finalScore <= 0) {
            return RiskAction.ALLOW;
        }
        if (finalScore >= policy.getBlockThreshold()) {
            return RiskAction.BLOCK;
        }
        if (finalScore >= policy.getRestrictThreshold()) {
            RiskAction highAction = policy.getHighAction();
            return highAction == null ? RiskAction.RESTRICT : highAction;
        }
        if (finalScore >= policy.getChallengeThreshold()) {
            return RiskAction.CHALLENGE;
        }
        return RiskAction.ALLOW;
    }

    private static double scoreToProbability(int score) {
        int clamped = Math.max(0, Math.min(10, score));
        return SCORE_TO_PROB[clamped];
    }

    private static double weightedNoisyOr(double p, double weight) {
        if (p <= 0.0d || weight <= 0.0d) return 0.0d;
        if (p >= 1.0d) return 1.0d;
        return 1.0d - Math.pow(1.0d - p, weight);
    }

    private static int toNormalizedScore(double prob) {
        if (prob <= 0.0d) return 0;
        int rounded = (int) Math.round(prob * 100.0d);
        return Math.max(1, Math.min(MAX_SCORE, rounded));
    }

    private static String joinLayers(EnumSet<EvidenceItem.SourceLayer> layers) {
        StringBuilder sb = new StringBuilder();
        for (EvidenceItem.SourceLayer layer : layers) {
            if (sb.length() > 0) sb.append(',');
            sb.append(layer.name());
        }
        return sb.toString();
    }

    private static boolean startsWithAny(String text, String... prefixes) {
        for (String p : prefixes) {
            if (text.startsWith(p)) return true;
        }
        return false;
    }
}
