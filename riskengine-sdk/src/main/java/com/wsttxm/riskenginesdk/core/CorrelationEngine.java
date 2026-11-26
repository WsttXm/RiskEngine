package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.RiskPolicy;
import com.wsttxm.riskenginesdk.detector.probe.hook.SelfIntegrityProbe;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class CorrelationEngine {
    private CorrelationEngine() {}

    public static List<DetectionResult> applyScene(List<DetectionResult> detections,
                                                   CollectScene scene) {
        CollectScene effective = scene == null ? CollectScene.STANDARD : scene;
        List<DetectionResult> out = new ArrayList<>(detections.size());
        for (DetectionResult detection : detections) {
            out.add(applyScene(detection, effective));
        }
        return out;
    }

    public static DetectionResult applyScene(DetectionResult detection, CollectScene scene) {
        if (detection == null || scene == CollectScene.STANDARD) {
            return detection;
        }
        String name = detection.getDetectorName();
        if ("consistency".equals(name)
                && (scene == CollectScene.LOGIN || scene == CollectScene.PAYMENT)) {
            boolean hasUnlocked = containsExact(detection, "bootloader_unlocked")
                    || containsPrefix(detection, "key_attestation:bootloader_unlocked");
            boolean hasOrangeOrRed = containsExact(detection, "verified_boot_state:orange")
                    || containsExact(detection, "verified_boot_state:red")
                    || containsPrefix(detection, "key_attestation:verified_boot_orange")
                    || containsPrefix(detection, "key_attestation:verified_boot_red");
            boolean hasHardwareConfirmed = containsPrefix(detection, "key_attestation:bootloader_unlocked")
                    || containsPrefix(detection, "key_attestation:verified_boot_orange")
                    || containsPrefix(detection, "key_attestation:verified_boot_red")
                    || containsExact(detection, "verified_boot_state:red");
            if (hasUnlocked || hasOrangeOrRed) {
                boolean elevateHigh = hasHardwareConfirmed
                        || (scene == CollectScene.PAYMENT && hasUnlocked && hasOrangeOrRed);
                RiskLevel targetLevel = elevateHigh
                        ? max(detection.getRiskLevel(), RiskLevel.HIGH)
                        : max(detection.getRiskLevel(), RiskLevel.MEDIUM);
                DetectionStatus targetStatus = targetLevel.getValue() >= RiskLevel.HIGH.getValue()
                        ? DetectionStatus.DANGER
                        : DetectionStatus.WARNING;
                int targetScore = targetLevel.getValue() >= RiskLevel.HIGH.getValue()
                        ? Math.max(detection.getScore(), 7)
                        : Math.max(detection.getScore(), 4);
                return new DetectionResult(
                        detection.getDetectorName(),
                        targetLevel,
                        targetStatus,
                        targetScore,
                        Math.max(detection.getMaxScore(), targetScore),
                        false,
                        detection.getExecutionStatus(),
                        detection.getChecksAttempted(),
                        detection.getChecksSucceeded(),
                        detection.getChecksFailed(),
                        detection.getFailureReasons(),
                        detection.getDetails(),
                        detection.getEvidence()
                ).withEvidenceItems(detection.getEvidenceItems())
                        .withScanTier(detection.getScanTier());
            }
        }
        if ("network_risk".equals(name)
                && scene == CollectScene.PAYMENT
                && detection.isInformational()
                && detection.getScore() > 0) {
            RiskLevel targetLevel = max(detection.getRiskLevel(), RiskLevel.MEDIUM);
            int targetScore = Math.max(detection.getScore(), 4);
            return new DetectionResult(
                    detection.getDetectorName(),
                    targetLevel,
                    DetectionStatus.WARNING,
                    targetScore,
                    Math.max(detection.getMaxScore(), targetScore),
                    false,
                    detection.getExecutionStatus(),
                    detection.getChecksAttempted(),
                    detection.getChecksSucceeded(),
                    detection.getChecksFailed(),
                    detection.getFailureReasons(),
                    detection.getDetails(),
                    detection.getEvidence()
            ).withEvidenceItems(detection.getEvidenceItems())
                    .withScanTier(detection.getScanTier());
        }
        if ("screen_and_fraud".equals(name) && scene == CollectScene.PAYMENT) {
            boolean hasScreenControl = containsPrefix(detection, "virtual_display:")
                    || containsPrefix(detection, "third_party_a11y:")
                    || containsPrefix(detection, "virtual_input:")
                    || containsExact(detection, "screen_recording_active");
            if (hasScreenControl) {
                RiskLevel targetLevel = max(detection.getRiskLevel(), RiskLevel.HIGH);
                int targetScore = Math.max(detection.getScore(), 7);
                return new DetectionResult(
                        detection.getDetectorName(),
                        targetLevel,
                        DetectionStatus.DANGER,
                        targetScore,
                        Math.max(detection.getMaxScore(), targetScore),
                        false,
                        detection.getExecutionStatus(),
                        detection.getChecksAttempted(),
                        detection.getChecksSucceeded(),
                        detection.getChecksFailed(),
                        detection.getFailureReasons(),
                        detection.getDetails(),
                        detection.getEvidence()
                ).withEvidenceItems(detection.getEvidenceItems())
                        .withScanTier(detection.getScanTier());
            }
        }
        boolean makeActionable = false;
        if (scene == CollectScene.DIAGNOSTIC) {
            makeActionable = !"debug".equals(name) || !isDebuggableOnly(detection);
        } else if ("emulator".equals(name) || "cloud_phone".equals(name)
                || "multi_instance".equals(name) || "location_risk".equals(name)) {
            makeActionable = scene == CollectScene.LOGIN || scene == CollectScene.PAYMENT;
        } else if ("adb".equals(name) || "app_integrity".equals(name)) {
            makeActionable = scene == CollectScene.PAYMENT;
        }
        if (makeActionable && detection.isInformational()) {
            return detection.withInformational(false);
        }
        return detection;
    }

    /**
     * Applies the base scene rules followed by per-family {@link RiskPolicy.FamilyMode}
     * overrides ({@code ALLOWLIST} strips evidence cleanly; {@code INFORMATIONAL_ONLY}
     * keeps evidence visible without scoring).
     */
    public static List<DetectionResult> applyPolicy(List<DetectionResult> detections,
                                                    RiskPolicy policy) {
        if (detections == null || detections.isEmpty()) {
            return new ArrayList<>();
        }
        RiskPolicy effective = policy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : policy;
        List<DetectionResult> out = new ArrayList<>(detections.size());
        for (DetectionResult detection : detections) {
            out.add(applyPolicy(detection, effective));
        }
        return out;
    }

    public static DetectionResult applyPolicy(DetectionResult detection, RiskPolicy policy) {
        if (detection == null) {
            return null;
        }
        RiskPolicy effective = policy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : policy;
        DetectionResult afterScene = applyScene(detection, effective.getBaseScene());
        if (effective.getFamilyModes().isEmpty()) {
            return afterScene;
        }
        return applyFamilyModes(afterScene, effective, false);
    }

    /**
     * Returns a view of detections with both {@code ALLOWLIST} and {@code INFORMATIONAL_ONLY}
     * family evidence stripped so suppressed families cannot trigger cross-domain C1–C10 rules.
     */
    static List<DetectionResult> filterForCorrelation(List<DetectionResult> detections,
                                                      RiskPolicy policy) {
        if (detections == null || detections.isEmpty()
                || policy == null || policy.getFamilyModes().isEmpty()) {
            return detections;
        }
        List<DetectionResult> out = new ArrayList<>(detections.size());
        for (DetectionResult det : detections) {
            out.add(det == null ? null : applyFamilyModes(det, policy, true));
        }
        return out;
    }

    private static DetectionResult applyFamilyModes(DetectionResult det,
                                                    RiskPolicy policy,
                                                    boolean stripInformationalOnly) {
        DetectionExecutionStatus exec = det.getExecutionStatus();
        if (exec == DetectionExecutionStatus.UNAVAILABLE
                || exec == DetectionExecutionStatus.TIMEOUT
                || exec == DetectionExecutionStatus.ERROR
                || exec == DetectionExecutionStatus.DISABLED) {
            return det;
        }
        List<String> origDetails = det.getDetails();
        List<EvidenceItem> origItems = det.getEvidenceItems();
        if (det.getRiskLevel() == RiskLevel.SAFE && det.getScore() == 0
                && origDetails.isEmpty() && origItems.isEmpty()) {
            return det;
        }

        String fallback = EvidenceFamily.fallbackFamilyForDetector(det.getDetectorName());
        List<String> keptDetails = new ArrayList<>(origDetails.size());
        Set<String> remainingFamilies = new LinkedHashSet<>();
        boolean strippedAny = false;

        for (String token : origDetails) {
            String family = resolveTokenFamily(token, fallback);
            RiskPolicy.FamilyMode mode = policy.getFamilyMode(family);
            if (mode == RiskPolicy.FamilyMode.ALLOWLIST
                    || (stripInformationalOnly && mode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY)) {
                strippedAny = true;
            } else {
                keptDetails.add(token);
                if (family != null) {
                    remainingFamilies.add(family);
                }
            }
        }

        List<EvidenceItem> keptItems = new ArrayList<>(origItems.size());
        EvidenceItem.Rank origMaxRank = EvidenceItem.Rank.INFO;
        EvidenceItem.Rank keptMaxRank = EvidenceItem.Rank.INFO;
        for (EvidenceItem item : origItems) {
            if (item == null) continue;
            origMaxRank = EvidenceItem.Rank.highest(origMaxRank, item.getRank());
            String family = resolveItemFamily(item, fallback);
            RiskPolicy.FamilyMode mode = policy.getFamilyMode(family);
            if (mode == RiskPolicy.FamilyMode.ALLOWLIST
                    || (stripInformationalOnly && mode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY)) {
                strippedAny = true;
            } else {
                keptItems.add(item);
                keptMaxRank = EvidenceItem.Rank.highest(keptMaxRank, item.getRank());
                if (family != null) {
                    remainingFamilies.add(family);
                }
            }
        }

        if (origDetails.isEmpty() && origItems.isEmpty()) {
            RiskPolicy.FamilyMode fallbackMode = policy.getFamilyMode(fallback);
            if (fallbackMode == RiskPolicy.FamilyMode.ALLOWLIST
                    || (stripInformationalOnly
                            && fallbackMode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY)) {
                return neutralizeDetection(det);
            }
            if (fallbackMode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY) {
                return det.withInformational(true);
            }
            return det;
        }

        if (strippedAny && keptDetails.isEmpty() && keptItems.isEmpty()) {
            return neutralizeDetection(det);
        }

        DetectionResult current = det;
        if (strippedAny) {
            RiskLevel targetLevel = det.getRiskLevel();
            DetectionStatus targetStatus = det.getStatus();
            int targetScore = det.getScore();
            boolean targetInformational = det.isInformational();
            if (!origItems.isEmpty() && keptMaxRank.getSeverity() < origMaxRank.getSeverity()) {
                targetScore = RiskScoringEngine.capScoreForRank(targetScore, keptMaxRank);
                targetLevel = RiskScoringEngine.capLevelForRank(targetLevel, keptMaxRank);
                if (keptMaxRank == EvidenceItem.Rank.INFO) {
                    targetStatus = DetectionStatus.WARNING;
                    targetInformational = true;
                } else if (keptMaxRank == EvidenceItem.Rank.WEAK
                        || (keptMaxRank == EvidenceItem.Rank.MEDIUM
                                && det.getRiskLevel().getValue() > RiskLevel.MEDIUM.getValue())) {
                    targetStatus = DetectionStatus.WARNING;
                }
            }
            String newEvidence = String.join("; ", keptDetails);
            current = new DetectionResult(
                    det.getDetectorName(),
                    targetLevel,
                    targetStatus,
                    targetScore,
                    det.getMaxScore(),
                    targetInformational,
                    det.getExecutionStatus(),
                    det.getChecksAttempted(),
                    det.getChecksSucceeded(),
                    det.getChecksFailed(),
                    det.getFailureReasons(),
                    keptDetails,
                    keptItems,
                    newEvidence
            ).withScanTier(det.getScanTier());
        }

        if (!stripInformationalOnly && !remainingFamilies.isEmpty()
                && allFamiliesInformationalOnly(remainingFamilies, policy)) {
            return current.withInformational(true);
        }
        return current;
    }

    private static DetectionResult neutralizeDetection(DetectionResult det) {
        DetectionExecutionStatus targetExec = det.getExecutionStatus() == DetectionExecutionStatus.RISK
                ? DetectionExecutionStatus.SAFE
                : det.getExecutionStatus();
        return new DetectionResult(
                det.getDetectorName(),
                RiskLevel.SAFE,
                DetectionStatus.NORMAL,
                0,
                det.getMaxScore(),
                false,
                targetExec,
                det.getChecksAttempted(),
                det.getChecksSucceeded(),
                det.getChecksFailed(),
                det.getFailureReasons(),
                Collections.emptyList(),
                Collections.emptyList(),
                ""
        ).withScanTier(det.getScanTier());
    }

    private static boolean allFamiliesInformationalOnly(Set<String> families, RiskPolicy policy) {
        for (String family : families) {
            if (policy.getFamilyMode(family) != RiskPolicy.FamilyMode.INFORMATIONAL_ONLY) {
                return false;
            }
        }
        return true;
    }

    private static String resolveTokenFamily(String token, String fallback) {
        String family = EvidenceFamily.familyOf(token);
        return family != null ? family : fallback;
    }

    private static String resolveItemFamily(EvidenceItem item, String fallback) {
        String family = item.getEvidenceFamily();
        if (family != null && !family.isBlank()) {
            return family.trim().toLowerCase(Locale.ROOT);
        }
        String inferred = EvidenceFamily.familyOf(item.getCode());
        return inferred != null ? inferred : fallback;
    }

    /**
     * Order-independent family-max deduplication: for each Evidence Family, the strongest
     * actionable detector wins regardless of registration order; weaker duplicates covering
     * no additional family remain visible as corroborating evidence.
     */
    public static List<DetectionResult> dedupeFamilies(List<DetectionResult> detections) {
        if (detections == null || detections.isEmpty()) {
            return new ArrayList<>();
        }
        int n = detections.size();
        List<Set<String>> familySets = new ArrayList<>(n);
        Map<String, Integer> familyWinners = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) {
            DetectionResult detection = detections.get(i);
            Set<String> families = EvidenceFamily.families(
                    detection.getDetails(), detection.getEvidenceItems());
            familySets.add(families);
            boolean actionable = !detection.isInformational() && detection.getScore() > 0;
            if (!actionable || families.isEmpty()) {
                continue;
            }
            for (String family : families) {
                Integer currentIdx = familyWinners.get(family);
                if (currentIdx == null || isStrongerWinner(detection, detections.get(currentIdx))) {
                    familyWinners.put(family, i);
                }
            }
        }

        List<DetectionResult> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            DetectionResult detection = detections.get(i);
            Set<String> families = familySets.get(i);
            boolean actionable = !detection.isInformational() && detection.getScore() > 0;
            if (!actionable || families.isEmpty()) {
                out.add(detection);
                continue;
            }
            boolean winsAnyFamily = false;
            for (String family : families) {
                Integer winnerIdx = familyWinners.get(family);
                if (winnerIdx != null && winnerIdx == i) {
                    winsAnyFamily = true;
                    break;
                }
            }
            out.add(winsAnyFamily ? detection : detection.asInformationalDuplicate());
        }
        return out;
    }

    private static boolean isStrongerWinner(DetectionResult candidate, DetectionResult incumbent) {
        if (candidate.getScore() != incumbent.getScore()) {
            return candidate.getScore() > incumbent.getScore();
        }
        return candidate.getRiskLevel().getValue() > incumbent.getRiskLevel().getValue();
    }

    public static DetectionResult correlate(List<DetectionResult> detections, CollectScene scene) {
        CollectScene effective = scene == null ? CollectScene.STANDARD : scene;
        DetectionResult emulator = find(detections, "emulator");
        DetectionResult root = find(detections, "root");
        DetectionResult mount = find(detections, "mount_analysis");
        DetectionResult hook = find(detections, "hook_framework");
        DetectionResult cloud = find(detections, "cloud_phone");
        DetectionResult rom = find(detections, "custom_rom");
        DetectionResult consistency = find(detections, "consistency");
        DetectionResult screenFraud = find(detections, "screen_and_fraud");

        List<String> details = new ArrayList<>();
        List<EvidenceItem> correlationItems = new ArrayList<>();
        int score = 0;
        RiskLevel level = RiskLevel.SAFE;
        DetectionStatus status = DetectionStatus.NORMAL;
        boolean informational = false;

        if (emulator != null) {
            int strong = 0;
            int usefulWeak = 0;
            boolean cpuOrQemu = false;
            for (String token : emulator.getDetails()) {
                EmulatorEvidenceClassifier.Rank rank = EmulatorEvidenceClassifier.rank(token);
                if (rank == EmulatorEvidenceClassifier.Rank.STRONG) {
                    strong++;
                } else if (rank == EmulatorEvidenceClassifier.Rank.WEAK
                        && !EmulatorEvidenceClassifier.isHardwareNoise(token)) {
                    usefulWeak++;
                }
                String lower = token.toLowerCase(Locale.ROOT);
                if (lower.startsWith("cpu:hypervisor") || lower.startsWith("qemu_")) {
                    cpuOrQemu = true;
                }
            }
            if (emulator.getRiskLevel().getValue() <= RiskLevel.LOW.getValue()
                    && strong == 0 && usefulWeak >= 3) {
                details.add("C1:emulator_weak_cluster");
                score = Math.max(score, 4);
                level = max(level, RiskLevel.MEDIUM);
                status = DetectionStatus.WARNING;
            }
            if (strong == 1 && cpuOrQemu
                    && emulator.getRiskLevel() == RiskLevel.MEDIUM) {
                details.add("C2:emulator_strong_plus_hypervisor");
                score = Math.max(score, 4);
                level = max(level, RiskLevel.HIGH);
                status = DetectionStatus.DANGER;
            }
        }

        boolean inline = containsPrefix(hook, "inline_hook:") || containsPrefix(hook, "got_hook:");
        boolean frida = containsFamily(hook, "frida");
        if (inline && frida) {
            details.add("C3:inline_hook_with_frida");
            score = Math.max(score, 10);
            level = RiskLevel.DEADLY;
            status = DetectionStatus.DANGER;
        }

        boolean hasSyscallMismatch = containsPrefix(root, "syscall_mismatch")
                || containsPrefix(root, "native:syscall_mismatch")
                || containsPrefix(mount, "syscall_mismatch");
        boolean hasRootMount = containsPrefix(root, "mount:module")
                || containsPrefix(root, "native:mount:module")
                || containsPrefix(root, "native:mount:magisk")
                || containsPrefix(mount, "module_mount")
                || containsPrefix(mount, "mountinfo:magisk")
                || containsPrefix(mount, "magisk_mount");
        if (hasSyscallMismatch && hasRootMount) {
            details.add("C4:hidden_root");
            score = Math.max(score, 8);
            level = max(level, RiskLevel.HIGH);
            status = DetectionStatus.DANGER;
        }

        if (containsPrefix(rom, "prop_mismatch:fingerprint")
                && (rom == null || !containsPrefix(rom, "community_rom:"))
                && (emulator == null || emulator.getStatus() == DetectionStatus.NORMAL)) {
            details.add("C5:resetprop_fingerprint");
            if (score == 0) {
                informational = true;
                score = 1;
                level = RiskLevel.LOW;
                status = DetectionStatus.WARNING;
            }
        }

        // C6:bridge_or_integrity_tamper — native code/JNI self-integrity tamper while
        // Java hook probes claim clean, OR UnsatisfiedLinkError paired with stealth signals.
        boolean nativeIntegrityTamper = hasNativeSelfIntegrityTamper(hook) && !hasJavaHookHit(hook);
        boolean linkFailureWithStealth = hasBridgeLinkFailureWithStealth(hook, root, mount);
        if (nativeIntegrityTamper || linkFailureWithStealth) {
            details.add("C6:bridge_or_integrity_tamper");
            correlationItems.add(new EvidenceItem(
                    "bridge_or_integrity_tamper",
                    EvidenceItem.SourceLayer.CORRELATION,
                    "hook_framework",
                    nativeIntegrityTamper ? "native_integrity_tamper_java_clean"
                            : "unsatisfied_link_with_stealth",
                    "hook_integrity",
                    EvidenceItem.Rank.STRONG));
            informational = false;
            score = Math.max(score, 10);
            level = RiskLevel.DEADLY;
            status = DetectionStatus.DANGER;
        }

        int cloudStrong = 0;
        int cloudWeak = 0;
        if (cloud != null) {
            for (String detail : cloud.getDetails()) {
                if (isStrongCloudToken(detail)) {
                    cloudStrong++;
                } else if (isWeakCloudToken(detail)) {
                    cloudWeak++;
                }
            }
        }
        if ((effective == CollectScene.LOGIN || effective == CollectScene.PAYMENT)
                && cloud != null && cloudStrong == 0 && cloudWeak >= 2) {
            details.add("C7:cloud_weak_cluster");
            if (score < 2) {
                score = 2;
                level = max(level, RiskLevel.LOW);
                status = DetectionStatus.WARNING;
            }
        }

        // C8:spoofed_verified_boot — hardware RootOfTrust reports unlocked/orange/red or
        // VBMeta empty-input digest while system properties claim verifiedbootstate=green + flash.locked=1 -> DEADLY/10.
        if (hasSpoofedVerifiedBoot(consistency)) {
            details.add("C8:spoofed_verified_boot");
            correlationItems.add(new EvidenceItem(
                    "spoofed_verified_boot",
                    EvidenceItem.SourceLayer.CORRELATION,
                    "consistency",
                    "hw_root_of_trust_or_vbmeta_contradicts_green_locked_props",
                    "boot_integrity",
                    EvidenceItem.Rank.STRONG));
            informational = false;
            score = Math.max(score, 10);
            level = RiskLevel.DEADLY;
            status = DetectionStatus.DANGER;
        }

        // C9:stealth_root_with_unmount — isolated cross-process mount diff or Bionic prop_area
        // hole/serial tamper while conventional root path checks ran and were all negative -> HIGH/8.
        boolean hasIsolatedMountDiff = hasIsolatedMountDiffEvidence(mount);
        boolean hasBionicPropTamper = hasBionicPropHoleOrSerialTamper(consistency);
        boolean rootRanCleanly = root != null
                && root.getExecutionStatus() != DetectionExecutionStatus.UNAVAILABLE
                && root.getExecutionStatus() != DetectionExecutionStatus.ERROR
                && !hasConventionalRootPathHit(root);
        if ((hasIsolatedMountDiff || hasBionicPropTamper) && rootRanCleanly) {
            details.add("C9:stealth_root_with_unmount");
            String reason = hasIsolatedMountDiff && hasBionicPropTamper
                    ? "isolated_mount_diff+bionic_prop_tamper"
                    : (hasIsolatedMountDiff ? "isolated_mount_diff" : "bionic_prop_tamper");
            correlationItems.add(new EvidenceItem(
                    "stealth_root_with_unmount",
                    EvidenceItem.SourceLayer.CORRELATION,
                    hasIsolatedMountDiff ? "mount_analysis" : "consistency",
                    reason,
                    "root_fw",
                    EvidenceItem.Rank.STRONG));
            informational = false;
            score = Math.max(score, 8);
            level = max(level, RiskLevel.HIGH);
            status = DetectionStatus.DANGER;
        }

        // C10:vishing_fraud_combo (PAYMENT scene): active voice/VoIP call paired with
        // screen sharing/recording or 3rd-party accessibility remote control -> HIGH/8.
        if (effective == CollectScene.PAYMENT && screenFraud != null) {
            boolean hasOngoingCall = containsPrefix(screenFraud, "ongoing_call:");
            boolean hasScreenOrA11y = containsPrefix(screenFraud, "virtual_display:")
                    || containsExact(screenFraud, "screen_recording_active")
                    || containsPrefix(screenFraud, "third_party_a11y:");
            if (hasOngoingCall && hasScreenOrA11y) {
                details.add("C10:vishing_fraud_combo");
                correlationItems.add(new EvidenceItem(
                        "vishing_fraud_combo",
                        EvidenceItem.SourceLayer.CORRELATION,
                        "screen_and_fraud",
                        "ongoing_call+screen_control",
                        "fraud_context",
                        EvidenceItem.Rank.STRONG));
                informational = false;
                score = Math.max(score, 8);
                level = max(level, RiskLevel.HIGH);
                status = DetectionStatus.DANGER;
            }
        }

        if (details.isEmpty()) {
            return null;
        }
        DetectionResult result = new DetectionResult(
                "signal_correlation",
                level,
                status,
                score,
                10,
                informational,
                details,
                String.join("; ", details)
        );
        return correlationItems.isEmpty() ? result : result.withEvidenceItems(correlationItems);
    }

    private static boolean hasNativeSelfIntegrityTamper(DetectionResult hook) {
        if (hook == null) return false;
        for (String detail : hook.getDetails()) {
            if (SelfIntegrityProbe.isSelfIntegrityToken(detail)) {
                return true;
            }
        }
        for (EvidenceItem item : hook.getEvidenceItems()) {
            if (item.getMergedSources().contains(EvidenceItem.SourceLayer.NATIVE)
                    && SelfIntegrityProbe.isSelfIntegrityCode(item.getCode())) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasJavaHookHit(DetectionResult hook) {
        if (hook == null) return false;
        for (EvidenceItem item : hook.getEvidenceItems()) {
            if (item.getMergedSources().contains(EvidenceItem.SourceLayer.JAVA)
                    && item.getRank() != EvidenceItem.Rank.INFO) {
                return true;
            }
        }
        for (String detail : hook.getDetails()) {
            if (detail == null) continue;
            String lower = detail.toLowerCase(Locale.ROOT);
            if (lower.startsWith("xposed_")
                    || lower.startsWith("frida_maps")
                    || lower.startsWith("frida_dbus_port:")
                    || lower.startsWith("frida_port_open:")
                    || lower.startsWith("frida_thread:")
                    || lower.startsWith("frida_pid")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasSpoofedVerifiedBoot(DetectionResult consistency) {
        if (consistency == null) return false;
        if (containsExact(consistency, "spoofed_verified_boot_props")
                || containsPrefix(consistency, "spoofed_verified_boot_props:")) {
            return true;
        }
        for (EvidenceItem item : consistency.getEvidenceItems()) {
            if (item != null && "spoofed_verified_boot_props".equals(item.getCode())) {
                return true;
            }
        }
        boolean hasHwBootAnomaly = containsPrefix(consistency, "key_attestation:bootloader_unlocked")
                || containsPrefix(consistency, "key_attestation:verified_boot_orange")
                || containsPrefix(consistency, "key_attestation:verified_boot_red")
                || containsPrefix(consistency, "vbmeta_empty_input_digest");
        boolean claimsGreenLocked = containsExact(consistency, "props_claim_green_locked")
                || containsExact(consistency, "verified_boot_state:green");
        return hasHwBootAnomaly && claimsGreenLocked;
    }

    private static boolean hasIsolatedMountDiffEvidence(DetectionResult mount) {
        if (mount == null) return false;
        if (containsPrefix(mount, "isolated_mount_diff")) {
            return true;
        }
        for (EvidenceItem item : mount.getEvidenceItems()) {
            if (item != null && "isolated_mount_diff".equals(item.getCode())) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasBionicPropHoleOrSerialTamper(DetectionResult consistency) {
        if (consistency == null) return false;
        if (containsPrefix(consistency, "prop_area_hole")
                || containsPrefix(consistency, "prop_ro_serial_modified")
                || containsPrefix(consistency, "prop_ro_nul_tail_residual")) {
            return true;
        }
        for (EvidenceItem item : consistency.getEvidenceItems()) {
            if (item == null) continue;
            String code = item.getCode();
            if ("prop_area_hole".equals(code)
                    || "prop_area_hole_critical".equals(code)
                    || "prop_ro_serial_modified".equals(code)
                    || "prop_ro_nul_tail_residual".equals(code)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasConventionalRootPathHit(DetectionResult root) {
        if (root == null) return false;
        for (String detail : root.getDetails()) {
            if (detail == null) continue;
            String lower = detail.toLowerCase(Locale.ROOT);
            if (lower.startsWith("native:")) {
                lower = lower.substring("native:".length());
            }
            if (lower.startsWith("su_found:")
                    || lower.startsWith("su:")
                    || lower.startsWith("path_su:")
                    || lower.startsWith("magisk_found:")
                    || lower.startsWith("magisk:")
                    || lower.startsWith("ksu_found:")
                    || lower.startsWith("ksu:")
                    || lower.startsWith("apatch_found:")
                    || lower.startsWith("apatch:")
                    || lower.startsWith("modules_found:")
                    || lower.startsWith("modules:")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasBridgeLinkFailureWithStealth(DetectionResult hook,
                                                           DetectionResult root,
                                                           DetectionResult mount) {
        boolean hasLinkError = containsIgnoreCase(hook, "unsatisfiedlinkerror")
                || containsIgnoreCase(root, "unsatisfiedlinkerror");
        if (!hasLinkError) {
            return false;
        }
        return containsPrefix(root, "syscall_mismatch")
                || containsPrefix(root, "native:syscall_mismatch")
                || containsPrefix(root, "listing_mismatch")
                || containsPrefix(root, "native:listing_mismatch")
                || containsPrefix(mount, "syscall_mismatch")
                || containsPrefix(hook, "anon_exec:")
                || containsPrefix(hook, "memfd_private_elf:")
                || containsFamily(hook, "frida")
                || containsFamily(hook, "xposed");
    }

    private static boolean containsIgnoreCase(DetectionResult detection, String needleLower) {
        if (detection == null) return false;
        for (String reason : detection.getFailureReasons()) {
            if (reason != null && reason.toLowerCase(Locale.ROOT).contains(needleLower)) {
                return true;
            }
        }
        for (String detail : detection.getDetails()) {
            if (detail != null && detail.toLowerCase(Locale.ROOT).contains(needleLower)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDebuggableOnly(DetectionResult detection) {
        if (detection.getDetails().isEmpty()) return false;
        for (String detail : detection.getDetails()) {
            if (!"debuggable_flag".equals(detail)) return false;
        }
        return true;
    }

    private static DetectionResult find(List<DetectionResult> detections, String name) {
        for (DetectionResult detection : detections) {
            if (name.equals(detection.getDetectorName())) return detection;
        }
        return null;
    }

    private static boolean containsPrefix(DetectionResult detection, String prefix) {
        if (detection == null) return false;
        for (String detail : detection.getDetails()) {
            if (detail != null && detail.startsWith(prefix)) return true;
        }
        return false;
    }

    private static boolean containsExact(DetectionResult detection, String expected) {
        if (detection == null || expected == null) return false;
        for (String detail : detection.getDetails()) {
            if (expected.equals(detail)) return true;
        }
        return false;
    }

    private static boolean isStrongCloudToken(String detail) {
        if (detail == null) return false;
        String lower = detail.toLowerCase(Locale.ROOT);
        return lower.startsWith("cloud_pkg:")
                || lower.startsWith("cloud_prop:")
                || lower.startsWith("virtual_gpu:");
    }

    private static boolean isWeakCloudToken(String detail) {
        if (detail == null) return false;
        String lower = detail.toLowerCase(Locale.ROOT);
        return lower.startsWith("wired_interface:")
                || lower.startsWith("battery_zero:")
                || lower.startsWith("battery_anomaly:")
                || lower.startsWith("low_camera_count:")
                || lower.startsWith("very_low_sensor_count:");
    }

    private static boolean containsFamily(DetectionResult detection, String family) {
        return detection != null
                && EvidenceFamily.families(detection.getDetails(), detection.getEvidenceItems())
                        .contains(family);
    }

    private static RiskLevel max(RiskLevel a, RiskLevel b) {
        return a.getValue() >= b.getValue() ? a : b;
    }
}
