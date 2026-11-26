package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.root.KernelSidechannelProbe;
import com.wsttxm.riskenginesdk.detector.probe.root.SelinuxAuditProbe;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

public class RootDetector extends BaseDetector {
    public static final String EVIDENCE_FAMILY = "root_fw";

    private static final String[] ANDROID_PATH_PREFIXES = {
            "/system/", "/system_ext/", "/vendor/", "/product/", "/odm/",
            "/apex/", "/sbin", "/su/", "/data/", "/debug_ramdisk/"
    };

    private final SignalSnapshot signals;
    private final Supplier<String> pathEnvSupplier;

    public RootDetector(Context context) {
        this(context, new SignalSnapshot(context), () -> System.getenv("PATH"));
    }

    public RootDetector(Context context, SignalSnapshot signals) {
        this(context, signals, () -> System.getenv("PATH"));
    }

    public RootDetector(Context context,
                        SignalSnapshot signals,
                        Supplier<String> pathEnvSupplier) {
        super(context);
        this.signals = signals;
        this.pathEnvSupplier = pathEnvSupplier != null
                ? pathEnvSupplier
                : () -> System.getenv("PATH");
    }

    @Override
    public String getName() {
        return "root";
    }

    @Override
    public boolean hasPostponedProbes() {
        return true;
    }

    @Override
    protected DetectionResult detect() {
        List<String> strongEvidence = new ArrayList<>();
        List<String> mediumEvidence = new ArrayList<>();
        List<String> weakEvidence = new ArrayList<>();
        List<EvidenceItem> evidenceItems = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        probePaths("su_found:", "su_binary", DetectionLists.SU_PATHS,
                strongEvidence, evidenceItems, coverage, "su_paths");
        probeDynamicPathSu(strongEvidence, evidenceItems);
        probePaths("magisk_found:", "magisk_artifact", DetectionLists.MAGISK_PATHS,
                strongEvidence, evidenceItems, coverage, "magisk_paths");
        probePaths("ksu_found:", "ksu_artifact", DetectionLists.KERNELSU_PATHS,
                strongEvidence, evidenceItems, coverage, "ksu_paths");
        probePaths("apatch_found:", "apatch_artifact", DetectionLists.APATCH_PATHS,
                strongEvidence, evidenceItems, coverage, "apatch_paths");
        probePaths("modules_found:", "root_modules_dir", DetectionLists.MODULE_PATHS,
                strongEvidence, evidenceItems, coverage, "module_paths");

        SignalResult<Integer> selinux = signals.getSelinuxEnforce();
        if (selinux.isSuccess() && selinux.getValue() != null) {
            coverage.success();
            if (selinux.getValue() == 0) {
                addUnique(weakEvidence, "selinux_permissive");
                evidenceItems.add(new EvidenceItem(
                        "selinux_permissive",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/sys/fs/selinux/enforce",
                        "0",
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.WEAK));
            }
        } else {
            coverage.failure("selinux:" + selinux.getFailureReason());
        }

        SignalResult<String> nativeDetails = signals.getNativeRootEvidence();
        if (nativeDetails.isSuccess()) {
            coverage.success();
            String rawEvidence = nativeDetails.getValue();
            if (rawEvidence != null && !rawEvidence.isEmpty()) {
                for (String token : rawEvidence.split(",")) {
                    String item = token.trim();
                    if (item.isEmpty()) continue;
                    classifyNativeToken(item, strongEvidence, mediumEvidence, weakEvidence, evidenceItems);
                }
            }
        } else {
            coverage.failure("native_root:" + nativeDetails.getFailureReason());
        }

        try {
            String tags = android.os.Build.TAGS;
            if (tags != null && tags.contains("test-keys")) {
                addUnique(weakEvidence, "test_keys");
                evidenceItems.add(new EvidenceItem(
                        "test_keys",
                        EvidenceItem.SourceLayer.JAVA,
                        "Build.TAGS",
                        "test-keys",
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.WEAK));
            }
            coverage.success();
        } catch (RuntimeException e) {
            coverage.failure("build_tags:" + e.getClass().getSimpleName());
        }

        List<String> allEvidence = new ArrayList<>(strongEvidence);
        allEvidence.addAll(mediumEvidence);
        allEvidence.addAll(weakEvidence);
        DetectionResult base;
        if (!strongEvidence.isEmpty()) {
            base = result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    allEvidence, String.join("; ", allEvidence), coverage);
        } else if (!mediumEvidence.isEmpty()) {
            base = result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    allEvidence, String.join("; ", allEvidence), coverage);
        } else if (!weakEvidence.isEmpty()) {
            base = result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    weakEvidence, String.join("; ", weakEvidence), coverage);
        } else {
            base = safe(coverage);
        }
        return evidenceItems.isEmpty() ? base : base.withEvidenceItems(evidenceItems);
    }

    /**
     * Stage 3 postponed pass: executes heavy native probes ({@link KernelSidechannelProbe}
     * including {@code disposable_child} and ARM64 {@code prctl} timing, plus
     * {@link SelinuxAuditProbe}) and consolidates findings into {@code priorResult}.
     */
    @Override
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        KernelSidechannelProbe.ProbeResult sidechannel =
                KernelSidechannelProbe.probe(signals, true);
        SelinuxAuditProbe.ProbeResult selinuxAudit =
                SelinuxAuditProbe.probe(signals);

        List<String> newStrong = new ArrayList<>();
        List<String> newMedium = new ArrayList<>();
        List<EvidenceItem> newItems = new ArrayList<>();
        int extraSucceeded = 0;

        if (sidechannel.isUsable()) {
            extraSucceeded++;
            for (String tok : sidechannel.getStrongTokens()) {
                newStrong.add("native:" + tok);
            }
            for (String tok : sidechannel.getMediumTokens()) {
                newMedium.add("native:" + tok);
            }
            newItems.addAll(sidechannel.getEvidenceItems());
        }
        if (selinuxAudit.isUsable()) {
            extraSucceeded++;
            for (String tok : selinuxAudit.getStrongTokens()) {
                newStrong.add("native:" + tok);
            }
            newItems.addAll(selinuxAudit.getEvidenceItems());
        }

        if (newItems.isEmpty()) {
            return priorResult;
        }

        Set<String> mergedDetails = new LinkedHashSet<>();
        List<EvidenceItem> mergedItems = new ArrayList<>();
        int attempted = extraSucceeded;
        int succeeded = extraSucceeded;
        int failed = 0;
        List<String> failureReasons = new ArrayList<>();
        RiskLevel level = RiskLevel.SAFE;
        DetectionStatus status = DetectionStatus.NORMAL;
        int score = 0;
        boolean informational = false;

        if (priorResult != null) {
            boolean priorUsable = priorResult.getExecutionStatus() != DetectionExecutionStatus.UNAVAILABLE
                    && priorResult.getExecutionStatus() != DetectionExecutionStatus.ERROR;
            if (priorUsable) {
                mergedDetails.addAll(priorResult.getDetails());
                level = priorResult.getRiskLevel();
                status = priorResult.getStatus();
                score = priorResult.getScore();
                informational = priorResult.isInformational();
            }
            mergedItems.addAll(priorResult.getEvidenceItems());
            attempted = priorResult.getChecksAttempted() + extraSucceeded;
            succeeded = priorResult.getChecksSucceeded() + extraSucceeded;
            failed = priorResult.getChecksFailed();
            failureReasons.addAll(priorResult.getFailureReasons());
        }

        mergedDetails.addAll(newStrong);
        mergedDetails.addAll(newMedium);
        mergedItems.addAll(newItems);

        if (!newStrong.isEmpty()) {
            level = RiskLevel.HIGH;
            status = DetectionStatus.DANGER;
            score = Math.max(score, 8);
            informational = false;
        } else if (!newMedium.isEmpty() && level.getValue() < RiskLevel.HIGH.getValue()) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = Math.max(score, 4);
            informational = false;
        }

        List<String> detailList = new ArrayList<>(mergedDetails);
        DetectionExecutionStatus execStatus = failed > 0
                ? DetectionExecutionStatus.PARTIAL
                : DetectionExecutionStatus.RISK;

        return new DetectionResult(
                getName(),
                level,
                status,
                score,
                10,
                informational,
                execStatus,
                attempted,
                succeeded,
                failed,
                failureReasons,
                detailList,
                mergedItems,
                String.join("; ", detailList)
        ).withScanTier(getScanTier());
    }

    private void classifyNativeToken(String item,
                                     List<String> strong,
                                     List<String> medium,
                                     List<String> weak,
                                     List<EvidenceItem> items) {
        if (item.startsWith("busybox:") || item.equals("busybox")) {
            // BusyBox noise isolation: strictly LOW/1 informational, never actionable root.
            String path = item.startsWith("busybox:") ? item.substring("busybox:".length()) : "busybox";
            addUnique(weak, "busybox:" + path);
            items.add(new EvidenceItem(
                    "busybox",
                    EvidenceItem.SourceLayer.NATIVE,
                    path,
                    "present",
                    EVIDENCE_FAMILY,
                    EvidenceItem.Rank.WEAK));
            return;
        }
        if (item.equals("selinux_permissive")) {
            addUnique(weak, item);
            items.add(new EvidenceItem(
                    "selinux_permissive",
                    EvidenceItem.SourceLayer.NATIVE,
                    "/sys/fs/selinux/enforce",
                    "0",
                    EVIDENCE_FAMILY,
                    EvidenceItem.Rank.WEAK));
            return;
        }
        if (item.startsWith("syscall_mismatch:") || item.startsWith("syscall_mismatch")
                || item.startsWith("eacces_exists:")) {
            addUnique(medium, "native:" + item);
            String code = item.startsWith("eacces_exists:") ? "eacces_exists" : "syscall_mismatch";
            String loc = extractSuffix(item);
            items.add(new EvidenceItem(
                    code,
                    EvidenceItem.SourceLayer.NATIVE,
                    loc,
                    item,
                    EVIDENCE_FAMILY,
                    EvidenceItem.Rank.MEDIUM));
            return;
        }

        addUnique(strong, "native:" + item);
        String code;
        String loc = extractSuffix(item);
        if (item.startsWith("su:") || item.startsWith("path_su:")) {
            code = "su_binary";
        } else if (item.startsWith("magisk:")) {
            code = "magisk_artifact";
        } else if (item.startsWith("ksu:")) {
            code = "ksu_artifact";
        } else if (item.startsWith("apatch:")) {
            code = "apatch_artifact";
        } else if (item.startsWith("modules:")) {
            code = "root_modules_dir";
        } else if (item.startsWith("ksu_prctl")) {
            code = "ksu_prctl";
        } else if (item.startsWith("listing_mismatch:")) {
            code = "listing_mismatch";
        } else if (item.startsWith("selinux_context:")) {
            code = "selinux_context";
        } else if (item.startsWith("mount:")) {
            code = "root_mount_marker";
        } else {
            code = "native_root_artifact";
        }
        items.add(new EvidenceItem(
                code,
                EvidenceItem.SourceLayer.NATIVE,
                loc.isEmpty() ? item : loc,
                item,
                EVIDENCE_FAMILY,
                EvidenceItem.Rank.STRONG));
    }

    /**
     * Merges Android-prefixed directories from {@code $PATH} without duplicating static
     * {@link DetectionLists#SU_PATHS} entries.
     */
    private void probeDynamicPathSu(List<String> strong, List<EvidenceItem> items) {
        try {
            String pathEnv = pathEnvSupplier.get();
            List<String> extraCandidates = mergeDynamicSuPaths(pathEnv);
            for (String candidate : extraCandidates) {
                SignalResult<Boolean> exists = signals.getPathExists(candidate);
                if (exists != null && exists.isSuccess() && Boolean.TRUE.equals(exists.getValue())) {
                    addUnique(strong, "su_found:" + candidate);
                    items.add(new EvidenceItem(
                            "su_binary",
                            EvidenceItem.SourceLayer.JAVA,
                            candidate,
                            "exists",
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                }
            }
        } catch (Exception ignored) {
            // Non-critical supplement to static SU_PATHS and native $PATH scan.
        }
    }

    static List<String> mergeDynamicSuPaths(String pathEnv) {
        if (pathEnv == null || pathEnv.isBlank()) {
            return List.of();
        }
        Set<String> known = new LinkedHashSet<>(Arrays.asList(DetectionLists.SU_PATHS));
        Set<String> extra = new LinkedHashSet<>();
        for (String rawDir : pathEnv.split(":")) {
            if (rawDir == null) continue;
            String dir = rawDir.trim();
            while (dir.length() > 1 && dir.endsWith("/")) {
                dir = dir.substring(0, dir.length() - 1);
            }
            if (!isAndroidSystemPathDir(dir)) {
                continue;
            }
            String candidate = dir + "/su";
            if (!known.contains(candidate)) {
                extra.add(candidate);
            }
        }
        return new ArrayList<>(extra);
    }

    private static boolean isAndroidSystemPathDir(String dir) {
        if (dir == null || dir.isEmpty()) {
            return false;
        }
        for (String prefix : ANDROID_PATH_PREFIXES) {
            if (dir.equals(prefix) || dir.startsWith(prefix)
                    || (prefix.endsWith("/") && dir.equals(prefix.substring(0, prefix.length() - 1)))) {
                return true;
            }
        }
        return false;
    }

    private void probePaths(String prefix,
                            String evidenceCode,
                            String[] paths,
                            List<String> strong,
                            List<EvidenceItem> items,
                            CheckCoverage coverage,
                            String failureKey) {
        try {
            boolean pathsAvailable = true;
            for (String path : paths) {
                SignalResult<Boolean> exists = signals.getPathExists(path);
                if (!exists.isSuccess()) pathsAvailable = false;
                if (Boolean.TRUE.equals(exists.getValue())) {
                    addUnique(strong, prefix + path);
                    items.add(new EvidenceItem(
                            evidenceCode,
                            EvidenceItem.SourceLayer.JAVA,
                            path,
                            "exists",
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                }
            }
            if (pathsAvailable) coverage.success();
            else coverage.failure(failureKey + ":access_failed");
        } catch (SecurityException e) {
            coverage.failure(failureKey + ":" + e.getClass().getSimpleName());
        }
    }

    private static String extractSuffix(String token) {
        int colon = token.indexOf(':');
        return (colon >= 0 && colon + 1 < token.length()) ? token.substring(colon + 1) : token;
    }

    private static void addUnique(List<String> list, String item) {
        if (!list.contains(item)) {
            list.add(item);
        }
    }
}
