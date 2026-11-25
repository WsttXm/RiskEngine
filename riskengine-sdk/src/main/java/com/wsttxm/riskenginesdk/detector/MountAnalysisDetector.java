package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;
import com.wsttxm.riskenginesdk.process.MountViewNormalizer;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

public class MountAnalysisDetector extends BaseDetector {
    public static final String EVIDENCE_FAMILY = "root_fw";

    private final SignalSnapshot signals;
    private final boolean isolatedProbeEnabled;
    private final Supplier<SignalResult<String>> nativeForensicsSupplier;

    public MountAnalysisDetector(Context context) {
        this(context, new SignalSnapshot(context), true,
                NativeCollectorBridge::getMountForensicsResult);
    }

    public MountAnalysisDetector(Context context, SignalSnapshot signals) {
        this(context, signals, true, NativeCollectorBridge::getMountForensicsResult);
    }

    public MountAnalysisDetector(Context context,
                                 SignalSnapshot signals,
                                 boolean isolatedProbeEnabled) {
        this(context, signals, isolatedProbeEnabled,
                NativeCollectorBridge::getMountForensicsResult);
    }

    public MountAnalysisDetector(Context context,
                                 SignalSnapshot signals,
                                 boolean isolatedProbeEnabled,
                                 Supplier<SignalResult<String>> nativeForensicsSupplier) {
        super(context);
        this.signals = signals;
        this.isolatedProbeEnabled = isolatedProbeEnabled;
        this.nativeForensicsSupplier = nativeForensicsSupplier != null
                ? nativeForensicsSupplier
                : NativeCollectorBridge::getMountForensicsResult;
    }

    @Override
    public String getName() {
        return "mount_analysis";
    }

    @Override
    public boolean hasPostponedProbes() {
        return true;
    }

    @Override
    protected DetectionResult detect() {
        List<String> strongEvidence = new ArrayList<>();
        List<String> mediumEvidence = new ArrayList<>();
        List<EvidenceItem> evidenceItems = new ArrayList<>();

        boolean mountsAvailable = checkMounts(mediumEvidence, evidenceItems);
        boolean mountInfoAvailable = checkMountInfo(mediumEvidence, evidenceItems);

        // /proc/mounts may expose only the shared debug_ramdisk marker while
        // mountinfo still names the owning framework. Prefer that specific
        // attribution and avoid presenting both as separate findings.
        if (mediumEvidence.contains("mountinfo:ksu")) {
            mediumEvidence.remove("debug_ramdisk_mount");
            removeEvidenceByCode(evidenceItems, "debug_ramdisk_mount");
            mediumEvidence.remove("mountinfo:ksu");
            mediumEvidence.add(0, "mountinfo:ksu");
        } else if (mediumEvidence.contains("mountinfo:magisk")) {
            mediumEvidence.remove("debug_ramdisk_mount");
            removeEvidenceByCode(evidenceItems, "debug_ramdisk_mount");
            mediumEvidence.remove("mountinfo:magisk");
            mediumEvidence.add(0, "mountinfo:magisk");
        }

        CheckCoverage coverage = new CheckCoverage();
        if (mountsAvailable) coverage.success();
        else coverage.failure("proc_mounts_unavailable");
        if (mountInfoAvailable) coverage.success();
        else coverage.failure("proc_mountinfo_unavailable");

        boolean nativeForensicsAvailable = checkNativeMountForensics(
                strongEvidence, mediumEvidence, evidenceItems);
        if (nativeForensicsAvailable) {
            coverage.success();
        }

        List<String> allEvidence = new ArrayList<>(strongEvidence);
        for (String item : mediumEvidence) {
            addUnique(allEvidence, item);
        }

        DetectionResult base;
        if (!strongEvidence.isEmpty()) {
            base = result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    allEvidence, String.join("; ", allEvidence), coverage);
        } else if (!mediumEvidence.isEmpty()) {
            base = result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    allEvidence, String.join("; ", allEvidence), coverage);
        } else if (!mountsAvailable && !mountInfoAvailable && !nativeForensicsAvailable) {
            return unavailable("procfs_mounts_unavailable");
        } else {
            base = safe(coverage);
        }
        return evidenceItems.isEmpty() ? base : base.withEvidenceItems(evidenceItems);
    }

    /**
     * Stage 3 postponed pass: executes the ephemeral {@code RiskIsolatedProbeService}
     * cross-process mount table diff and merges selective-unmount findings into
     * {@code priorResult} without impacting FAST-tier latency.
     */
    @Override
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        if (!isolatedProbeEnabled || signals == null) {
            return priorResult;
        }
        SignalResult<IsolatedProbeClient.IsolatedMountReport> reportResult =
                signals.getIsolatedMountReport(true);
        if (reportResult == null || !reportResult.isSuccess()
                || reportResult.getValue() == null
                || reportResult.getValue().getDiffResult() == null) {
            return priorResult;
        }

        MountViewNormalizer.MountDiffResult diff = reportResult.getValue().getDiffResult();
        if (!diff.hasSelectiveUnmountEvidence()) {
            return priorResult;
        }

        List<String> newStrong = new ArrayList<>();
        List<String> newMedium = new ArrayList<>();
        List<EvidenceItem> newItems = new ArrayList<>();

        boolean hasDirectRoot = !diff.getDirectRootTokens().isEmpty();
        for (String rootTok : diff.getDirectRootTokens()) {
            addUnique(newStrong, "isolated_mount_diff:root:" + rootTok);
            newItems.add(new EvidenceItem(
                    "isolated_mount_diff",
                    EvidenceItem.SourceLayer.ISOLATED,
                    rootTok,
                    "selective_unmount_root_token",
                    EVIDENCE_FAMILY,
                    EvidenceItem.Rank.STRONG));
        }
        for (String hidden : diff.getSuspiciousHiddenMounts()) {
            String token = "isolated_mount_diff:hidden:" + hidden;
            if (hasDirectRoot) {
                addUnique(newStrong, token);
            } else {
                addUnique(newMedium, token);
            }
            newItems.add(new EvidenceItem(
                    "isolated_mount_diff",
                    EvidenceItem.SourceLayer.ISOLATED,
                    hidden,
                    "hidden_in_main_process",
                    EVIDENCE_FAMILY,
                    hasDirectRoot ? EvidenceItem.Rank.STRONG : EvidenceItem.Rank.MEDIUM));
        }

        if (newItems.isEmpty()) {
            return priorResult;
        }

        Set<String> mergedDetails = new LinkedHashSet<>();
        List<EvidenceItem> mergedItems = new ArrayList<>();
        int attempted = 1;
        int succeeded = 1;
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
            attempted = priorResult.getChecksAttempted() + 1;
            succeeded = priorResult.getChecksSucceeded() + 1;
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

    private boolean checkNativeMountForensics(List<String> strong,
                                              List<String> medium,
                                              List<EvidenceItem> items) {
        try {
            SignalResult<String> raw = nativeForensicsSupplier.get();
            if (raw == null || !raw.isSuccess() || raw.getValue() == null
                    || raw.getValue().isEmpty()) {
                return false;
            }
            NativePayloadCodec.DecodedPayload decoded =
                    NativePayloadCodec.decodePayload(raw.getValue());
            if (!decoded.isOk()) {
                return false;
            }
            for (Map<String, String> rec : decoded.getRecords()) {
                String kind = rec.get("kind");
                if (kind == null || kind.isEmpty()) {
                    continue;
                }
                switch (kind) {
                    case "statx_mnt_id_hidden": {
                        String path = nonEmpty(rec.get("path"), "/system");
                        String mntId = nonEmpty(rec.get("mnt_id"), "?");
                        addUnique(strong, "native:statx_mnt_id_hidden:" + path);
                        items.add(new EvidenceItem(
                                "statx_mnt_id_hidden",
                                EvidenceItem.SourceLayer.NATIVE,
                                path,
                                "mnt_id=" + mntId,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.STRONG));
                        break;
                    }
                    case "system_ro_rw_mount": {
                        String path = nonEmpty(rec.get("path"), "/system");
                        String fs = rec.getOrDefault("fs", "");
                        String opts = rec.getOrDefault("opts", "rw");
                        addUnique(medium, "native:system_ro_rw_mount:" + path);
                        items.add(new EvidenceItem(
                                "system_ro_rw_mount",
                                EvidenceItem.SourceLayer.NATIVE,
                                path,
                                fs.isEmpty() ? opts : (fs + ":" + opts),
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                        break;
                    }
                    case "mount_mtime_mismatch": {
                        String val = "mounts=" + rec.getOrDefault("mounts", "?")
                                + ",mountinfo=" + rec.getOrDefault("mountinfo", "?")
                                + ",mountstats=" + rec.getOrDefault("mountstats", "?");
                        addUnique(medium, "native:mount_mtime_mismatch");
                        items.add(new EvidenceItem(
                                "mount_mtime_mismatch",
                                EvidenceItem.SourceLayer.NATIVE,
                                "/proc/self/mounts",
                                val,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                        break;
                    }
                    case "statfs_overlay_on_system": {
                        String path = nonEmpty(rec.get("path"), "/system");
                        if (isBenignStockOemOverlayInMountInfo(path)) {
                            break;
                        }
                        String magic = nonEmpty(rec.get("magic"), "0x794c7630");
                        addUnique(medium, "native:statfs_overlay_on_system:" + path);
                        items.add(new EvidenceItem(
                                "statfs_overlay_on_system",
                                EvidenceItem.SourceLayer.NATIVE,
                                path,
                                magic,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                        break;
                    }
                    case "statfs_tmpfs_on_system": {
                        String path = nonEmpty(rec.get("path"), "/system");
                        String magic = nonEmpty(rec.get("magic"), "0x01021994");
                        addUnique(medium, "native:statfs_tmpfs_on_system:" + path);
                        items.add(new EvidenceItem(
                                "statfs_tmpfs_on_system",
                                EvidenceItem.SourceLayer.NATIVE,
                                path,
                                magic,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                        break;
                    }
                    default:
                        break;
                }
            }
            return true;
        } catch (Exception | LinkageError e) {
            CLog.e("Native mount forensics check failed", e);
            return false;
        }
    }

    private boolean checkMounts(List<String> evidence, List<EvidenceItem> items) {
        try {
            SignalResult<String> mounts = signals.getTextFile("/proc/mounts");
            if (!mounts.isSuccess() || mounts.getValue() == null) return false;
            String allMounts = mounts.getValue().toLowerCase(Locale.ROOT);
            boolean hasKernelSu = allMounts.contains("kernelsu")
                    || allMounts.contains("/data/adb/ksu")
                    || allMounts.contains(" ksu ");
            boolean hasMagisk = allMounts.contains("magisk")
                    || allMounts.contains("core/mirror");
            if (hasKernelSu) {
                addUnique(evidence, "kernelsu_mount");
                items.add(new EvidenceItem(
                        "kernelsu_mount",
                        EvidenceItem.SourceLayer.JAVA,
                        "/proc/mounts",
                        "kernelsu",
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.MEDIUM));
            }
            if (hasMagisk) {
                addUnique(evidence, "magisk_mount");
                items.add(new EvidenceItem(
                        "magisk_mount",
                        EvidenceItem.SourceLayer.JAVA,
                        "/proc/mounts",
                        "magisk",
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.MEDIUM));
            }
            if (!hasKernelSu && !hasMagisk && allMounts.contains("debug_ramdisk")) {
                addUnique(evidence, "debug_ramdisk_mount");
                items.add(new EvidenceItem(
                        "debug_ramdisk_mount",
                        EvidenceItem.SourceLayer.JAVA,
                        "/proc/mounts",
                        "debug_ramdisk",
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.MEDIUM));
            }
            for (String line : mounts.getValue().split("\\n")) {
                String lower = line.toLowerCase(Locale.ROOT);
                // Docker/container markers
                if (lower.contains("docker") || lower.contains("overlay") && lower.contains("lowerdir")) {
                    if (lower.contains("/docker/")) {
                        if (addUnique(evidence, "docker_mount")) {
                            items.add(new EvidenceItem(
                                    "docker_mount",
                                    EvidenceItem.SourceLayer.JAVA,
                                    "/proc/mounts",
                                    "/docker/",
                                    EVIDENCE_FAMILY,
                                    EvidenceItem.Rank.MEDIUM));
                        }
                    }
                }
                // Check for bind mounts on system partitions (common in modification frameworks)
                if (lower.contains("/data/adb/modules")) {
                    if (addUnique(evidence, "module_mount")) {
                        items.add(new EvidenceItem(
                                "module_mount",
                                EvidenceItem.SourceLayer.JAVA,
                                "/data/adb/modules",
                                "module_mount",
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                    }
                }
            }
            return true;
        } catch (Exception e) {
            CLog.e("Mount check failed", e);
            return false;
        }
    }

    private boolean checkMountInfo(List<String> evidence, List<EvidenceItem> items) {
        try {
            SignalResult<String> mountInfo = signals.getTextFile("/proc/self/mountinfo");
            if (!mountInfo.isSuccess() || mountInfo.getValue() == null) return false;
            String content = mountInfo.getValue();
            String lower = content.toLowerCase(Locale.ROOT);
            if (lower.contains("kernelsu") || lower.contains("/data/adb/ksu")
                    || lower.contains(" ksu ")) {
                if (addUnique(evidence, "mountinfo:ksu")) {
                    items.add(new EvidenceItem(
                            "mountinfo_ksu",
                            EvidenceItem.SourceLayer.JAVA,
                            "/proc/self/mountinfo",
                            "ksu",
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.MEDIUM));
                }
            }
            if (lower.contains("magisk") || lower.contains("core/mirror")) {
                if (addUnique(evidence, "mountinfo:magisk")) {
                    items.add(new EvidenceItem(
                            "mountinfo_magisk",
                            EvidenceItem.SourceLayer.JAVA,
                            "/proc/self/mountinfo",
                            "magisk",
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.MEDIUM));
                }
            }
            // Detect tmpfs mounted directly onto read-only system partition subpaths
            // (e.g. MoveCertificate / Magisk / KernelSU modules mounting tmpfs over
            // /system/etc/security/cacerts, surviving per-process overlay umount).
            for (String line : content.split("\\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) continue;
                int sep = trimmed.indexOf(" - ");
                if (sep <= 0) continue;
                String[] left = trimmed.substring(0, sep).split("\\s+");
                if (left.length < 5) continue;
                String mountPoint = left[4];
                if (!isReadOnlySystemSubpath(mountPoint)) continue;
                String[] right = trimmed.substring(sep + 3).trim().split("\\s+");
                if (right.length > 0 && "tmpfs".equalsIgnoreCase(right[0])) {
                    if (addUnique(evidence, "system_tmpfs_mount:" + mountPoint)) {
                        items.add(new EvidenceItem(
                                "system_tmpfs_mount",
                                EvidenceItem.SourceLayer.JAVA,
                                mountPoint,
                                "tmpfs",
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                    }
                }
            }
            return true;
        } catch (Exception e) {
            CLog.e("MountInfo check failed", e);
            return false;
        }
    }

    private static boolean isReadOnlySystemSubpath(String mountPoint) {
        return mountPoint.startsWith("/system/")
                || mountPoint.startsWith("/vendor/")
                || mountPoint.startsWith("/product/")
                || mountPoint.startsWith("/system_ext/")
                || mountPoint.startsWith("/odm/");
    }

    private boolean isBenignStockOemOverlayInMountInfo(String targetPath) {
        if (signals == null || targetPath == null || targetPath.isEmpty()) {
            return false;
        }
        if ("/system/bin".equals(targetPath)
                || "/system/lib".equals(targetPath)
                || "/system/lib64".equals(targetPath)
                || "/system/etc/security/cacerts".equals(targetPath)) {
            return false;
        }
        SignalResult<String> mountInfo = signals.getTextFile("/proc/self/mountinfo");
        if (mountInfo == null || !mountInfo.isSuccess() || mountInfo.getValue() == null) {
            return false;
        }
        return isBenignStockOemOverlay(mountInfo.getValue(), targetPath);
    }

    /**
     * Checks whether {@code targetPath} is backed by a visible, strictly read-only stock OEM
     * OverlayFS mount (e.g. HyperOS {@code /mi_ext/product/app:/product/app} or ColorOS
     * {@code /my_product/...}) with no {@code upperdir=}, no {@code rw}, and no root tokens.
     */
    static boolean isBenignStockOemOverlay(String mountInfoContent, String targetPath) {
        if (mountInfoContent == null || mountInfoContent.isEmpty() || targetPath == null) {
            return false;
        }
        String bestMountOpts = null;
        String bestSource = null;
        String bestSuperOpts = null;
        int bestLen = -1;

        for (String line : mountInfoContent.split("\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            int sep = trimmed.indexOf(" - ");
            if (sep <= 0) continue;
            String[] left = trimmed.substring(0, sep).split("\\s+");
            String[] right = trimmed.substring(sep + 3).trim().split("\\s+");
            if (left.length < 6 || right.length < 2) continue;
            String fs = right[0];
            if (!"overlay".equalsIgnoreCase(fs) && !"overlayfs".equalsIgnoreCase(fs)) continue;
            String mp = left[4];
            boolean covers = targetPath.equals(mp)
                    || (targetPath.startsWith(mp) && (mp.endsWith("/") || targetPath.charAt(mp.length()) == '/'));
            if (covers && mp.length() > bestLen) {
                bestLen = mp.length();
                bestMountOpts = left[5];
                bestSource = right[1];
                bestSuperOpts = right.length >= 3 ? right[2] : "";
            }
        }
        if (bestLen < 0) {
            return false;
        }
        if (hasExactRwOption(bestMountOpts) || hasExactRwOption(bestSuperOpts)) {
            return false;
        }
        String lowerSrc = bestSource.toLowerCase(Locale.ROOT);
        String lowerSuper = bestSuperOpts.toLowerCase(Locale.ROOT);
        if (containsSuspiciousOverlayMarker(lowerSrc) || containsSuspiciousOverlayMarker(lowerSuper)) {
            return false;
        }
        int keyPos = bestSuperOpts.indexOf("lowerdir=");
        if (keyPos < 0) {
            return false;
        }
        int valStart = keyPos + "lowerdir=".length();
        int comma = bestSuperOpts.indexOf(',', valStart);
        String dirs = comma < 0 ? bestSuperOpts.substring(valStart) : bestSuperOpts.substring(valStart, comma);
        if (dirs.isEmpty()) {
            return false;
        }
        String[] segments = dirs.split(":");
        if (segments.length == 0) {
            return false;
        }
        for (String seg : segments) {
            if (!isBenignOemLowerdirSegment(seg)) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasExactRwOption(String opts) {
        if (opts == null || opts.isEmpty()) return false;
        for (String tok : opts.split(",")) {
            if ("rw".equals(tok.trim())) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsSuspiciousOverlayMarker(String lower) {
        return lower.contains("magisk")
                || lower.contains("ksu")
                || lower.contains("kernelsu")
                || lower.contains("apatch")
                || lower.contains("susfs")
                || lower.contains("/data/")
                || lower.contains("/adb/")
                || lower.contains("debug_ramdisk")
                || lower.contains("upperdir=")
                || lower.contains("workdir=");
    }

    private static boolean isBenignOemLowerdirSegment(String seg) {
        if (seg == null || !seg.startsWith("/") || seg.contains("..")) {
            return false;
        }
        String[] prefixes = {
                "/mi_ext", "/my_product", "/my_region", "/my_carrier", "/my_company",
                "/my_heytap", "/my_stock", "/my_manifest", "/my_bigball", "/my_engineering",
                "/product", "/system_ext", "/vendor", "/odm", "/system",
                "/oem", "/prism", "/optics", "/preload"
        };
        for (String prefix : prefixes) {
            if (seg.equals(prefix) || seg.startsWith(prefix + "/")) {
                return true;
            }
        }
        return false;
    }

    private static void removeEvidenceByCode(List<EvidenceItem> items, String code) {
        items.removeIf(item -> item != null && code.equals(item.getCode()));
    }

    private static boolean addUnique(List<String> evidence, String signal) {
        if (!evidence.contains(signal)) {
            evidence.add(signal);
            return true;
        }
        return false;
    }

    private static String nonEmpty(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }
}
