package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Process;
import android.system.Os;
import android.system.StructStat;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.InstallTokenSanitizer;

import java.io.File;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * FAST-tier multi-instance, OEM dual-app & virtual container detector ({@code multi_instance}).
 *
 * <p>Deliberately avoids fragile hidden/non-SDK reflection (such as
 * {@code BaseDexClassLoader.pathList}) and instead combines five public/kernel signals:
 * <ol>
 *   <li>Canonical {@code filesDir}/{@code dataDir}/{@code sourceDir} path depth, owner package
 *       consistency, and {@code uid / 100000} classification separating normal primary user (0),
 *       legitimate Android multi-user / Work Profile (e.g. user 10), OEM dual-app spaces
 *       (e.g. user 999), and nested virtual containers (VirtualApp/ParallelSpace/BlackBox).</li>
 *   <li>{@code Process.myUid()} vs {@code Os.stat().st_uid} ownership parity on app data dirs.</li>
 *   <li>Multi-APK mapping check over {@code /proc/self/maps} after stripping 24-char Base64
 *       install tokens via {@link InstallTokenSanitizer}.</li>
 *   <li>Container native artifact detection in sanitized {@code /proc/self/maps}.</li>
 *   <li>Dynamic {@code Proxy$} Binder/service wrapper check on public framework handles.</li>
 * </ol>
 */
public class MultiInstanceDetector extends BaseDetector {
    private static final String FAMILY_VIRTUAL_CONTAINER = "virtual_container";
    private static final int PER_USER_RANGE = 100_000;

    /** Shared system/WebView/GMS APK package prefixes legitimately mapped into app processes. */
    private static final List<String> ALLOWED_SHARED_APK_PREFIXES = Arrays.asList(
            "com.google.android.webview",
            "com.android.webview",
            "com.google.android.trichromelibrary",
            "com.android.chrome",
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.ext.shared",
            "com.huawei.webview",
            "com.huawei.hwid",
            "com.heytap.webview",
            "com.xiaomi.webview",
            "com.sec.android.app.chromecustomizations",
            "com.android.vending"
    );

    /** Known virtual-container path segments or engine markers (checked on sanitized paths). */
    private static final List<String> CONTAINER_PATH_MARKERS = Arrays.asList(
            "/virtual/",
            "/parallel/",
            "/blackbox/",
            "/dkplugin/",
            "/vapp/",
            "io.va.exposed",
            "com.lbe.parallel",
            "top.niunaijun.blackbox",
            "com.bly.dkplat",
            "com.excelliance.dualaid",
            "com.ludashi.dualspace",
            "com.polestar.super.clone",
            "com.qihoo.magic",
            "com.x8zs.sandbox"
    );

    /** Known virtual-container native engine libraries in /proc/self/maps. */
    private static final List<String> CONTAINER_MAP_LIBRARIES = Arrays.asList(
            "libva++.so",
            "libva64.so",
            "libva.so",
            "libblackbox.so",
            "libdkhelper.so",
            "libdualspace.so",
            "libparallel.so",
            "libvirtualapp.so"
    );

    private final SignalSnapshot signals;
    private final MultiInstanceEnvironment env;

    public MultiInstanceDetector(Context context, SignalSnapshot signals) {
        this(context, signals, null);
    }

    /** Internal test seam for deterministic pure-JVM unit tests (not part of public SDK contract). */
    public static MultiInstanceDetector createForTest(Context context,
                                                      SignalSnapshot signals,
                                                      MultiInstanceEnvironment env) {
        return new MultiInstanceDetector(context, signals, env);
    }

    MultiInstanceDetector(Context context,
                          SignalSnapshot signals,
                          MultiInstanceEnvironment env) {
        super(context);
        this.signals = signals != null ? signals : new SignalSnapshot(context);
        this.env = env != null ? env : new AndroidMultiInstanceEnvironment(this.context);
    }

    @Override
    public String getName() {
        return "multi_instance";
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.FAST;
    }

    @Override
    public boolean hasPostponedProbes() {
        return true;
    }

    /**
     * Stage 3 postponed pass consuming native {@code sacrificial_syscall_pack} mismatches
     * executed inside {@code disposable_child}. Any confirmed libc-vs-raw syscall interception
     * elevates {@code multi_instance} to actionable MEDIUM/5 under {@code virtual_container}.
     */
    @Override
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        DetectionResult base = priorResult != null ? priorResult : call();
        if (base == null) {
            return null;
        }
        SignalResult<String> traps = signals.getVirtualizationTraps(true);
        if (traps == null || !traps.isSuccess() || traps.getValue() == null) {
            return base;
        }
        NativePayloadCodec.DecodedPayload decoded =
                NativePayloadCodec.decodePayload(traps.getValue());
        if (!decoded.isOk()) {
            return base;
        }

        List<String> mergedDetails = new ArrayList<>(base.getDetails());
        Map<String, EvidenceItem> evidenceByKey = new LinkedHashMap<>();
        for (EvidenceItem existing : base.getEvidenceItems()) {
            String key = existing.getCode() + "|" + existing.getLocation();
            EvidenceItem prev = evidenceByKey.get(key);
            evidenceByKey.put(key, prev == null ? existing : prev.mergeWith(existing));
        }

        boolean foundMismatch = false;
        for (Map<String, String> rec : decoded.getRecords()) {
            if (!"sacrificial_syscall_mismatch".equals(rec.get("kind"))) {
                continue;
            }
            String syscall = rec.get("syscall");
            if (syscall == null || syscall.isBlank()) {
                syscall = "unknown";
            }
            String mismatches = rec.get("mismatches");
            String libcErrno = rec.get("libc_errno");
            String rawErrno = rec.get("raw_errno");
            String token = "sacrificial_syscall_mismatch:" + syscall
                    + (mismatches != null && !mismatches.isBlank() ? ":mismatches=" + mismatches : "");
            String rawVal = "mismatches=" + (mismatches == null ? "1" : mismatches)
                    + ",libc_errno=" + (libcErrno == null ? "0" : libcErrno)
                    + ",raw_errno=" + (rawErrno == null ? "0" : rawErrno);
            addFinding(mergedDetails, evidenceByKey, token, "sacrificial_syscall_mismatch",
                    EvidenceItem.SourceLayer.NATIVE, "syscall:" + syscall,
                    rawVal, EvidenceItem.Rank.STRONG);
            foundMismatch = true;
        }

        if (!foundMismatch) {
            return base;
        }

        RiskLevel targetLevel = base.getRiskLevel().getValue() >= RiskLevel.MEDIUM.getValue()
                ? base.getRiskLevel() : RiskLevel.MEDIUM;
        DetectionStatus targetStatus = targetLevel.getValue() >= RiskLevel.HIGH.getValue()
                ? DetectionStatus.DANGER : DetectionStatus.WARNING;
        int targetScore = Math.max(base.getScore(), 5);
        int attempted = base.getChecksAttempted() + 1;
        int succeeded = base.getChecksSucceeded() + 1;
        int failed = base.getChecksFailed();
        DetectionExecutionStatus execStatus = failed > 0
                ? DetectionExecutionStatus.PARTIAL
                : DetectionExecutionStatus.RISK;

        return new DetectionResult(
                getName(),
                targetLevel,
                targetStatus,
                targetScore,
                Math.max(base.getMaxScore(), 10),
                false,
                execStatus,
                attempted,
                succeeded,
                failed,
                base.getFailureReasons(),
                mergedDetails,
                String.join("; ", mergedDetails)
        ).withEvidenceItems(new ArrayList<>(evidenceByKey.values()))
                .withScanTier(getScanTier());
    }

    @Override
    protected DetectionResult detect() {
        CheckCoverage coverage = new CheckCoverage();
        List<String> details = new ArrayList<>();
        Map<String, EvidenceItem> evidenceByKey = new LinkedHashMap<>();

        boolean hasStrongContainer = false;
        boolean hasOemDualApp = false;

        String packageName = null;
        int myUid = -1;
        String filesDir = null;
        String dataDir = null;
        String sourceDir = null;

        try {
            packageName = env.getPackageName();
            myUid = env.getMyUid();
            filesDir = env.getFilesDirPath();
            dataDir = env.getDataDirPath();
            sourceDir = env.getSourceDirPath();
            if (packageName != null && !packageName.isBlank()) {
                coverage.success();
            } else {
                coverage.failure("package_name_unavailable");
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("env_info_error:" + e.getClass().getSimpleName());
        }

        int userId = myUid >= 0 ? (myUid / PER_USER_RANGE) : -1;

        // 1. Directory canonical depth, owner package consistency, and uid/100000 classification
        if (packageName != null && !packageName.isBlank()) {
            boolean dirChecked = false;
            if (filesDir != null && !filesDir.isBlank()) {
                dirChecked = true;
                PathAuditResult audit = auditAppDataPath(filesDir, packageName, userId, true);
                if (audit.nestedContainer) {
                    hasStrongContainer = true;
                    String token = "nested_container_path:" + audit.sanitizedPath;
                    addFinding(details, evidenceByKey, token, "nested_container_path",
                            EvidenceItem.SourceLayer.JAVA, audit.sanitizedPath,
                            audit.reason, EvidenceItem.Rank.STRONG);
                }
                if (audit.userIdMismatch) {
                    hasStrongContainer = true;
                    String token = "user_id_path_mismatch:uid=" + userId
                            + ",path=" + audit.pathUserId;
                    addFinding(details, evidenceByKey, token, "user_id_path_mismatch",
                            EvidenceItem.SourceLayer.JAVA, audit.sanitizedPath,
                            "uid_user=" + userId + ",path_user=" + audit.pathUserId,
                            EvidenceItem.Rank.STRONG);
                }
            }
            if (dataDir != null && !dataDir.isBlank()) {
                dirChecked = true;
                PathAuditResult audit = auditAppDataPath(dataDir, packageName, userId, false);
                if (audit.nestedContainer) {
                    hasStrongContainer = true;
                    String token = "nested_container_path:" + audit.sanitizedPath;
                    addFinding(details, evidenceByKey, token, "nested_container_path",
                            EvidenceItem.SourceLayer.JAVA, audit.sanitizedPath,
                            audit.reason, EvidenceItem.Rank.STRONG);
                }
                if (audit.userIdMismatch) {
                    hasStrongContainer = true;
                    String token = "user_id_path_mismatch:uid=" + userId
                            + ",path=" + audit.pathUserId;
                    addFinding(details, evidenceByKey, token, "user_id_path_mismatch",
                            EvidenceItem.SourceLayer.JAVA, audit.sanitizedPath,
                            "uid_user=" + userId + ",path_user=" + audit.pathUserId,
                            EvidenceItem.Rank.STRONG);
                }
            }
            if (sourceDir != null && !sourceDir.isBlank()) {
                dirChecked = true;
                String sanitizedSource = InstallTokenSanitizer.stripInstallTokens(sourceDir);
                if (isContainerHostedSourceDir(sanitizedSource, packageName)) {
                    hasStrongContainer = true;
                    String token = "container_source_dir:" + sanitizedSource;
                    addFinding(details, evidenceByKey, token, "container_source_dir",
                            EvidenceItem.SourceLayer.JAVA, sanitizedSource,
                            "apk_outside_standard_install_root", EvidenceItem.Rank.STRONG);
                }
            }
            if (dirChecked) {
                coverage.success();
            }

            // Classify OEM dual-app user IDs (e.g. Xiaomi/OPPO/vivo/OnePlus user 999,
            // Samsung Dual Messenger user 95, Huawei/Honor App Twin 128..150, generic >= 900).
            // Normal primary user (0) and standard Android multi-user / Work Profile (10..89)
            // are intentionally NOT flagged when paths & UIDs match cleanly.
            if (isOemDualAppUserId(userId)) {
                hasOemDualApp = true;
                String token = "oem_dual_app:user_" + userId;
                addFinding(details, evidenceByKey, token, "oem_dual_app",
                        EvidenceItem.SourceLayer.JAVA, "user:" + userId,
                        "uid=" + myUid, EvidenceItem.Rank.WEAK);
            }
        }

        // 2. Process.myUid() vs Os.stat(dir).st_uid ownership parity
        if (myUid >= 0) {
            String statTarget = (filesDir != null && !filesDir.isBlank()) ? filesDir : dataDir;
            if (statTarget != null && !statTarget.isBlank()) {
                try {
                    int statUid = env.statUid(statTarget);
                    if (statUid >= 0) {
                        coverage.success();
                        if (statUid != myUid) {
                            hasStrongContainer = true;
                            String sanitized = InstallTokenSanitizer.stripInstallTokens(statTarget);
                            String token = "dir_uid_mismatch:my=" + myUid + ",stat=" + statUid;
                            addFinding(details, evidenceByKey, token, "dir_uid_mismatch",
                                    EvidenceItem.SourceLayer.NATIVE, sanitized,
                                    "my_uid=" + myUid + ",st_uid=" + statUid,
                                    EvidenceItem.Rank.STRONG);
                        }
                    }
                } catch (Exception | LinkageError | OutOfMemoryError e) {
                    coverage.failure("stat_uid_error:" + e.getClass().getSimpleName());
                }
            }
        }

        // 3. /proc/self/maps multi-APK & container artifact scan (token-sanitized)
        try {
            SignalResult<List<String>> mapsResult = signals.getSelfMaps();
            if (mapsResult != null && mapsResult.isSuccess() && mapsResult.getValue() != null) {
                coverage.success();
                Set<String> foreignApkPackages = new LinkedHashSet<>();
                Set<String> containerArtifacts = new LinkedHashSet<>();
                for (String rawLine : mapsResult.getValue()) {
                    String mapPath = extractMapsPath(rawLine);
                    if (mapPath == null || mapPath.isEmpty()) {
                        continue;
                    }
                    String sanitized = InstallTokenSanitizer.stripInstallTokens(mapPath);
                    String lowerSanitized = sanitized.toLowerCase(Locale.ROOT);

                    // Check for container engine libraries or host container paths
                    for (String lib : CONTAINER_MAP_LIBRARIES) {
                        if (lowerSanitized.endsWith("/" + lib) || lowerSanitized.equals(lib)) {
                            containerArtifacts.add(lib);
                        }
                    }
                    for (String marker : CONTAINER_PATH_MARKERS) {
                        if (lowerSanitized.contains(marker)) {
                            // Ignore self if somehow marker matched package name
                            if (packageName == null
                                    || !packageName.toLowerCase(Locale.ROOT).contains(marker)) {
                                containerArtifacts.add(marker);
                            }
                        }
                    }

                    // Check for foreign application APKs mapped into this process
                    if (lowerSanitized.endsWith(".apk")) {
                        String mappedPkg = InstallTokenSanitizer.extractDataAppApkPackage(sanitized);
                        if (mappedPkg == null) {
                            mappedPkg = InstallTokenSanitizer.extractDataOwnerPackage(sanitized);
                        }
                        if (mappedPkg != null
                                && packageName != null
                                && !mappedPkg.equals(packageName)
                                && !isAllowedSharedApk(mappedPkg)) {
                            foreignApkPackages.add(mappedPkg);
                        }
                    }
                }

                for (String foreignPkg : foreignApkPackages) {
                    hasStrongContainer = true;
                    String token = "multi_apk_maps:" + foreignPkg;
                    addFinding(details, evidenceByKey, token, "multi_apk_maps",
                            EvidenceItem.SourceLayer.NATIVE, "/proc/self/maps:" + foreignPkg,
                            "foreign_apk_mapped=" + foreignPkg, EvidenceItem.Rank.STRONG);
                }
                for (String artifact : containerArtifacts) {
                    hasStrongContainer = true;
                    String token = "container_maps_artifact:" + artifact;
                    addFinding(details, evidenceByKey, token, "container_maps_artifact",
                            EvidenceItem.SourceLayer.NATIVE, "/proc/self/maps",
                            "artifact=" + artifact, EvidenceItem.Rank.STRONG);
                }
            } else if (mapsResult != null
                    && mapsResult.getStatus() == SignalResult.Status.ERROR) {
                coverage.failure("maps_error:" + mapsResult.getFailureReason());
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("maps_scan_error:" + e.getClass().getSimpleName());
        }

        // 4. Dynamic Proxy$ Binder / service wrapper check (public APIs only, zero hidden reflection)
        try {
            Map<String, String> proxyHits = env.inspectDynamicBinderProxies();
            coverage.success();
            if (proxyHits != null) {
                for (Map.Entry<String, String> entry : proxyHits.entrySet()) {
                    String service = entry.getKey();
                    String proxyClass = entry.getValue();
                    if (service == null || proxyClass == null || proxyClass.isBlank()) {
                        continue;
                    }
                    hasStrongContainer = true;
                    String token = "binder_dynamic_proxy:" + service + ":" + proxyClass;
                    addFinding(details, evidenceByKey, token, "binder_dynamic_proxy",
                            EvidenceItem.SourceLayer.JAVA, "service:" + service,
                            proxyClass, EvidenceItem.Rank.STRONG);
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("binder_proxy_error:" + e.getClass().getSimpleName());
        }

        RiskLevel level;
        DetectionStatus status;
        int score;
        boolean informational;
        if (hasStrongContainer) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = 5;
            informational = false;
        } else if (hasOemDualApp) {
            level = RiskLevel.LOW;
            status = DetectionStatus.WARNING;
            score = 2;
            informational = true;
        } else {
            level = RiskLevel.SAFE;
            status = DetectionStatus.NORMAL;
            score = 0;
            informational = false;
        }

        String evidence = details.isEmpty() ? "clean" : String.join("; ", details);
        DetectionResult result = result(
                level,
                status,
                score,
                10,
                informational,
                details,
                evidence,
                coverage
        );

        if (!evidenceByKey.isEmpty()) {
            result = result.withEvidenceItems(new ArrayList<>(evidenceByKey.values()));
        }
        return result;
    }

    static boolean isOemDualAppUserId(int userId) {
        // 999: MIUI/HyperOS, OPPO/OnePlus/realme, vivo dual-app spaces; >=900 OEM clone spaces;
        // 95: Samsung Dual Messenger; 128..150: Huawei/Honor App Twin.
        return userId >= 900 || userId == 95 || (userId >= 128 && userId <= 150);
    }

    static boolean isDynamicProxyClassName(String className) {
        if (className == null || className.isEmpty()) {
            return false;
        }
        // Standard Android Binder proxy classes end with "$Stub$Proxy" and are legitimate.
        if (className.endsWith("$Stub$Proxy")) {
            return false;
        }
        return className.contains("$Proxy")
                || className.contains("Proxy$")
                || className.startsWith("jdk.proxy");
    }

    private static boolean isAllowedSharedApk(String packageName) {
        String lower = packageName.toLowerCase(Locale.ROOT);
        for (String prefix : ALLOWED_SHARED_APK_PREFIXES) {
            if (lower.equals(prefix) || lower.startsWith(prefix + "_")) {
                return true;
            }
        }
        return false;
    }

    private static PathAuditResult auditAppDataPath(String rawPath,
                                                    String packageName,
                                                    int uidUserId,
                                                    boolean expectFilesSuffix) {
        String normalized = normalizePath(rawPath);
        String sanitized = InstallTokenSanitizer.stripInstallTokens(normalized);
        String lower = sanitized.toLowerCase(Locale.ROOT);

        // 1. Check explicit nested container markers or duplicated /data/user/ or /data/data/
        for (String marker : CONTAINER_PATH_MARKERS) {
            if (lower.contains(marker)
                    && !packageName.toLowerCase(Locale.ROOT).contains(marker)) {
                return PathAuditResult.nested(sanitized, "marker:" + marker);
            }
        }
        if (countOccurrences(lower, "/data/user/") > 1
                || countOccurrences(lower, "/data/user_de/") > 1
                || countOccurrences(lower, "/data/data/") > 1
                || (lower.contains("/data/user/") && lower.contains("/data/data/"))) {
            return PathAuditResult.nested(sanitized, "duplicated_data_root");
        }

        String[] parts = sanitized.split("/");
        // Canonical forms:
        //   /data/user/<uId>/<pkg>[/files]       -> length 5 (or 6 with /files)
        //   /data/user_de/<uId>/<pkg>[/files]    -> length 5 (or 6 with /files)
        //   /data/data/<pkg>[/files]             -> length 4 (or 5 with /files)
        if (parts.length >= 5 && "data".equals(parts[1])
                && ("user".equals(parts[2]) || "user_de".equals(parts[2]))) {
            int expectedDepth = expectFilesSuffix ? 6 : 5;
            Integer parsedPathUser = parseNonNegativeInt(parts[3]);
            String ownerPkg = parts[4];
            if (!packageName.equals(ownerPkg)) {
                return PathAuditResult.nested(sanitized, "owner_pkg_mismatch:" + ownerPkg);
            }
            if (parts.length > expectedDepth) {
                return PathAuditResult.nested(sanitized, "excess_depth:" + parts.length);
            }
            if (expectFilesSuffix && (parts.length != 6 || !"files".equals(parts[5]))) {
                return PathAuditResult.nested(sanitized, "unexpected_files_dir_layout");
            }
            if (parsedPathUser != null && uidUserId >= 0 && parsedPathUser != uidUserId) {
                return PathAuditResult.userMismatch(sanitized, parsedPathUser);
            }
            return PathAuditResult.clean(sanitized);
        }

        if (parts.length >= 4 && "data".equals(parts[1]) && "data".equals(parts[2])) {
            int expectedDepth = expectFilesSuffix ? 5 : 4;
            String ownerPkg = parts[3];
            if (!packageName.equals(ownerPkg)) {
                return PathAuditResult.nested(sanitized, "owner_pkg_mismatch:" + ownerPkg);
            }
            if (parts.length > expectedDepth) {
                return PathAuditResult.nested(sanitized, "excess_depth:" + parts.length);
            }
            if (expectFilesSuffix && (parts.length != 5 || !"files".equals(parts[4]))) {
                return PathAuditResult.nested(sanitized, "unexpected_files_dir_layout");
            }
            return PathAuditResult.clean(sanitized);
        }

        // Any other unexpected root (e.g. /mnt/expand/<uuid>/user/<uId>/<pkg>[/files] is valid
        // adoptable storage; allow it only when depth & owner match).
        if (parts.length >= 7 && "mnt".equals(parts[1]) && "expand".equals(parts[2])
                && ("user".equals(parts[4]) || "user_de".equals(parts[4]))) {
            int expectedDepth = expectFilesSuffix ? 8 : 7;
            Integer parsedPathUser = parseNonNegativeInt(parts[5]);
            String ownerPkg = parts[6];
            if (!packageName.equals(ownerPkg) || parts.length > expectedDepth) {
                return PathAuditResult.nested(sanitized, "expand_layout_anomaly");
            }
            if (parsedPathUser != null && uidUserId >= 0 && parsedPathUser != uidUserId) {
                return PathAuditResult.userMismatch(sanitized, parsedPathUser);
            }
            return PathAuditResult.clean(sanitized);
        }

        return PathAuditResult.nested(sanitized, "non_canonical_root");
    }

    private static boolean isContainerHostedSourceDir(String sanitizedSource, String packageName) {
        String lower = sanitizedSource.toLowerCase(Locale.ROOT);
        for (String marker : CONTAINER_PATH_MARKERS) {
            if (lower.contains(marker)
                    && !packageName.toLowerCase(Locale.ROOT).contains(marker)) {
                return true;
            }
        }
        // Standard APKs live in /data/app/..., /mnt/expand/.../app/..., /system/...,
        // /system_ext/..., /product/..., /vendor/..., /odm/..., /oem/..., /apex/...
        if (lower.startsWith("/data/user/") || lower.startsWith("/data/user_de/")
                || lower.startsWith("/data/data/")) {
            return true;
        }
        if (lower.startsWith("/data/app/")) {
            String apkPkg = InstallTokenSanitizer.extractDataAppApkPackage(sanitizedSource);
            return apkPkg != null && !apkPkg.equals(packageName);
        }
        return false;
    }

    private static String extractMapsPath(String mapsLine) {
        if (mapsLine == null || mapsLine.isEmpty()) {
            return null;
        }
        int slash = mapsLine.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String path = mapsLine.substring(slash).trim();
        int deletedIdx = path.indexOf(" (deleted)");
        if (deletedIdx > 0) {
            path = path.substring(0, deletedIdx).trim();
        }
        return path;
    }

    private static String normalizePath(String path) {
        String trimmed = path.trim();
        while (trimmed.length() > 1 && trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }

    private static Integer parseNonNegativeInt(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            int parsed = Integer.parseInt(value);
            return parsed >= 0 ? parsed : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void addFinding(List<String> details,
                                   Map<String, EvidenceItem> evidenceByKey,
                                   String detailToken,
                                   String code,
                                   EvidenceItem.SourceLayer source,
                                   String location,
                                   String rawValue,
                                   EvidenceItem.Rank rank) {
        if (!details.contains(detailToken)) {
            details.add(detailToken);
        }
        String key = code + "|" + (location == null ? "" : location);
        EvidenceItem item = new EvidenceItem(
                code, source, location, rawValue, FAMILY_VIRTUAL_CONTAINER, rank);
        EvidenceItem existing = evidenceByKey.get(key);
        evidenceByKey.put(key, existing == null ? item : existing.mergeWith(item));
    }

    private static final class PathAuditResult {
        final String sanitizedPath;
        final boolean nestedContainer;
        final boolean userIdMismatch;
        final int pathUserId;
        final String reason;

        private PathAuditResult(String sanitizedPath,
                                boolean nestedContainer,
                                boolean userIdMismatch,
                                int pathUserId,
                                String reason) {
            this.sanitizedPath = sanitizedPath;
            this.nestedContainer = nestedContainer;
            this.userIdMismatch = userIdMismatch;
            this.pathUserId = pathUserId;
            this.reason = reason;
        }

        static PathAuditResult clean(String sanitizedPath) {
            return new PathAuditResult(sanitizedPath, false, false, -1, "");
        }

        static PathAuditResult nested(String sanitizedPath, String reason) {
            return new PathAuditResult(sanitizedPath, true, false, -1, reason);
        }

        static PathAuditResult userMismatch(String sanitizedPath, int pathUserId) {
            return new PathAuditResult(sanitizedPath, false, true, pathUserId, "user_id_mismatch");
        }
    }

    /** Environment abstraction for pure-JVM testability without hidden reflection. */
    public interface MultiInstanceEnvironment {
        String getPackageName();
        int getMyUid();
        String getFilesDirPath();
        String getDataDirPath();
        String getSourceDirPath();
        int statUid(String path);
        Map<String, String> inspectDynamicBinderProxies();
    }

    private static final class AndroidMultiInstanceEnvironment implements MultiInstanceEnvironment {
        private final Context context;

        AndroidMultiInstanceEnvironment(Context context) {
            this.context = context;
        }

        @Override
        public String getPackageName() {
            return context == null ? null : context.getPackageName();
        }

        @Override
        public int getMyUid() {
            try {
                return Process.myUid();
            } catch (Exception | LinkageError e) {
                return -1;
            }
        }

        @Override
        public String getFilesDirPath() {
            if (context == null) return null;
            File filesDir = context.getFilesDir();
            return filesDir == null ? null : filesDir.getAbsolutePath();
        }

        @Override
        public String getDataDirPath() {
            if (context == null) return null;
            File dataDir = context.getDataDir();
            if (dataDir != null) {
                return dataDir.getAbsolutePath();
            }
            ApplicationInfo info = context.getApplicationInfo();
            return info == null ? null : info.dataDir;
        }

        @Override
        public String getSourceDirPath() {
            if (context == null) return null;
            ApplicationInfo info = context.getApplicationInfo();
            return info == null ? null : info.sourceDir;
        }

        @Override
        public int statUid(String path) {
            if (path == null || path.isBlank()) {
                return -1;
            }
            try {
                StructStat st = Os.stat(path);
                return st == null ? -1 : st.st_uid;
            } catch (Exception | LinkageError e) {
                return -1;
            }
        }

        @Override
        public Map<String, String> inspectDynamicBinderProxies() {
            if (context == null) {
                return Collections.emptyMap();
            }
            Map<String, String> hits = new LinkedHashMap<>();
            checkObjectProxy("PackageManager", safeGet(() -> context.getPackageManager()), hits);
            checkObjectProxy("ActivityManager",
                    safeGet(() -> context.getSystemService(Context.ACTIVITY_SERVICE)), hits);
            checkObjectProxy("ContentResolver", safeGet(context::getContentResolver), hits);
            return hits;
        }

        private interface CheckedSupplier {
            Object get() throws Exception;
        }

        private static Object safeGet(CheckedSupplier supplier) {
            try {
                return supplier.get();
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return null;
            }
        }

        private static void checkObjectProxy(String name, Object obj, Map<String, String> hits) {
            if (obj == null) {
                return;
            }
            Class<?> cls = obj.getClass();
            String className = cls.getName();
            if (Proxy.isProxyClass(cls) || isDynamicProxyClassName(className)) {
                hits.put(name, className);
            }
        }
    }
}
