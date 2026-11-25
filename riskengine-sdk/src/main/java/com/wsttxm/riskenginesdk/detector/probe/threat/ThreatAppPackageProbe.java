package com.wsttxm.riskenginesdk.detector.probe.threat;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import com.wsttxm.riskenginesdk.ThreatAppPolicy;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.xmlpull.v1.XmlPullParser;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Package-visibility-compliant probe inspecting targeted apps for:
 * <ol>
 *   <li>Full v2/v3/v3.1 signing certificate lineage ({@code apkContentsSigners} +
 *       {@code signingCertificateHistory}) against {@link ThreatAppSignatureLibrary} and
 *       {@link ThreatAppPolicy#getAdditionalCertSha256s()}.</li>
 *   <li>Extracted daemon binaries in {@code ApplicationInfo.nativeLibraryDir}
 *       ({@code libksud.so}, {@code libapd.so}, {@code libmagisk.so}, etc.) via {@code Os.stat}
 *       where {@code ENOENT}/{@code ENOTDIR} is clean absence and non-ENOENT errors are recorded
 *       as unobserved (never a positive threat).</li>
 *   <li>{@code android:zygotePreloadName} via public {@link PackageManager#getResourcesForApplication}
 *       binary manifest XML inspection (zero hidden-API reflection, zero 3rd-party deps).</li>
 *   <li>Host-defined {@link ThreatAppPolicy.PermissionComboRule} matching against
 *       {@code PackageInfo.requestedPermissions}.</li>
 * </ol>
 *
 * <p>Never invokes {@code getInstalledPackages()} to avoid unauthorized full app enumeration;
 * inspects only curated {@code <queries>} packages plus explicit host policy packages.
 */
public final class ThreatAppPackageProbe {

    public static final String FAMILY_ROOT_FW = "root_fw";
    public static final String FAMILY_HMA_HIDING = "hma_hiding";
    public static final String FAMILY_THREAT_APP = "threat_app";

    private static final String ANDROID_XML_NS = "http://schemas.android.com/apk/res/android";
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    /** Snapshot of one installed app's observable metadata for pure-Java inspection and tests. */
    public static final class InspectedApp {
        private final String packageName;
        private final List<String> certSha256Lineage;
        private final String nativeLibraryDir;
        private final Set<String> requestedPermissions;
        private final ApplicationInfo applicationInfo;

        public InspectedApp(String packageName,
                            Collection<String> certSha256Lineage,
                            String nativeLibraryDir,
                            Collection<String> requestedPermissions,
                            ApplicationInfo applicationInfo) {
            this.packageName = packageName == null ? "" : packageName;
            List<String> certs = new ArrayList<>();
            if (certSha256Lineage != null) {
                for (String c : certSha256Lineage) {
                    if (c != null && !c.isBlank()) {
                        certs.add(c.trim().toLowerCase(Locale.US));
                    }
                }
            }
            this.certSha256Lineage = Collections.unmodifiableList(certs);
            this.nativeLibraryDir = nativeLibraryDir;
            Set<String> perms = new LinkedHashSet<>();
            if (requestedPermissions != null) {
                for (String p : requestedPermissions) {
                    if (p != null && !p.isBlank()) {
                        perms.add(p.trim());
                    }
                }
            }
            this.requestedPermissions = Collections.unmodifiableSet(perms);
            this.applicationInfo = applicationInfo;
        }

        public String getPackageName() {
            return packageName;
        }

        public List<String> getCertSha256Lineage() {
            return certSha256Lineage;
        }

        public String getNativeLibraryDir() {
            return nativeLibraryDir;
        }

        public Set<String> getRequestedPermissions() {
            return requestedPermissions;
        }

        public ApplicationInfo getApplicationInfo() {
            return applicationInfo;
        }
    }

    /** Injectable adapter for package queries (supports deterministic pure-JVM unit tests). */
    public interface PackageQueryAdapter {
        /** Returns {@link InspectedApp} or {@code null} if not installed / not visible. */
        InspectedApp queryPackage(String packageName, boolean includePermissions);
    }

    /** Outcome of inspecting one {@code nativeLibraryDir}. */
    public static final class PayloadScanResult {
        private final boolean observable;
        private final Set<String> foundPayloads;
        private final String failureReason;

        public static PayloadScanResult observed(Set<String> foundPayloads) {
            return new PayloadScanResult(true, foundPayloads, null);
        }

        public static PayloadScanResult failed(String reason) {
            return new PayloadScanResult(false, Collections.emptySet(), reason);
        }

        private PayloadScanResult(boolean observable,
                                  Set<String> foundPayloads,
                                  String failureReason) {
            this.observable = observable;
            this.foundPayloads = foundPayloads == null || foundPayloads.isEmpty()
                    ? Collections.emptySet()
                    : Collections.unmodifiableSet(new LinkedHashSet<>(foundPayloads));
            this.failureReason = failureReason;
        }

        public boolean isObservable() {
            return observable;
        }

        public Set<String> getFoundPayloads() {
            return foundPayloads;
        }

        public String getFailureReason() {
            return failureReason;
        }
    }

    /** Injectable adapter for {@code nativeLibraryDir} stat checks. */
    public interface NativePayloadReader {
        PayloadScanResult read(String nativeLibraryDir, Set<String> payloadNames);
    }

    /** Injectable adapter for reading {@code android:zygotePreloadName}. */
    public interface ZygotePreloadReader {
        String read(InspectedApp app);
    }

    /** Aggregated findings from one {@link ThreatAppPackageProbe} run. */
    public static final class ProbeOutcome {
        private final List<EvidenceItem> evidenceItems;
        private final List<String> details;
        private final int inspectedCount;
        private final int installedCount;
        private final int payloadDirectoryFailures;
        private final boolean rootManagerDetected;
        private final boolean appHiderDetected;
        private final boolean threatToolDetected;

        ProbeOutcome(List<EvidenceItem> evidenceItems,
                     List<String> details,
                     int inspectedCount,
                     int installedCount,
                     int payloadDirectoryFailures,
                     boolean rootManagerDetected,
                     boolean appHiderDetected,
                     boolean threatToolDetected) {
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.details = Collections.unmodifiableList(details);
            this.inspectedCount = inspectedCount;
            this.installedCount = installedCount;
            this.payloadDirectoryFailures = payloadDirectoryFailures;
            this.rootManagerDetected = rootManagerDetected;
            this.appHiderDetected = appHiderDetected;
            this.threatToolDetected = threatToolDetected;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public List<String> getDetails() {
            return details;
        }

        public int getInspectedCount() {
            return inspectedCount;
        }

        public int getInstalledCount() {
            return installedCount;
        }

        public int getPayloadDirectoryFailures() {
            return payloadDirectoryFailures;
        }

        public boolean isRootManagerDetected() {
            return rootManagerDetected;
        }

        public boolean isAppHiderDetected() {
            return appHiderDetected;
        }

        public boolean isThreatToolDetected() {
            return threatToolDetected;
        }

        public boolean hasFindings() {
            return !evidenceItems.isEmpty();
        }
    }

    private final PackageQueryAdapter packageQueryAdapter;
    private final NativePayloadReader nativePayloadReader;
    private final ZygotePreloadReader zygotePreloadReader;

    public ThreatAppPackageProbe(Context context) {
        this(defaultPackageQueryAdapter(context),
                DEFAULT_NATIVE_PAYLOAD_READER,
                defaultZygotePreloadReader(context));
    }

    public ThreatAppPackageProbe(PackageQueryAdapter packageQueryAdapter,
                                 NativePayloadReader nativePayloadReader,
                                 ZygotePreloadReader zygotePreloadReader) {
        this.packageQueryAdapter = packageQueryAdapter;
        this.nativePayloadReader = nativePayloadReader != null
                ? nativePayloadReader
                : DEFAULT_NATIVE_PAYLOAD_READER;
        this.zygotePreloadReader = zygotePreloadReader;
    }

    /**
     * Runs targeted package, certificate lineage, native payload, zygotePreloadName, and
     * permission-combo inspection according to {@code policy}.
     */
    public ProbeOutcome probe(ThreatAppPolicy policy) {
        ThreatAppPolicy effectivePolicy = policy != null ? policy : ThreatAppPolicy.DEFAULT;
        Set<String> targetPackages = buildTargetPackages(effectivePolicy);
        return probePackages(targetPackages, effectivePolicy);
    }

    /**
     * Inspects an explicit collection of target package names (supports inspecting renamed
     * candidate packages supplied by callers or unit tests without full app enumeration).
     */
    public ProbeOutcome probePackages(Collection<String> targetPackages, ThreatAppPolicy policy) {
        ThreatAppPolicy effectivePolicy = policy != null ? policy : ThreatAppPolicy.DEFAULT;
        List<EvidenceItem> items = new ArrayList<>();
        List<String> details = new ArrayList<>();
        Map<String, PayloadScanResult> payloadCache = new LinkedHashMap<>();

        if (packageQueryAdapter == null || targetPackages == null || targetPackages.isEmpty()) {
            return new ProbeOutcome(items, details, 0, 0, 0, false, false, false);
        }

        boolean needPermissions = !effectivePolicy.getDangerousPermissionCombos().isEmpty();
        int inspected = 0;
        int installed = 0;
        int payloadFailures = 0;
        boolean rootFound = false;
        boolean hiderFound = false;
        boolean toolFound = false;

        Set<String> uniqueTargets = new LinkedHashSet<>();
        for (String pkg : targetPackages) {
            if (pkg != null && !pkg.isBlank()) {
                uniqueTargets.add(pkg.trim());
            }
        }

        for (String pkg : uniqueTargets) {
            inspected++;
            InspectedApp app;
            try {
                app = packageQueryAdapter.queryPackage(pkg, needPermissions);
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                continue;
            }
            if (app == null) {
                continue;
            }
            installed++;

            String actualPkg = (app.getPackageName() != null && !app.getPackageName().isBlank())
                    ? app.getPackageName()
                    : pkg;

            boolean matchedByStrongIdentity = false;

            // 1. Full v2/v3/v3.1 certificate lineage verification
            for (String sha256 : app.getCertSha256Lineage()) {
                if (effectivePolicy.isEnableBuiltInCatalog()) {
                    ThreatAppSignatureLibrary.ToolSignature sig =
                            ThreatAppSignatureLibrary.matchByCertSha256(sha256);
                    if (sig != null) {
                        matchedByStrongIdentity = true;
                        String family = familyFor(sig.getCategory());
                        EvidenceItem.Rank rank = sig.isRootManager()
                                ? EvidenceItem.Rank.STRONG
                                : EvidenceItem.Rank.MEDIUM;
                        if (sig.isRootManager()) {
                            rootFound = true;
                        } else if (sig.getCategory() == ThreatAppSignatureLibrary.Category.APP_HIDER) {
                            hiderFound = true;
                        } else {
                            toolFound = true;
                        }
                        details.add("threat_app_cert:" + sig.getToolId() + ":" + actualPkg);
                        items.add(new EvidenceItem(
                                "threat_app_cert",
                                EvidenceItem.SourceLayer.JAVA,
                                actualPkg,
                                sig.getToolId() + ":" + prefix16(sha256),
                                family,
                                rank));
                    }
                }
                if (effectivePolicy.getAdditionalCertSha256s().contains(sha256)) {
                    matchedByStrongIdentity = true;
                    toolFound = true;
                    details.add("threat_app_custom_cert:" + actualPkg);
                    items.add(new EvidenceItem(
                            "threat_app_custom_cert",
                            EvidenceItem.SourceLayer.JAVA,
                            actualPkg,
                            prefix16(sha256),
                            FAMILY_THREAT_APP,
                            EvidenceItem.Rank.MEDIUM));
                }
            }

            // 2. Extracted nativeLibraryDir daemon payloads (immune to package/label renaming)
            String dir = app.getNativeLibraryDir();
            if (effectivePolicy.isEnableNativePayloadInspection()
                    && dir != null
                    && !dir.isBlank()) {
                PayloadScanResult payloadResult = payloadCache.get(dir);
                if (payloadResult == null) {
                    try {
                        payloadResult = nativePayloadReader.read(
                                dir, ThreatAppSignatureLibrary.getAllNativePayloads());
                    } catch (Exception | LinkageError | OutOfMemoryError e) {
                        payloadResult = PayloadScanResult.failed(e.getClass().getSimpleName());
                    }
                    payloadCache.put(dir, payloadResult);
                    if (!payloadResult.isObservable()) {
                        payloadFailures++;
                    }
                }
                if (payloadResult.isObservable() && !payloadResult.getFoundPayloads().isEmpty()) {
                    // Aggregate matched payloads per evidence family so DataAggregator.mergeEvidenceItems
                    // (keyed on code|location) preserves every matched .so rather than dropping secondary ones.
                    Map<String, List<String>> payloadsByFamily = new LinkedHashMap<>();
                    for (String payload : payloadResult.getFoundPayloads()) {
                        matchedByStrongIdentity = true;
                        ThreatAppSignatureLibrary.ToolSignature sig =
                                ThreatAppSignatureLibrary.matchByNativePayload(payload);
                        String family = (sig != null)
                                ? familyFor(sig.getCategory())
                                : FAMILY_ROOT_FW;
                        if (FAMILY_ROOT_FW.equals(family)) {
                            rootFound = true;
                        } else {
                            toolFound = true;
                        }
                        details.add("threat_app_native_payload:" + payload + ":" + actualPkg);
                        payloadsByFamily.computeIfAbsent(family, k -> new ArrayList<>()).add(payload);
                    }
                    for (Map.Entry<String, List<String>> entry : payloadsByFamily.entrySet()) {
                        items.add(new EvidenceItem(
                                "threat_app_native_payload",
                                EvidenceItem.SourceLayer.JAVA,
                                actualPkg,
                                String.join(",", entry.getValue()),
                                entry.getKey(),
                                EvidenceItem.Rank.STRONG));
                    }
                }
            }

            // 3. ApplicationInfo.zygotePreloadName (via public manifest XML inspection)
            if (effectivePolicy.isEnableZygotePreloadInspection() && zygotePreloadReader != null) {
                String preloadName = null;
                try {
                    preloadName = zygotePreloadReader.read(app);
                } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                    // Visibility or asset failure is never a threat.
                }
                if (preloadName != null && !preloadName.isBlank()) {
                    ThreatAppSignatureLibrary.ToolSignature sig =
                            ThreatAppSignatureLibrary.matchByZygotePreload(preloadName);
                    if (sig != null) {
                        matchedByStrongIdentity = true;
                        String family = familyFor(sig.getCategory());
                        if (sig.isRootManager()) {
                            rootFound = true;
                        } else {
                            toolFound = true;
                        }
                        details.add("threat_app_zygote_preload:" + sig.getToolId() + ":" + actualPkg);
                        items.add(new EvidenceItem(
                                "threat_app_zygote_preload",
                                EvidenceItem.SourceLayer.JAVA,
                                actualPkg,
                                preloadName,
                                family,
                                EvidenceItem.Rank.STRONG));
                    }
                }
            }

            // 4. Built-in package match (covers self-compiled / re-signed builds)
            if (!matchedByStrongIdentity && effectivePolicy.isEnableBuiltInCatalog()) {
                ThreatAppSignatureLibrary.ToolSignature pkgSig =
                        ThreatAppSignatureLibrary.matchByPackageName(actualPkg);
                if (pkgSig != null) {
                    String family = familyFor(pkgSig.getCategory());
                    if (pkgSig.isRootManager()) {
                        rootFound = true;
                    } else if (pkgSig.getCategory() == ThreatAppSignatureLibrary.Category.APP_HIDER) {
                        hiderFound = true;
                    } else {
                        toolFound = true;
                    }
                    details.add("threat_app_package:" + actualPkg);
                    items.add(new EvidenceItem(
                            "threat_app_package",
                            EvidenceItem.SourceLayer.JAVA,
                            actualPkg,
                            pkgSig.getToolId(),
                            family,
                            EvidenceItem.Rank.MEDIUM));
                }
            }

            // 5. Host-configured custom package hit
            if (effectivePolicy.getAdditionalPackages().contains(actualPkg)
                    || effectivePolicy.getAdditionalPackages().contains(pkg)) {
                toolFound = true;
                details.add("threat_app_custom_pkg:" + actualPkg);
                items.add(new EvidenceItem(
                        "threat_app_custom_pkg",
                        EvidenceItem.SourceLayer.JAVA,
                        actualPkg,
                        actualPkg,
                        FAMILY_THREAT_APP,
                        EvidenceItem.Rank.MEDIUM));
            }

            // 6. Host-configured dangerous permission combinations
            if (needPermissions && !app.getRequestedPermissions().isEmpty()) {
                for (ThreatAppPolicy.PermissionComboRule rule
                        : effectivePolicy.getDangerousPermissionCombos()) {
                    if (app.getRequestedPermissions().containsAll(rule.getPermissions())) {
                        toolFound = true;
                        details.add("threat_app_perm_combo:" + rule.getName() + ":" + actualPkg);
                        items.add(new EvidenceItem(
                                "threat_app_perm_combo",
                                EvidenceItem.SourceLayer.JAVA,
                                actualPkg,
                                rule.getName(),
                                FAMILY_THREAT_APP,
                                EvidenceItem.Rank.MEDIUM));
                    }
                }
            }
        }

        return new ProbeOutcome(
                items,
                details,
                inspected,
                installed,
                payloadFailures,
                rootFound,
                hiderFound,
                toolFound);
    }

    /**
     * Extracts all distinct lowercase 64-char SHA-256 certificate digests across both
     * {@code apkContentsSigners} and (for single-signer v3/v3.1 rotated APKs)
     * {@code signingCertificateHistory}.
     */
    public static List<String> extractCertSha256Lineage(PackageInfo pkgInfo) {
        if (pkgInfo == null) {
            return Collections.emptyList();
        }
        SigningInfo signingInfo = pkgInfo.signingInfo;
        if (signingInfo == null) {
            return Collections.emptyList();
        }
        return extractCertSha256Lineage(
                signingInfo.getApkContentsSigners(),
                signingInfo.hasMultipleSigners(),
                signingInfo.getSigningCertificateHistory());
    }

    /** Pure helper for extracting distinct SHA-256 digests from signer + rotation arrays. */
    static List<String> extractCertSha256Lineage(Signature[] apkContentsSigners,
                                                 boolean hasMultipleSigners,
                                                 Signature[] signingCertificateHistory) {
        Set<String> digests = new LinkedHashSet<>();
        addSignatureDigests(digests, apkContentsSigners);
        if (!hasMultipleSigners) {
            addSignatureDigests(digests, signingCertificateHistory);
        }
        return digests.isEmpty() ? Collections.emptyList() : new ArrayList<>(digests);
    }

    private static void addSignatureDigests(Set<String> target, Signature[] signatures) {
        if (signatures == null) {
            return;
        }
        for (Signature sig : signatures) {
            if (sig == null) {
                continue;
            }
            byte[] der = sig.toByteArray();
            if (der != null && der.length > 0) {
                String sha = sha256LowerHex(der);
                if (sha != null) {
                    target.add(sha);
                }
            }
        }
    }

    public static String sha256LowerHex(byte[] data) {
        if (data == null) {
            return null;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            char[] out = new char[digest.length * 2];
            for (int i = 0; i < digest.length; i++) {
                int v = digest[i] & 0xFF;
                out[i * 2] = HEX_DIGITS[v >>> 4];
                out[i * 2 + 1] = HEX_DIGITS[v & 0x0F];
            }
            return new String(out);
        } catch (Exception | LinkageError e) {
            return null;
        }
    }

    private static String prefix16(String hex) {
        return hex.length() > 16 ? hex.substring(0, 16) : hex;
    }

    private static Set<String> buildTargetPackages(ThreatAppPolicy policy) {
        Set<String> targets = new LinkedHashSet<>();
        if (policy.isEnableBuiltInCatalog()) {
            Collections.addAll(targets, DetectionLists.THREAT_APP_PACKAGES);
        }
        targets.addAll(policy.getAdditionalPackages());
        return targets;
    }

    private static String familyFor(ThreatAppSignatureLibrary.Category category) {
        if (category == ThreatAppSignatureLibrary.Category.ROOT_MANAGER) {
            return FAMILY_ROOT_FW;
        }
        if (category == ThreatAppSignatureLibrary.Category.APP_HIDER) {
            return FAMILY_HMA_HIDING;
        }
        return FAMILY_THREAT_APP;
    }

    private static PackageQueryAdapter defaultPackageQueryAdapter(Context context) {
        if (context == null) {
            return null;
        }
        final PackageManager pm;
        try {
            Context appCtx = context.getApplicationContext();
            Context effective = appCtx != null ? appCtx : context;
            pm = effective.getPackageManager();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return null;
        }
        if (pm == null) {
            return null;
        }
        return (packageName, includePermissions) -> {
            int flags = PackageManager.GET_SIGNING_CERTIFICATES;
            if (includePermissions) {
                flags |= PackageManager.GET_PERMISSIONS;
            }
            PackageInfo pkgInfo;
            try {
                if (Build.VERSION.SDK_INT >= 33) {
                    pkgInfo = pm.getPackageInfo(
                            packageName, PackageManager.PackageInfoFlags.of(flags));
                } else {
                    pkgInfo = getPackageInfoLegacy(pm, packageName, flags);
                }
            } catch (PackageManager.NameNotFoundException e) {
                return null;
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                return null;
            }
            if (pkgInfo == null) {
                return null;
            }
            String actualPkg = (pkgInfo.packageName != null && !pkgInfo.packageName.isBlank())
                    ? pkgInfo.packageName
                    : packageName;
            String nativeDir = pkgInfo.applicationInfo != null
                    ? pkgInfo.applicationInfo.nativeLibraryDir
                    : null;
            List<String> perms = pkgInfo.requestedPermissions != null
                    ? Arrays.asList(pkgInfo.requestedPermissions)
                    : Collections.emptyList();
            return new InspectedApp(
                    actualPkg,
                    extractCertSha256Lineage(pkgInfo),
                    nativeDir,
                    perms,
                    pkgInfo.applicationInfo);
        };
    }

    @SuppressWarnings("deprecation")
    private static PackageInfo getPackageInfoLegacy(PackageManager pm, String pkg, int flags)
            throws PackageManager.NameNotFoundException {
        return pm.getPackageInfo(pkg, flags);
    }

    private static final NativePayloadReader DEFAULT_NATIVE_PAYLOAD_READER =
            (nativeLibraryDir, payloadNames) -> {
                if (nativeLibraryDir == null || nativeLibraryDir.isBlank()) {
                    return PayloadScanResult.observed(Collections.emptySet());
                }
                Set<String> present = new LinkedHashSet<>();
                for (String name : payloadNames) {
                    if (name == null || name.isBlank()) {
                        continue;
                    }
                    try {
                        Os.stat(nativeLibraryDir + "/" + name);
                        present.add(name);
                    } catch (ErrnoException e) {
                        if (e.errno != OsConstants.ENOENT && e.errno != OsConstants.ENOTDIR) {
                            return PayloadScanResult.failed("errno_" + e.errno);
                        }
                    } catch (Exception | LinkageError | OutOfMemoryError e) {
                        return PayloadScanResult.failed(e.getClass().getSimpleName());
                    }
                }
                return PayloadScanResult.observed(present);
            };

    /**
     * Reads {@code <application android:zygotePreloadName="...">} through public
     * {@link PackageManager#getResourcesForApplication(ApplicationInfo)} +
     * {@link AssetManager#openXmlResourceParser(String)} with zero hidden-API reflection.
     */
    private static ZygotePreloadReader defaultZygotePreloadReader(Context context) {
        if (context == null) {
            return null;
        }
        final PackageManager pm;
        try {
            Context appCtx = context.getApplicationContext();
            Context effective = appCtx != null ? appCtx : context;
            pm = effective.getPackageManager();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return null;
        }
        if (pm == null) {
            return null;
        }
        return app -> {
            if (app == null || app.getApplicationInfo() == null) {
                return null;
            }
            ApplicationInfo appInfo = app.getApplicationInfo();
            XmlResourceParser parser = null;
            try {
                Resources res = pm.getResourcesForApplication(appInfo);
                if (res == null) {
                    return null;
                }
                AssetManager assets = res.getAssets();
                if (assets == null) {
                    return null;
                }
                parser = assets.openXmlResourceParser("AndroidManifest.xml");
                int eventType = parser.getEventType();
                while (eventType != XmlPullParser.END_DOCUMENT) {
                    if (eventType == XmlPullParser.START_TAG
                            && "application".equals(parser.getName())) {
                        String attr = parser.getAttributeValue(
                                ANDROID_XML_NS, "zygotePreloadName");
                        if (attr == null || attr.isBlank()) {
                            return null;
                        }
                        String trimmed = attr.trim();
                        if (trimmed.startsWith(".")
                                && appInfo.packageName != null
                                && !appInfo.packageName.isBlank()) {
                            return appInfo.packageName + trimmed;
                        }
                        return trimmed;
                    }
                    eventType = parser.next();
                }
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                return null;
            } finally {
                if (parser != null) {
                    try {
                        parser.close();
                    } catch (Exception ignored) {
                        // Best-effort close.
                    }
                }
            }
            return null;
        };
    }
}
