package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CRITICAL-tier application integrity & anti-repackaging detector ({@code app_integrity}).
 *
 * <p>Combines five independent checks:
 * <ol>
 *   <li>Expected package name pinning (when configured in {@link RiskEngineConfig}).</li>
 *   <li>Java APK Signing Scheme v2/v3/v3.1 verification via {@code GET_SIGNING_CERTIFICATES}:
 *       validates ALL {@code apkContentsSigners} when {@code hasMultipleSigners()} is true,
 *       otherwise validates the active signer ({@code apkContentsSigners[0]} /
 *       {@code signingCertificateHistory[last]} — never {@code history[0]}) and lineage.</li>
 *   <li>Native raw-syscall {@code base.apk} APK Signing Block cross-verification against Java
 *       {@link SigningInfo} (detects Binder/{@code PackageManager} hooks via
 *       {@code apk_native_java_sig_conflict}) and independent native certificate pinning.</li>
 *   <li>Installer store verification via API 30+ {@code getInstallSourceInfo} against built-in
 *       official presets or host {@code trustedInstallerPackages} override.</li>
 *   <li>Non-debuggable release obfuscation check via unkept {@link ObfuscationSentinel}.</li>
 * </ol>
 */
public class AppIntegrityDetector extends BaseDetector {
    private static final String FAMILY_APP_TAMPER = "app_tamper";

    private final RiskEngineConfig config;
    private final SignalSnapshot signals;
    private final IntegrityEnvironment env;

    public AppIntegrityDetector(Context context, RiskEngineConfig config, SignalSnapshot signals) {
        this(context, config, signals, null);
    }

    /** Internal test seam for deterministic pure-JVM unit tests (not part of public SDK contract). */
    public static AppIntegrityDetector createForTest(Context context,
                                                     RiskEngineConfig config,
                                                     SignalSnapshot signals,
                                                     IntegrityEnvironment env) {
        return new AppIntegrityDetector(context, config, signals, env);
    }

    AppIntegrityDetector(Context context,
                         RiskEngineConfig config,
                         SignalSnapshot signals,
                         IntegrityEnvironment env) {
        super(context);
        this.config = config == null ? new RiskEngineConfig.Builder().build() : config;
        this.signals = signals != null ? signals : new SignalSnapshot(context);
        this.env = env != null ? env : new AndroidIntegrityEnvironment(this.context);
    }

    @Override
    public String getName() {
        return "app_integrity";
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.CRITICAL;
    }

    @Override
    protected DetectionResult detect() {
        CheckCoverage coverage = new CheckCoverage();
        List<String> details = new ArrayList<>();
        Map<String, EvidenceItem> evidenceByKey = new LinkedHashMap<>();

        boolean hasHardTamper = false;
        boolean hasUnofficialInstaller = false;
        boolean hasReleaseUnobfuscated = false;

        // 1. Expected package name pinning (skipped cleanly when unconfigured)
        String expectedPkg = config.getExpectedPackageName();
        String runtimePkg = null;
        try {
            runtimePkg = env.getRuntimePackageName();
            if (runtimePkg != null && !runtimePkg.isBlank()) {
                coverage.success();
            } else if (expectedPkg != null) {
                coverage.failure("package_name_unavailable");
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("package_name_error:" + e.getClass().getSimpleName());
        }

        if (expectedPkg != null && runtimePkg != null && !runtimePkg.isBlank()) {
            String appInfoPkg = null;
            try {
                appInfoPkg = env.getApplicationInfoPackageName();
            } catch (Exception | LinkageError | OutOfMemoryError ignored) {
                // Non-fatal; runtimePkg already checked.
            }
            boolean runtimeMismatch = !expectedPkg.equals(runtimePkg);
            boolean appInfoMismatch = appInfoPkg != null && !appInfoPkg.isBlank()
                    && !expectedPkg.equals(appInfoPkg);
            if (runtimeMismatch || appInfoMismatch) {
                String observed = runtimeMismatch ? runtimePkg : appInfoPkg;
                hasHardTamper = true;
                addUnique(details, "pkg_name_mismatch:" + observed);
                putMergedEvidence(evidenceByKey, new EvidenceItem(
                        "pkg_name_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "package_manager",
                        observed + "!=" + expectedPkg,
                        FAMILY_APP_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
        }

        // 2. Java SigningInfo extraction (APK v2 / v3 / v3.1)
        Set<String> expectedPins = normalizePinSet(config.getExpectedSigningCertSha256Base64());
        Set<String> javaActiveSigners = Collections.emptySet();
        List<String> javaLineage = Collections.emptyList();
        boolean javaMultipleSigners = false;

        try {
            JavaSigningSnapshot javaSig = env.readJavaSigningSnapshot();
            if (javaSig != null && javaSig.available) {
                coverage.success();
                javaMultipleSigners = javaSig.hasMultipleSigners;
                if (javaSig.hasMultipleSigners) {
                    Set<String> active = new LinkedHashSet<>();
                    for (String cert : javaSig.apkContentsSigners) {
                        String norm = normalizeSha256Base64(cert);
                        if (!norm.isEmpty()) {
                            active.add(norm);
                        }
                    }
                    javaActiveSigners = active;
                    javaLineage = Collections.emptyList();
                } else {
                    List<String> normalizedContents = normalizeList(javaSig.apkContentsSigners);
                    String activeFromContents = normalizedContents.isEmpty()
                            ? ""
                            : normalizedContents.get(0);
                    List<String> normalizedHistory = normalizeList(javaSig.signingCertificateHistory);
                    String activeFromHistoryLast = normalizedHistory.isEmpty()
                            ? ""
                            : normalizedHistory.get(normalizedHistory.size() - 1);

                    // Consistency guard: apkContentsSigners[0] must agree with history[last]
                    // when both are present (never use history[0] as the active signer).
                    if (!activeFromContents.isEmpty()
                            && !activeFromHistoryLast.isEmpty()
                            && !activeFromContents.equals(activeFromHistoryLast)) {
                        hasHardTamper = true;
                        addUnique(details, "apk_sig_mismatch:lineage_active_conflict");
                        putMergedEvidence(evidenceByKey, new EvidenceItem(
                                "apk_sig_mismatch",
                                EvidenceItem.SourceLayer.JAVA,
                                "apk_signing_cert",
                                "active_vs_history_last_conflict",
                                FAMILY_APP_TAMPER,
                                EvidenceItem.Rank.STRONG));
                    }

                    // Collect ALL apkContentsSigners even when hasMultipleSigners() reports false,
                    // blocking multi-signer smuggling if hasMultipleSigners() is hooked.
                    if (!normalizedContents.isEmpty()) {
                        javaActiveSigners = new LinkedHashSet<>(normalizedContents);
                    } else if (!activeFromHistoryLast.isEmpty()) {
                        javaActiveSigners = Collections.singleton(activeFromHistoryLast);
                    }
                    javaLineage = normalizedHistory;
                }

                if (!expectedPins.isEmpty()) {
                    if (javaActiveSigners.isEmpty()) {
                        coverage.failure("java_signing_empty");
                    } else if (!allPinned(javaActiveSigners, expectedPins)) {
                        hasHardTamper = true;
                        addUnique(details, "apk_sig_mismatch");
                        putMergedEvidence(evidenceByKey, new EvidenceItem(
                                "apk_sig_mismatch",
                                EvidenceItem.SourceLayer.JAVA,
                                "apk_signing_cert",
                                javaMultipleSigners
                                        ? "java_multi_signer_untrusted"
                                        : "java_active_signer_untrusted",
                                FAMILY_APP_TAMPER,
                                EvidenceItem.Rank.STRONG));
                    }
                }
            } else if (!expectedPins.isEmpty()) {
                coverage.failure("java_signing_unavailable");
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("java_signing_error:" + e.getClass().getSimpleName());
        }

        // 3. Native raw-syscall APK Signing Block verification & Java/Native parity
        try {
            SignalResult<String> nativeRaw = signals.getNativeApkSigningInfo();
            if (nativeRaw != null && nativeRaw.isSuccess()
                    && nativeRaw.getValue() != null && !nativeRaw.getValue().isEmpty()) {
                NativePayloadCodec.DecodedPayload decoded =
                        NativePayloadCodec.decodePayload(nativeRaw.getValue());
                if (decoded.isOk()) {
                    coverage.success();
                    int sdkInt = env.getSdkInt();
                    NativeEffectiveSigning nativeSig = resolveEffectiveNativeSigning(decoded, sdkInt);
                    String apkPath = decoded.getHeaderField("apk_path");
                    String location = (apkPath == null || apkPath.isBlank())
                            ? "base.apk"
                            : apkPath;

                    if (!expectedPins.isEmpty() && !nativeSig.activeSigners.isEmpty()
                            && !allPinned(nativeSig.activeSigners, expectedPins)) {
                        hasHardTamper = true;
                        addUnique(details, "apk_sig_mismatch");
                        putMergedEvidence(evidenceByKey, new EvidenceItem(
                                "apk_sig_mismatch",
                                EvidenceItem.SourceLayer.NATIVE,
                                "apk_signing_cert",
                                "native_active_signer_untrusted:" + nativeSig.scheme,
                                FAMILY_APP_TAMPER,
                                EvidenceItem.Rank.STRONG));
                    }

                    // Cross-verify Java SigningInfo vs Native raw-syscall base.apk
                    if (!javaActiveSigners.isEmpty() && !nativeSig.activeSigners.isEmpty()) {
                        boolean activeConflict = !javaActiveSigners.equals(nativeSig.activeSigners);
                        boolean lineageConflict = false;
                        if (!activeConflict && !javaMultipleSigners) {
                            boolean eitherRotated =
                                    javaLineage.size() >= 2 || nativeSig.lineage.size() >= 2;
                            if (eitherRotated) {
                                if (nativeSig.lineage.isEmpty()) {
                                    lineageConflict = javaLineage.size() >= 2;
                                } else {
                                    lineageConflict = !javaLineage.equals(nativeSig.lineage);
                                }
                            }
                        }
                        if (activeConflict || lineageConflict) {
                            hasHardTamper = true;
                            addUnique(details, "apk_native_java_sig_conflict");
                            putMergedEvidence(evidenceByKey, new EvidenceItem(
                                    "apk_native_java_sig_conflict",
                                    EvidenceItem.SourceLayer.NATIVE,
                                    EnumSet.of(
                                            EvidenceItem.SourceLayer.JAVA,
                                            EvidenceItem.SourceLayer.NATIVE),
                                    location,
                                    activeConflict
                                            ? "active_signer_mismatch:" + nativeSig.scheme
                                            : "rotation_lineage_mismatch:" + nativeSig.scheme,
                                    FAMILY_APP_TAMPER,
                                    EvidenceItem.Rank.STRONG));
                        }
                    }
                }
                // RESTRICTED / UNSUPPORTED (e.g. v1-only APK or SELinux denial) is visibility loss,
                // never a positive threat and must not degrade a clean device to UNKNOWN.
            }
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Native visibility loss must not crash or degrade clean Java checks.
        }

        // Read application flags once for installer & obfuscation checks.
        int appFlags = 0;
        boolean hasAppFlags = false;
        try {
            Integer flags = env.getApplicationFlags();
            if (flags != null) {
                appFlags = flags;
                hasAppFlags = true;
            }
        } catch (Exception | LinkageError | OutOfMemoryError ignored) {
            // Best-effort.
        }

        // 4. Official installer source check (API 30+ getInstallSourceInfo)
        try {
            InstallSourceSnapshot installSource = env.readInstallSource();
            if (installSource != null && installSource.available) {
                coverage.success();
                String effectiveInstaller = firstNonBlank(
                        installSource.installingPackageName,
                        installSource.initiatingPackageName);
                boolean isSystemApp = hasAppFlags
                        && (appFlags & ApplicationInfo.FLAG_SYSTEM) != 0;
                if (!(effectiveInstaller == null && isSystemApp)) {
                    Set<String> trusted = config.getTrustedInstallerPackages();
                    if (effectiveInstaller == null || !trusted.contains(effectiveInstaller)) {
                        hasUnofficialInstaller = true;
                        String label = effectiveInstaller == null ? "sideload" : effectiveInstaller;
                        addUnique(details, "unofficial_installer:" + label);
                        putMergedEvidence(evidenceByKey, new EvidenceItem(
                                "unofficial_installer",
                                EvidenceItem.SourceLayer.JAVA,
                                "install_source",
                                label,
                                FAMILY_APP_TAMPER,
                                EvidenceItem.Rank.MEDIUM));
                    }
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            coverage.failure("install_source_error:" + e.getClass().getSimpleName());
        }

        // 5. Release obfuscation sentinel check (only on non-debuggable builds)
        if (hasAppFlags) {
            try {
                boolean isDebuggable = (appFlags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                if (!isDebuggable && !env.isObfuscated()) {
                    hasReleaseUnobfuscated = true;
                    addUnique(details, "release_unobfuscated");
                    putMergedEvidence(evidenceByKey, new EvidenceItem(
                            "release_unobfuscated",
                            EvidenceItem.SourceLayer.JAVA,
                            "obfuscation_sentinel",
                            "ObfuscationSentinel",
                            FAMILY_APP_TAMPER,
                            EvidenceItem.Rank.WEAK));
                }
                coverage.success();
            } catch (Exception | LinkageError | OutOfMemoryError e) {
                coverage.failure("obfuscation_check_error:" + e.getClass().getSimpleName());
            }
        }

        List<EvidenceItem> evidenceItems = new ArrayList<>(evidenceByKey.values());
        if (hasHardTamper) {
            return result(
                    RiskLevel.DEADLY,
                    DetectionStatus.DANGER,
                    10,
                    10,
                    false,
                    details,
                    String.join("; ", details),
                    coverage
            ).withEvidenceItems(evidenceItems);
        }
        if (hasUnofficialInstaller) {
            return result(
                    RiskLevel.MEDIUM,
                    DetectionStatus.WARNING,
                    4,
                    10,
                    true,
                    details,
                    String.join("; ", details),
                    coverage
            ).withEvidenceItems(evidenceItems);
        }
        if (hasReleaseUnobfuscated) {
            return result(
                    RiskLevel.LOW,
                    DetectionStatus.WARNING,
                    2,
                    10,
                    true,
                    details,
                    String.join("; ", details),
                    coverage
            ).withEvidenceItems(evidenceItems);
        }
        return safe(coverage);
    }

    /**
     * Resolves the active APK Signing Scheme signers and optional rotation lineage
     * from a decoded {@link NativePayloadCodec.DecodedPayload} following Android's
     * {@code ApkSignatureVerifier} precedence: v3.1 (matching SDK range) &gt; v3
     * (matching SDK range) &gt; v2.
     */
    static NativeEffectiveSigning resolveEffectiveNativeSigning(
            NativePayloadCodec.DecodedPayload payload, int sdkInt) {
        List<NativeSigner> v31Signers = new ArrayList<>();
        List<NativeSigner> v3Signers = new ArrayList<>();
        List<NativeSigner> v2Signers = new ArrayList<>();
        List<NativeLineageEntry> allLineage = new ArrayList<>();

        for (Map<String, String> record : payload.getRecords()) {
            String kind = record.get("kind");
            String scheme = record.get("scheme");
            String b64 = normalizeSha256Base64(record.get("cert_sha256_b64"));
            if (b64.isEmpty()) {
                b64 = hexSha256ToBase64(record.get("cert_sha256_hex"));
            }
            if (b64.isEmpty() || scheme == null) {
                continue;
            }
            if ("signer".equals(kind)) {
                int index = parseIntOr(record.get("index"), 0);
                int minSdk = parseIntOr(record.get("min_sdk"), 0);
                int maxSdk = parseIntOr(record.get("max_sdk"), Integer.MAX_VALUE);
                NativeSigner signer = new NativeSigner(scheme, index, minSdk, maxSdk, b64);
                if ("v3.1".equals(scheme)) {
                    v31Signers.add(signer);
                } else if ("v3".equals(scheme)) {
                    v3Signers.add(signer);
                } else if ("v2".equals(scheme)) {
                    v2Signers.add(signer);
                }
            } else if ("lineage".equals(kind)) {
                int signerIndex = parseIntOr(record.get("signer_index"), 0);
                int level = parseIntOr(record.get("level"), 0);
                allLineage.add(new NativeLineageEntry(scheme, signerIndex, level, b64));
            }
        }

        // Android 13 (API 33) introduced APK Signature Scheme v3.1; API 30-32 ignore v3.1 blocks.
        NativeEffectiveSigning selected = sdkInt >= 33
                ? selectBySdk("v3.1", v31Signers, allLineage, sdkInt)
                : null;
        if (selected != null) {
            return selected;
        }
        selected = selectBySdk("v3", v3Signers, allLineage, sdkInt);
        if (selected != null) {
            return selected;
        }
        Set<String> v2Active = new LinkedHashSet<>();
        for (NativeSigner signer : v2Signers) {
            v2Active.add(signer.certB64);
        }
        return new NativeEffectiveSigning("v2", v2Active, Collections.emptyList());
    }

    private static NativeEffectiveSigning selectBySdk(String scheme,
                                                      List<NativeSigner> signers,
                                                      List<NativeLineageEntry> allLineage,
                                                      int sdkInt) {
        if (signers.isEmpty()) {
            return null;
        }
        List<NativeSigner> matched = new ArrayList<>();
        for (NativeSigner s : signers) {
            if (sdkInt >= s.minSdk && sdkInt <= s.maxSdk) {
                matched.add(s);
            }
        }
        if (matched.isEmpty()) {
            return null;
        }
        Set<String> active = new LinkedHashSet<>();
        Set<Integer> matchedIndices = new LinkedHashSet<>();
        for (NativeSigner s : matched) {
            active.add(s.certB64);
            matchedIndices.add(s.index);
        }
        List<NativeLineageEntry> matchingLineage = new ArrayList<>();
        for (NativeLineageEntry entry : allLineage) {
            if (scheme.equals(entry.scheme) && matchedIndices.contains(entry.signerIndex)) {
                matchingLineage.add(entry);
            }
        }
        matchingLineage.sort(Comparator.comparingInt(a -> a.level));
        List<String> lineageCerts = new ArrayList<>(matchingLineage.size());
        for (NativeLineageEntry entry : matchingLineage) {
            lineageCerts.add(entry.certB64);
        }
        return new NativeEffectiveSigning(scheme, active, lineageCerts);
    }

    static String normalizeSha256Base64(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String trimmed = raw.trim();
        try {
            byte[] decoded = (trimmed.indexOf('-') >= 0 || trimmed.indexOf('_') >= 0)
                    ? Base64.getUrlDecoder().decode(trimmed)
                    : Base64.getDecoder().decode(trimmed);
            if (decoded.length == 32) {
                return Base64.getEncoder().encodeToString(decoded);
            }
        } catch (IllegalArgumentException ignored) {
            // Preserve non-standard token verbatim so typos fail pinning cleanly.
        }
        return trimmed;
    }

    private static String hexSha256ToBase64(String hex) {
        if (hex == null) {
            return "";
        }
        String cleaned = hex.trim();
        if (cleaned.length() != 64) {
            return "";
        }
        byte[] bytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            int hi = Character.digit(cleaned.charAt(i * 2), 16);
            int lo = Character.digit(cleaned.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                return "";
            }
            bytes[i] = (byte) ((hi << 4) | lo);
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static Set<String> normalizePinSet(Set<String> rawPins) {
        if (rawPins == null || rawPins.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> normalized = new LinkedHashSet<>(rawPins.size());
        for (String pin : rawPins) {
            String value = normalizeSha256Base64(pin);
            if (!value.isEmpty()) {
                normalized.add(value);
            }
        }
        return normalized;
    }

    private static List<String> normalizeList(List<String> certs) {
        if (certs == null || certs.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> out = new ArrayList<>(certs.size());
        for (String cert : certs) {
            String norm = normalizeSha256Base64(cert);
            if (!norm.isEmpty()) {
                out.add(norm);
            }
        }
        return out;
    }

    private static boolean allPinned(Set<String> observed, Set<String> expectedPins) {
        if (observed == null || observed.isEmpty()) {
            return false;
        }
        for (String cert : observed) {
            if (!expectedPins.contains(cert)) {
                return false;
            }
        }
        return true;
    }

    private static String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first.trim();
        }
        if (second != null && !second.isBlank()) {
            return second.trim();
        }
        return null;
    }

    private static int parseIntOr(String raw, int fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static void addUnique(List<String> list, String value) {
        if (value != null && !value.isBlank() && !list.contains(value)) {
            list.add(value);
        }
    }

    private static void putMergedEvidence(Map<String, EvidenceItem> byKey, EvidenceItem item) {
        String key = item.getCode() + "\0" + item.getLocation();
        EvidenceItem existing = byKey.get(key);
        byKey.put(key, existing == null ? item : existing.mergeWith(item));
    }

    static final class NativeEffectiveSigning {
        final String scheme;
        final Set<String> activeSigners;
        final List<String> lineage;

        NativeEffectiveSigning(String scheme, Set<String> activeSigners, List<String> lineage) {
            this.scheme = scheme;
            this.activeSigners = Collections.unmodifiableSet(activeSigners);
            this.lineage = Collections.unmodifiableList(lineage);
        }
    }

    private static final class NativeSigner {
        final String scheme;
        final int index;
        final int minSdk;
        final int maxSdk;
        final String certB64;

        NativeSigner(String scheme, int index, int minSdk, int maxSdk, String certB64) {
            this.scheme = scheme;
            this.index = index;
            this.minSdk = minSdk;
            this.maxSdk = maxSdk;
            this.certB64 = certB64;
        }
    }

    private static final class NativeLineageEntry {
        final String scheme;
        final int signerIndex;
        final int level;
        final String certB64;

        NativeLineageEntry(String scheme, int signerIndex, int level, String certB64) {
            this.scheme = scheme;
            this.signerIndex = signerIndex;
            this.level = level;
            this.certB64 = certB64;
        }
    }

    /** Injectable platform adapter for pure-JVM unit testing. */
    public interface IntegrityEnvironment {
        String getRuntimePackageName();
        String getApplicationInfoPackageName();
        Integer getApplicationFlags();
        JavaSigningSnapshot readJavaSigningSnapshot() throws Exception;
        InstallSourceSnapshot readInstallSource() throws Exception;
        int getSdkInt();
        boolean isObfuscated();
    }

    public static final class JavaSigningSnapshot {
        final boolean available;
        final boolean hasMultipleSigners;
        final List<String> apkContentsSigners;
        final List<String> signingCertificateHistory;

        public JavaSigningSnapshot(boolean available,
                                   boolean hasMultipleSigners,
                                   List<String> apkContentsSigners,
                                   List<String> signingCertificateHistory) {
            this.available = available;
            this.hasMultipleSigners = hasMultipleSigners;
            this.apkContentsSigners = apkContentsSigners == null
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(apkContentsSigners));
            this.signingCertificateHistory = signingCertificateHistory == null
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(signingCertificateHistory));
        }

        public static JavaSigningSnapshot unavailable() {
            return new JavaSigningSnapshot(
                    false, false, Collections.emptyList(), Collections.emptyList());
        }
    }

    public static final class InstallSourceSnapshot {
        final boolean available;
        final String installingPackageName;
        final String initiatingPackageName;

        public InstallSourceSnapshot(boolean available,
                                     String installingPackageName,
                                     String initiatingPackageName) {
            this.available = available;
            this.installingPackageName = installingPackageName;
            this.initiatingPackageName = initiatingPackageName;
        }

        public static InstallSourceSnapshot unavailable() {
            return new InstallSourceSnapshot(false, null, null);
        }
    }

    private static final class AndroidIntegrityEnvironment implements IntegrityEnvironment {
        private final Context context;

        AndroidIntegrityEnvironment(Context context) {
            this.context = context;
        }

        @Override
        public String getRuntimePackageName() {
            return context == null ? null : context.getPackageName();
        }

        @Override
        public String getApplicationInfoPackageName() {
            if (context == null) return null;
            ApplicationInfo info = context.getApplicationInfo();
            return info == null ? null : info.packageName;
        }

        @Override
        public Integer getApplicationFlags() {
            if (context == null) return null;
            ApplicationInfo info = context.getApplicationInfo();
            return info == null ? null : info.flags;
        }

        @Override
        public JavaSigningSnapshot readJavaSigningSnapshot() throws Exception {
            if (context == null) {
                return JavaSigningSnapshot.unavailable();
            }
            PackageManager pm = context.getPackageManager();
            String pkg = context.getPackageName();
            if (pm == null || pkg == null || pkg.isBlank()) {
                return JavaSigningSnapshot.unavailable();
            }
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            if (info == null || info.signingInfo == null) {
                return JavaSigningSnapshot.unavailable();
            }
            SigningInfo signingInfo = info.signingInfo;
            return new JavaSigningSnapshot(
                    true,
                    signingInfo.hasMultipleSigners(),
                    hashSignaturesBase64(signingInfo.getApkContentsSigners()),
                    hashSignaturesBase64(signingInfo.getSigningCertificateHistory()));
        }

        @Override
        public InstallSourceSnapshot readInstallSource() throws Exception {
            if (context == null) {
                return InstallSourceSnapshot.unavailable();
            }
            PackageManager pm = context.getPackageManager();
            String pkg = context.getPackageName();
            if (pm == null || pkg == null || pkg.isBlank()) {
                return InstallSourceSnapshot.unavailable();
            }
            InstallSourceInfo info = pm.getInstallSourceInfo(pkg);
            if (info == null) {
                return InstallSourceSnapshot.unavailable();
            }
            return new InstallSourceSnapshot(
                    true,
                    info.getInstallingPackageName(),
                    info.getInitiatingPackageName());
        }

        @Override
        public int getSdkInt() {
            return Build.VERSION.SDK_INT;
        }

        @Override
        public boolean isObfuscated() {
            return ObfuscationSentinel.isObfuscated();
        }

        private static List<String> hashSignaturesBase64(Signature[] signatures) throws Exception {
            if (signatures == null || signatures.length == 0) {
                return Collections.emptyList();
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            List<String> out = new ArrayList<>(signatures.length);
            for (Signature sig : signatures) {
                if (sig == null) continue;
                byte[] der = sig.toByteArray();
                if (der == null || der.length == 0) continue;
                digest.reset();
                out.add(Base64.getEncoder().encodeToString(digest.digest(der)));
            }
            return out;
        }
    }
}
