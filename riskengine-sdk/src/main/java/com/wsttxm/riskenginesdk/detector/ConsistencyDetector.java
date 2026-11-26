package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.os.Build;
import android.system.Os;
import android.system.StructUtsname;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.consistency.BionicPropProbe;
import com.wsttxm.riskenginesdk.detector.probe.consistency.BootloaderProbe;
import com.wsttxm.riskenginesdk.detector.probe.consistency.PlayIntegrityFixProbe;
import com.wsttxm.riskenginesdk.detector.probe.consistency.WidevineParityProbe;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cross-source self-consistency checks.
 *
 * Compares independent readings of the same fact to catch contradictions left
 * behind by spoofing tools (such as resetprop, PlayIntegrityFix, SUSFS uname
 * hooks, or Build hooks) while avoiding false positives on stock Treble OEM
 * devices, big.LITTLE CPU migration, and dynamic CPU hotplugging.
 */
public class ConsistencyDetector extends BaseDetector {
    public static final String FAMILY_PROP_TAMPER = "prop_tamper";
    public static final String FAMILY_BOOT_INTEGRITY = "boot_integrity";
    public static final String FAMILY_HW_SPOOF = "hw_spoof";

    private static final int UTS_FIELD_MAX_LEN = 64;
    private static final Pattern PROCESSOR_LINE =
            Pattern.compile("^processor\\s*:", Pattern.MULTILINE);

    private final SignalSnapshot signals;
    private final NativeConsistencySource nativeSource;
    private final boolean enableTeeAttestation;
    private final WidevineParityProbe.JavaWidevineReader widevineJavaReader;

    /** Injectable source for native consistency probes to support deterministic JVM tests. */
    public interface NativeConsistencySource {
        SignalResult<String> getHardwareCpuIdentity();
        SignalResult<String> getKernelConsistency();
        SignalResult<String> getPifProperties();
        String getJavaOsVersion();
        default SignalResult<String> getWidevineNdkProbe() {
            return SignalResult.unavailable("widevine_ndk_not_seeded");
        }
    }

    private static final NativeConsistencySource DEFAULT_NATIVE_SOURCE =
            new NativeConsistencySource() {
                @Override
                public SignalResult<String> getHardwareCpuIdentity() {
                    return NativeCollectorBridge.getHardwareCpuIdentityResult();
                }

                @Override
                public SignalResult<String> getKernelConsistency() {
                    return NativeCollectorBridge.getKernelConsistencyResult();
                }

                @Override
                public SignalResult<String> getPifProperties() {
                    return NativeCollectorBridge.getPifPropertiesResult();
                }

                @Override
                public String getJavaOsVersion() {
                    try {
                        return System.getProperty("os.version");
                    } catch (Exception e) {
                        return "";
                    }
                }

                @Override
                public SignalResult<String> getWidevineNdkProbe() {
                    return NativeCollectorBridge.getWidevineNdkProbeResult();
                }
            };

    public ConsistencyDetector(Context context, SignalSnapshot signals) {
        this(context, signals, DEFAULT_NATIVE_SOURCE, true, WidevineParityProbe.DEFAULT_JAVA_READER);
    }

    public ConsistencyDetector(Context context,
                               SignalSnapshot signals,
                               NativeConsistencySource nativeSource) {
        this(context, signals, nativeSource, true, WidevineParityProbe.DEFAULT_JAVA_READER);
    }

    public ConsistencyDetector(Context context,
                               SignalSnapshot signals,
                               NativeConsistencySource nativeSource,
                               boolean enableTeeAttestation) {
        this(context, signals, nativeSource, enableTeeAttestation, WidevineParityProbe.DEFAULT_JAVA_READER);
    }

    public ConsistencyDetector(Context context,
                               SignalSnapshot signals,
                               NativeConsistencySource nativeSource,
                               boolean enableTeeAttestation,
                               WidevineParityProbe.JavaWidevineReader widevineJavaReader) {
        super(context);
        this.signals = signals;
        this.nativeSource = nativeSource != null ? nativeSource : DEFAULT_NATIVE_SOURCE;
        this.enableTeeAttestation = enableTeeAttestation;
        this.widevineJavaReader = widevineJavaReader != null
                ? widevineJavaReader
                : WidevineParityProbe.DEFAULT_JAVA_READER;
    }

    @Override
    public String getName() {
        return "consistency";
    }

    @Override
    public boolean hasPostponedProbes() {
        return true;
    }

    @Override
    protected DetectionResult detect() {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> mediumActionable = new LinkedHashSet<>();
        Set<String> weak = new LinkedHashSet<>();
        List<EvidenceItem> evidenceItems = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        checkPartitionFingerprints(strong, weak, evidenceItems, coverage);
        checkBuildAgainstProperties(strong, evidenceItems, coverage);
        checkCoreCount(strong, evidenceItems, coverage);
        checkAbiArch(strong, evidenceItems, coverage);
        checkApiRelease(weak, evidenceItems, coverage);
        checkFingerprintShape(weak, evidenceItems, coverage);
        checkVerifiedBoot(strong, mediumActionable, weak, evidenceItems, coverage);
        checkKernelRelease(weak, evidenceItems, coverage);
        checkThreeSourceKernelConsistency(strong, evidenceItems, coverage);
        checkBionicPropArea(strong, mediumActionable, evidenceItems, coverage);
        checkPlayIntegrityFix(strong, mediumActionable, weak, evidenceItems, coverage);

        List<String> evidence = new ArrayList<>(strong);
        evidence.addAll(mediumActionable);
        evidence.addAll(weak);

        DetectionResult base;
        if (!strong.isEmpty()) {
            base = result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        } else if (!mediumActionable.isEmpty()) {
            base = result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 5, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        } else if (hasConfirmedBootloaderRisk(weak)) {
            base = result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        } else if (!weak.isEmpty()) {
            base = result(RiskLevel.LOW, DetectionStatus.WARNING, 2, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        } else {
            base = safe(coverage);
        }
        return evidenceItems.isEmpty() ? base : base.withEvidenceItems(evidenceItems);
    }

    /**
     * Stage 3 postponed pass: runs the ARM64 EL0 {@code MIDR_EL1} hardware CPU identity
     * probe and Hardware Key Attestation {@code RootOfTrust} bootloader verification,
     * merging any findings into {@code priorResult} without impacting FAST-tier latency.
     */
    @Override
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        Set<String> newStrongTokens = new LinkedHashSet<>();
        Set<String> newMediumTokens = new LinkedHashSet<>();
        List<EvidenceItem> newItems = new ArrayList<>();
        int extraAttempted = 0;
        int extraSucceeded = 0;

        // 1. Hardware ARM64 MIDR_EL1 probe
        SignalResult<String> raw = nativeSource.getHardwareCpuIdentity();
        if (raw != null && raw.isSuccess() && raw.getValue() != null && !raw.getValue().isEmpty()) {
            NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(raw.getValue());
            if (decoded.isOk()) {
                extraAttempted++;
                extraSucceeded++;
                for (Map<String, String> rec : decoded.getRecords()) {
                    String kind = rec.get("kind");
                    if (kind == null || kind.isEmpty()) {
                        continue;
                    }
                    String cpu = rec.getOrDefault("cpu", "?");
                    String location = "cpu" + cpu;
                    if ("midr_sysfs_mismatch".equals(kind)) {
                        String value = "mrs=" + rec.getOrDefault("mrs", "")
                                + ",sysfs=" + rec.getOrDefault("sysfs", "");
                        newStrongTokens.add("midr_sysfs_mismatch:" + location);
                        newItems.add(new EvidenceItem(
                                "midr_sysfs_mismatch",
                                EvidenceItem.SourceLayer.NATIVE,
                                location,
                                value,
                                FAMILY_HW_SPOOF,
                                EvidenceItem.Rank.STRONG));
                    } else if ("midr_cpuinfo_mismatch".equals(kind)) {
                        String value = "mrs=" + rec.getOrDefault("mrs", "")
                                + ",cpuinfo=" + rec.getOrDefault("cpuinfo", "");
                        newStrongTokens.add("midr_cpuinfo_mismatch:" + location);
                        newItems.add(new EvidenceItem(
                                "midr_cpuinfo_mismatch",
                                EvidenceItem.SourceLayer.NATIVE,
                                location,
                                value,
                                FAMILY_HW_SPOOF,
                                EvidenceItem.Rank.STRONG));
                    } else if ("sysfs_cpuinfo_mismatch".equals(kind)) {
                        String value = "sysfs=" + rec.getOrDefault("sysfs", "")
                                + ",cpuinfo=" + rec.getOrDefault("cpuinfo", "");
                        newStrongTokens.add("sysfs_cpuinfo_mismatch:" + location);
                        newItems.add(new EvidenceItem(
                                "sysfs_cpuinfo_mismatch",
                                EvidenceItem.SourceLayer.NATIVE,
                                location,
                                value,
                                FAMILY_HW_SPOOF,
                                EvidenceItem.Rank.STRONG));
                    }
                }
            }
        }

        // 2. Hardware Key Attestation RootOfTrust bootloader verification
        BootloaderProbe.HardwareResult hwBoot =
                BootloaderProbe.evaluateHardwareRootOfTrust(signals, enableTeeAttestation);
        if (hwBoot.isEvaluated()) {
            extraAttempted++;
            extraSucceeded++;
            newStrongTokens.addAll(hwBoot.getStrongTokens());
            newMediumTokens.addAll(hwBoot.getMediumActionableTokens());
            newItems.addAll(hwBoot.getEvidenceItems());
        }

        // 3. Widevine Java MediaDrm vs NDK AMediaDrm dual-source parity
        WidevineParityProbe.ProbeResult wvRes = WidevineParityProbe.probe(
                widevineJavaReader,
                nativeSource::getWidevineNdkProbe,
                WidevineParityProbe.DEFAULT_TIMEOUT_MS);
        if (wvRes.isUsable()) {
            extraAttempted++;
            extraSucceeded++;
            newStrongTokens.addAll(wvRes.getStrongTokens());
            newMediumTokens.addAll(wvRes.getMediumTokens());
            newItems.addAll(wvRes.getEvidenceItems());
        }

        if (newStrongTokens.isEmpty() && newMediumTokens.isEmpty() && newItems.isEmpty()) {
            return priorResult;
        }

        Set<String> mergedDetails = new LinkedHashSet<>();
        List<EvidenceItem> mergedItems = new ArrayList<>();
        int attempted = Math.max(1, extraAttempted);
        int succeeded = Math.max(1, extraSucceeded);
        int failed = 0;
        List<String> failureReasons = new ArrayList<>();
        RiskLevel priorLevel = RiskLevel.SAFE;
        DetectionStatus priorStatus = DetectionStatus.NORMAL;
        int priorScore = 0;
        boolean priorInformational = true;

        if (priorResult != null) {
            if (priorResult.getExecutionStatus() != DetectionExecutionStatus.UNAVAILABLE
                    && priorResult.getExecutionStatus() != DetectionExecutionStatus.ERROR) {
                mergedDetails.addAll(priorResult.getDetails());
            }
            mergedItems.addAll(priorResult.getEvidenceItems());
            attempted = priorResult.getChecksAttempted() + Math.max(1, extraAttempted);
            succeeded = priorResult.getChecksSucceeded() + Math.max(1, extraSucceeded);
            failed = priorResult.getChecksFailed();
            failureReasons.addAll(priorResult.getFailureReasons());
            priorLevel = priorResult.getRiskLevel();
            priorStatus = priorResult.getStatus();
            priorScore = priorResult.getScore();
            priorInformational = priorResult.isInformational();
        }

        mergedDetails.addAll(newStrongTokens);
        mergedDetails.addAll(newMediumTokens);
        mergedItems.addAll(newItems);
        List<String> detailList = new ArrayList<>(mergedDetails);

        RiskLevel targetLevel;
        DetectionStatus targetStatus;
        int targetScore;
        boolean targetInformational;
        if (!newStrongTokens.isEmpty()) {
            targetLevel = priorLevel.getValue() >= RiskLevel.HIGH.getValue() ? priorLevel : RiskLevel.HIGH;
            targetStatus = DetectionStatus.DANGER;
            targetScore = Math.max(priorScore, 8);
            targetInformational = false;
        } else {
            // Hardware-confirmed unlock / orange boot: actionable MEDIUM/5 in STANDARD
            // (elevates to HIGH/7 in LOGIN/PAYMENT via CorrelationEngine.applyScene).
            targetLevel = priorLevel.getValue() >= RiskLevel.MEDIUM.getValue() ? priorLevel : RiskLevel.MEDIUM;
            targetStatus = targetLevel.getValue() >= RiskLevel.HIGH.getValue()
                    ? DetectionStatus.DANGER
                    : (priorStatus == DetectionStatus.DANGER ? DetectionStatus.DANGER : DetectionStatus.WARNING);
            targetScore = Math.max(priorScore, 5);
            targetInformational = false;
        }
        if (!priorInformational) {
            targetInformational = false;
        }

        DetectionExecutionStatus execStatus = failed > 0
                ? DetectionExecutionStatus.PARTIAL
                : DetectionExecutionStatus.RISK;

        return new DetectionResult(
                getName(),
                targetLevel,
                targetStatus,
                targetScore,
                10,
                targetInformational,
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

    static boolean hasConfirmedBootloaderRisk(Set<String> signals) {
        return signals.contains("bootloader_unlocked")
                || signals.contains("verified_boot_state:orange")
                || signals.contains("verified_boot_state:red");
    }

    /**
     * Checks partition build fingerprints in a Treble-aware way.
     */
    private void checkPartitionFingerprints(Set<String> strong,
                                            Set<String> weak,
                                            List<EvidenceItem> items,
                                            CheckCoverage coverage) {
        try {
            Map<String, String> values = new LinkedHashMap<>();
            for (String property : DetectionLists.PARTITION_FINGERPRINT_PROPERTIES) {
                // build_bootimage_prop is SELinux neverallow for untrusted_app on API 33+.
                if (Build.VERSION.SDK_INT >= 33
                        && "ro.bootimage.build.fingerprint".equals(property)) {
                    continue;
                }
                SignalResult<String> value = signals.getSystemProperty(property);
                if (!value.isSuccess() || value.getValue() == null
                        || value.getValue().isBlank()) {
                    continue;
                }
                values.put(property, value.getValue().trim());
            }
            if (values.size() < 2) {
                coverage.failure("partition_fingerprints:insufficient_sources");
                return;
            }
            coverage.success();

            String primary = values.get("ro.build.fingerprint");
            String system = values.get("ro.system.build.fingerprint");
            if (primary != null && system != null && !primary.equals(system)
                    && isBuildVsSystemFingerprintTamper(primary, system)) {
                strong.add("partition_fingerprint_mismatch:build_vs_system");
                items.add(new EvidenceItem(
                        "partition_fingerprint_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "ro.build.fingerprint",
                        "build_vs_system",
                        FAMILY_PROP_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }

            Set<String> brandFamilies = new LinkedHashSet<>();
            Set<String> keyTypes = new LinkedHashSet<>();
            for (String fp : values.values()) {
                String rawBrand = extractFingerprintBrand(fp);
                if (!rawBrand.isEmpty() && !isSocReferencePartitionBrand(rawBrand)) {
                    brandFamilies.add(normalizeBrandFamily(rawBrand));
                }
                String lower = fp.toLowerCase(Locale.ROOT);
                if (lower.endsWith("/release-keys")) {
                    keyTypes.add("release-keys");
                } else if (lower.endsWith("/test-keys") || lower.endsWith("/dev-keys")) {
                    keyTypes.add("non-release-keys");
                }
            }
            if (brandFamilies.size() > 1) {
                String joined = String.join(",", brandFamilies);
                strong.add("partition_fingerprint_mismatch:brand_conflict=" + joined);
                items.add(new EvidenceItem(
                        "partition_fingerprint_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "partition_brands",
                        "brand_conflict=" + joined,
                        FAMILY_PROP_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
            if (keyTypes.size() > 1) {
                weak.add("partition_keytype_mismatch");
                items.add(new EvidenceItem(
                        "partition_keytype_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "partition_keytypes",
                        String.join(",", keyTypes),
                        FAMILY_PROP_TAMPER,
                        EvidenceItem.Rank.WEAK));
            }
        } catch (Exception e) {
            coverage.failure("partition_fingerprints:" + e.getClass().getSimpleName());
        }
    }

    /** Build fields must agree with the ro.product.* properties they derive from. */
    private void checkBuildAgainstProperties(Set<String> evidence,
                                             List<EvidenceItem> items,
                                             CheckCoverage coverage) {
        String[][] pairs = {
                {"ro.product.model", Build.MODEL},
                {"ro.product.brand", Build.BRAND},
                {"ro.product.device", Build.DEVICE},
                {"ro.product.manufacturer", Build.MANUFACTURER},
                {"ro.build.fingerprint", Build.FINGERPRINT},
        };
        int compared = 0;
        for (String[] pair : pairs) {
            SignalResult<String> value = signals.getSystemProperty(pair[0]);
            if (!value.isSuccess() || value.getValue() == null
                    || value.getValue().isBlank() || pair[1] == null) {
                continue;
            }
            compared++;
            if (!value.getValue().trim().equals(pair[1].trim())) {
                evidence.add("build_prop_mismatch:" + pair[0]);
                items.add(new EvidenceItem(
                        "build_prop_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        pair[0],
                        "build_vs_prop",
                        FAMILY_PROP_TAMPER,
                        EvidenceItem.Rank.STRONG));
            }
        }
        if (compared == 0) coverage.failure("build_props:no_readable_properties");
        else coverage.success();
    }

    /**
     * Core count consistency across Runtime, sysfs possible cores, and procfs.
     */
    private void checkCoreCount(Set<String> evidence,
                                List<EvidenceItem> items,
                                CheckCoverage coverage) {
        try {
            int runtime = Runtime.getRuntime().availableProcessors();
            int procfs = 0;
            SignalResult<String> cpuinfoResult = signals != null
                    ? signals.getTextFile("/proc/cpuinfo") : null;
            String cpuinfo = cpuinfoResult != null && cpuinfoResult.isSuccess()
                    ? cpuinfoResult.getValue() : null;
            if (cpuinfo != null && !cpuinfo.isEmpty()) {
                Matcher matcher = PROCESSOR_LINE.matcher(cpuinfo);
                while (matcher.find()) procfs++;
            }
            SignalResult<Integer> possibleResult = signals.getPossibleCpuCoreCount();
            int possible = possibleResult.isSuccess() && possibleResult.getValue() != null
                    ? possibleResult.getValue() : -1;

            if (possible <= 0 && procfs == 0) {
                coverage.failure("core_count:sysfs_and_cpuinfo_unavailable");
                return;
            }
            coverage.success();
            if (possible > 0) {
                if (runtime > possible || (procfs > 0 && procfs > possible)) {
                    String val = "runtime=" + runtime + ",procfs=" + procfs + ",possible=" + possible;
                    evidence.add("core_count_mismatch:" + val);
                    items.add(new EvidenceItem(
                            "core_count_mismatch",
                            EvidenceItem.SourceLayer.JAVA,
                            "/proc/cpuinfo",
                            val,
                            FAMILY_HW_SPOOF,
                            EvidenceItem.Rank.STRONG));
                }
            } else if (runtime > 0 && procfs > 0 && runtime > procfs) {
                String val = "runtime=" + runtime + ",procfs=" + procfs;
                evidence.add("core_count_mismatch:" + val);
                items.add(new EvidenceItem(
                        "core_count_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "/proc/cpuinfo",
                        val,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
        } catch (Exception e) {
            coverage.failure("core_count:" + e.getClass().getSimpleName());
        }
    }

    /** The primary ABI and the JVM's os.arch describe the same CPU. */
    private void checkAbiArch(Set<String> evidence,
                              List<EvidenceItem> items,
                              CheckCoverage coverage) {
        try {
            String[] abis = Build.SUPPORTED_ABIS;
            String osArch = System.getProperty("os.arch");
            if (abis == null || abis.length == 0 || osArch == null || osArch.isBlank()) {
                coverage.failure("abi_arch:unavailable");
                return;
            }
            coverage.success();
            String abi = abis[0].toLowerCase(Locale.ROOT);
            String arch = osArch.toLowerCase(Locale.ROOT);
            boolean armAbi = abi.contains("arm");
            boolean armArch = arch.contains("aarch") || arch.contains("arm");
            boolean x86Abi = abi.contains("x86");
            boolean x86Arch = arch.contains("x86") || arch.contains("i686")
                    || arch.contains("i386") || arch.contains("amd64");
            if ((armAbi && !armArch) || (x86Abi && !x86Arch)) {
                String val = "abi=" + abis[0] + ",os_arch=" + osArch;
                evidence.add("abi_arch_mismatch:" + val);
                items.add(new EvidenceItem(
                        "abi_arch_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "Build.SUPPORTED_ABIS",
                        val,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
            String[] abis64 = Build.SUPPORTED_64_BIT_ABIS;
            boolean claims64 = abis64 != null && abis64.length > 0;
            boolean primaryIs64 = abi.contains("64");
            if (primaryIs64 && !claims64) {
                String val = "primary=" + abis[0] + ",no_64bit_list";
                evidence.add("abi_64bit_mismatch:" + val);
                items.add(new EvidenceItem(
                        "abi_64bit_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "Build.SUPPORTED_64_BIT_ABIS",
                        val,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
        } catch (Exception e) {
            coverage.failure("abi_arch:" + e.getClass().getSimpleName());
        }
    }

    /** SDK_INT and VERSION.RELEASE must map to each other. */
    private void checkApiRelease(Set<String> evidence,
                                 List<EvidenceItem> items,
                                 CheckCoverage coverage) {
        try {
            int sdk = Build.VERSION.SDK_INT;
            String release = Build.VERSION.RELEASE;
            if (release == null || release.isBlank()) {
                coverage.failure("api_release:no_release");
                return;
            }
            int major;
            try {
                String head = release.split("\\.")[0];
                major = Integer.parseInt(head.trim());
            } catch (NumberFormatException e) {
                coverage.failure("api_release:unparseable_release");
                return;
            }
            int expected = expectedMajorFor(sdk);
            if (expected <= 0) {
                coverage.failure("api_release:unsupported_sdk_" + sdk);
                return;
            }
            coverage.success();
            if (major != expected) {
                String val = "sdk=" + sdk + ",release=" + release;
                evidence.add("api_release_mismatch:" + val);
                items.add(new EvidenceItem(
                        "api_release_mismatch",
                        EvidenceItem.SourceLayer.JAVA,
                        "Build.VERSION",
                        val,
                        FAMILY_PROP_TAMPER,
                        EvidenceItem.Rank.WEAK));
            }
        } catch (Exception e) {
            coverage.failure("api_release:" + e.getClass().getSimpleName());
        }
    }

    static int expectedMajorFor(int sdk) {
        if (sdk == 30) return 11;
        if (sdk == 31 || sdk == 32) return 12;
        if (sdk >= 33) return sdk - 20;
        return -1;
    }

    /** brand/product/device:version/id:type/tags is the required shape. */
    private void checkFingerprintShape(Set<String> evidence,
                                       List<EvidenceItem> items,
                                       CheckCoverage coverage) {
        try {
            String fingerprint = Build.FINGERPRINT;
            if (fingerprint == null || fingerprint.isBlank()) {
                coverage.failure("fingerprint_shape:absent");
                return;
            }
            coverage.success();
            long slashes = fingerprint.chars().filter(c -> c == '/').count();
            long colons = fingerprint.chars().filter(c -> c == ':').count();
            if (slashes < 3 || colons < 2) {
                evidence.add("fingerprint_malformed:" + fingerprint);
                items.add(new EvidenceItem(
                        "fingerprint_malformed",
                        EvidenceItem.SourceLayer.JAVA,
                        "Build.FINGERPRINT",
                        fingerprint,
                        FAMILY_PROP_TAMPER,
                        EvidenceItem.Rank.WEAK));
            }
            if (Build.BRAND != null && !Build.BRAND.isBlank()) {
                String fpBrand = extractFingerprintBrand(fingerprint);
                String buildFamily = normalizeBrandFamily(Build.BRAND);
                String fpFamily = normalizeBrandFamily(fpBrand);
                if (!fpBrand.isEmpty() && !isSocReferencePartitionBrand(fpBrand)
                        && !buildFamily.equals(fpFamily)) {
                    evidence.add("fingerprint_brand_mismatch:brand=" + Build.BRAND);
                    items.add(new EvidenceItem(
                            "fingerprint_brand_mismatch",
                            EvidenceItem.SourceLayer.JAVA,
                            "Build.FINGERPRINT",
                            "brand=" + Build.BRAND,
                            FAMILY_PROP_TAMPER,
                            EvidenceItem.Rank.WEAK));
                }
            }
        } catch (Exception e) {
            coverage.failure("fingerprint_shape:" + e.getClass().getSimpleName());
        }
    }

    /**
     * Verified boot state, /proc/bootconfig, /proc/cmdline, 21 Boot/AVB/Samsung Knox properties,
     * and VBMeta empty-input SHA-256/512 digest trap via {@link BootloaderProbe}.
     */
    private void checkVerifiedBoot(Set<String> strong,
                                   Set<String> mediumActionable,
                                   Set<String> weak,
                                   List<EvidenceItem> items,
                                   CheckCoverage coverage) {
        try {
            BootloaderProbe.FastResult fast = BootloaderProbe.evaluateFast(signals);
            strong.addAll(fast.getStrongTokens());
            mediumActionable.addAll(fast.getMediumActionableTokens());
            weak.addAll(fast.getWeakTokens());
            items.addAll(fast.getEvidenceItems());
            if (fast.isUsable()) {
                coverage.success();
            } else {
                coverage.failure("verified_boot:properties_unavailable");
            }
        } catch (Exception e) {
            CLog.e("Verified boot check failed", e);
            coverage.failure("verified_boot:" + e.getClass().getSimpleName());
        }
    }

    /**
     * Production release-keys devices do not ship kernels compiled from a
     * dirty git working tree ("-dirty" suffix in uname.release).
     */
    private void checkKernelRelease(Set<String> weak,
                                    List<EvidenceItem> items,
                                    CheckCoverage coverage) {
        try {
            String release = "";
            try {
                StructUtsname uts = Os.uname();
                if (uts != null && uts.release != null) {
                    release = uts.release;
                }
            } catch (Throwable ignored) {}
            if (release.isEmpty()) {
                SignalResult<String> nativeKernel = signals.getKernelInfo();
                if (nativeKernel.isSuccess() && nativeKernel.getValue() != null) {
                    release = nativeKernel.getValue();
                }
            }
            if (release.isEmpty()) {
                coverage.failure("kernel_release:unavailable");
                return;
            }
            coverage.success();
            String tags = Build.TAGS == null ? "" : Build.TAGS.toLowerCase(Locale.ROOT);
            if (tags.contains("release-keys")
                    && release.toLowerCase(Locale.ROOT).contains("-dirty")) {
                weak.add("kernel_dirty_on_release");
                items.add(new EvidenceItem(
                        "kernel_dirty_on_release",
                        EvidenceItem.SourceLayer.JAVA,
                        "uname.release",
                        release,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.WEAK));
            }
        } catch (Exception e) {
            coverage.failure("kernel_release:" + e.getClass().getSimpleName());
        }
    }

    /**
     * 3-source kernel consistency: cross-checks raw {@code __NR_uname},
     * {@code /proc/sys/kernel/{osrelease,version}} & {@code /proc/version}, and
     * Java {@code System.getProperty("os.version")} to catch SUSFS newuname /
     * set_uname spoofing.
     */
    private void checkThreeSourceKernelConsistency(Set<String> strong,
                                                   List<EvidenceItem> items,
                                                   CheckCoverage coverage) {
        try {
            SignalResult<String> raw = nativeSource.getKernelConsistency();
            if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
                coverage.failure("kernel_3source:native_unavailable");
                return;
            }
            NativePayloadCodec.DecodedPayload decoded =
                    NativePayloadCodec.decodePayload(raw.getValue());
            if (!decoded.isOk()) {
                coverage.failure("kernel_3source:" + decoded.getStatus().name().toLowerCase(Locale.ROOT));
                return;
            }

            String unameRel = trimOrEmpty(decoded.getHeaderField("uname_release"));
            String unameVer = trimOrEmpty(decoded.getHeaderField("uname_version"));
            String procOsRel = trimOrEmpty(decoded.getHeaderField("proc_osrelease"));
            String procKVer = trimOrEmpty(decoded.getHeaderField("proc_kversion"));
            String procVersion = trimOrEmpty(decoded.getHeaderField("proc_version"));
            String procVerRel = extractProcVersionRelease(procVersion);
            String javaOsVer = trimOrEmpty(nativeSource.getJavaOsVersion());

            int releaseSources = (unameRel.isEmpty() ? 0 : 1)
                    + (procOsRel.isEmpty() ? 0 : 1)
                    + (procVerRel.isEmpty() ? 0 : 1)
                    + (javaOsVer.isEmpty() ? 0 : 1);
            int versionSources = (unameVer.isEmpty() ? 0 : 1)
                    + (procKVer.isEmpty() ? 0 : 1)
                    + (procVersion.isEmpty() ? 0 : 1);
            if (releaseSources < 2 && versionSources < 2) {
                coverage.failure("kernel_3source:insufficient_sources");
                return;
            }
            coverage.success();

            if (!unameRel.isEmpty() && !procOsRel.isEmpty()
                    && !matchesUtsField(unameRel, procOsRel)) {
                strong.add("kernel_uname_osrelease_mismatch");
                items.add(new EvidenceItem(
                        "kernel_uname_osrelease_mismatch",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/proc/sys/kernel/osrelease",
                        "uname=" + unameRel + ",proc=" + procOsRel,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
            if (!unameRel.isEmpty() && !procVerRel.isEmpty()
                    && !matchesUtsField(unameRel, procVerRel)) {
                strong.add("kernel_uname_proc_version_mismatch");
                items.add(new EvidenceItem(
                        "kernel_uname_proc_version_mismatch",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/proc/version",
                        "uname=" + unameRel + ",proc_version=" + procVerRel,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
            if (!procOsRel.isEmpty() && !procVerRel.isEmpty()
                    && !procOsRel.equals(procVerRel)) {
                strong.add("kernel_proc_osrelease_version_mismatch");
                items.add(new EvidenceItem(
                        "kernel_proc_osrelease_version_mismatch",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/proc/sys/kernel/osrelease",
                        "osrelease=" + procOsRel + ",proc_version=" + procVerRel,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
            if (!javaOsVer.isEmpty()) {
                if (!unameRel.isEmpty() && !matchesUtsField(unameRel, javaOsVer)) {
                    strong.add("kernel_java_os_version_mismatch");
                    items.add(new EvidenceItem(
                            "kernel_java_os_version_mismatch",
                            EvidenceItem.SourceLayer.JAVA,
                            "os.version",
                            "java=" + javaOsVer + ",uname=" + unameRel,
                            FAMILY_HW_SPOOF,
                            EvidenceItem.Rank.STRONG));
                } else if (!procOsRel.isEmpty() && !matchesUtsField(javaOsVer, procOsRel)) {
                    strong.add("kernel_java_os_version_mismatch");
                    items.add(new EvidenceItem(
                            "kernel_java_os_version_mismatch",
                            EvidenceItem.SourceLayer.JAVA,
                            "os.version",
                            "java=" + javaOsVer + ",proc=" + procOsRel,
                            FAMILY_HW_SPOOF,
                            EvidenceItem.Rank.STRONG));
                }
            }
            if (!unameVer.isEmpty() && !procKVer.isEmpty()
                    && !matchesUtsField(unameVer, procKVer)) {
                strong.add("kernel_uname_kversion_mismatch");
                items.add(new EvidenceItem(
                        "kernel_uname_kversion_mismatch",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/proc/sys/kernel/version",
                        "uname_ver=" + unameVer + ",proc_ver=" + procKVer,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
            if (!unameVer.isEmpty() && !procVersion.isEmpty()
                    && !procVersion.contains(unameVer)) {
                strong.add("kernel_version_banner_mismatch");
                items.add(new EvidenceItem(
                        "kernel_version_banner_mismatch",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/proc/version",
                        "uname_ver=" + unameVer,
                        FAMILY_HW_SPOOF,
                        EvidenceItem.Rank.STRONG));
            }
        } catch (Exception e) {
            coverage.failure("kernel_3source:" + e.getClass().getSimpleName());
        }
    }

    /** Integrates Bionic /dev/__properties__ binary forensics into consistency. */
    private void checkBionicPropArea(Set<String> strong,
                                     Set<String> mediumActionable,
                                     List<EvidenceItem> items,
                                     CheckCoverage coverage) {
        try {
            BionicPropProbe.ProbeResult res = BionicPropProbe.probe(signals);
            if (!res.isUsable()) {
                coverage.failure("bionic_prop_area:"
                        + res.getStatus().name().toLowerCase(Locale.ROOT));
                return;
            }
            coverage.success();
            for (EvidenceItem item : res.getEvidenceItems()) {
                items.add(item);
                String token = item.getCode() + ":" + stripPropPrefix(item.getLocation());
                if (item.getRank() == EvidenceItem.Rank.STRONG) {
                    strong.add(token);
                } else if (item.getRank() == EvidenceItem.Rank.MEDIUM) {
                    mediumActionable.add(token);
                }
            }
        } catch (Exception e) {
            coverage.failure("bionic_prop_area:" + e.getClass().getSimpleName());
        }
    }

    /** Integrates PlayIntegrityFix / PixelProps property & maps forensics into consistency. */
    private void checkPlayIntegrityFix(Set<String> strong,
                                       Set<String> mediumActionable,
                                       Set<String> weak,
                                       List<EvidenceItem> items,
                                       CheckCoverage coverage) {
        try {
            PlayIntegrityFixProbe.ProbeResult res = PlayIntegrityFixProbe.probe(
                    signals, nativeSource.getPifProperties());
            if (!res.isUsable()) {
                coverage.failure("play_integrity_fix:unavailable");
                return;
            }
            coverage.success();
            strong.addAll(res.getStrongTokens());
            mediumActionable.addAll(res.getMediumTokens());
            weak.addAll(res.getWeakTokens());
            items.addAll(res.getEvidenceItems());
        } catch (Exception e) {
            coverage.failure("play_integrity_fix:" + e.getClass().getSimpleName());
        }
    }

    static boolean matchesUtsField(String utsVal, String otherVal) {
        if (utsVal.equals(otherVal)) {
            return true;
        }
        if (otherVal.length() > UTS_FIELD_MAX_LEN) {
            if (utsVal.length() == UTS_FIELD_MAX_LEN && otherVal.startsWith(utsVal)) {
                return true;
            }
            if (otherVal.substring(0, UTS_FIELD_MAX_LEN).trim().equals(utsVal)) {
                return true;
            }
        }
        return false;
    }

    static String extractProcVersionRelease(String procVersion) {
        if (procVersion == null || procVersion.isEmpty()) {
            return "";
        }
        String prefix = "Linux version ";
        int idx = procVersion.indexOf(prefix);
        if (idx < 0) {
            return "";
        }
        int start = idx + prefix.length();
        int end = start;
        while (end < procVersion.length() && !Character.isWhitespace(procVersion.charAt(end))) {
            end++;
        }
        return end > start ? procVersion.substring(start, end) : "";
    }

    static String extractFingerprintBrand(String fp) {
        if (fp == null || fp.isEmpty()) return "";
        int slash = fp.indexOf('/');
        return slash > 0 ? fp.substring(0, slash).trim().toLowerCase(Locale.ROOT) : "";
    }

    static String normalizeBrandFamily(String rawBrand) {
        if (rawBrand == null || rawBrand.isBlank()) return "";
        String b = rawBrand.trim().toLowerCase(Locale.ROOT);
        switch (b) {
            case "xiaomi":
            case "redmi":
            case "poco":
            case "blackshark":
                return "xiaomi";
            case "oppo":
            case "oneplus":
            case "realme":
            case "oplus":
                return "oppo";
            case "vivo":
            case "iqoo":
                return "vivo";
            case "huawei":
            case "honor":
                return "huawei";
            case "tecno":
            case "infinix":
            case "itel":
            case "transsion":
                return "transsion";
            case "zte":
            case "nubia":
            case "redmagic":
                return "zte";
            case "motorola":
            case "lenovo":
                return "lenovo";
            default:
                return b;
        }
    }

    static boolean isSocReferencePartitionBrand(String rawBrand) {
        if (rawBrand == null || rawBrand.isBlank()) return false;
        String b = rawBrand.trim().toLowerCase(Locale.ROOT);
        return "qti".equals(b)
                || "qualcomm".equals(b)
                || "mediatek".equals(b)
                || "mtk".equals(b)
                || "sprd".equals(b)
                || "unisoc".equals(b)
                || "android".equals(b);
    }

    /**
     * Treble / MISSI / QSSI-aware comparison between {@code ro.build.fingerprint} and
     * {@code ro.system.build.fingerprint}. Stock OEM single-system images (Xiaomi MISSI,
     * Qualcomm QSSI, MediaTek MSSI/VSSI, Samsung ESSI, OPPO OSSI) legitimately differ in
     * product/device/build-id from the device-level {@code ro.build.fingerprint}. Only flag
     * cross-OEM brand conflicts or incompatible Android major releases / release-vs-test-keys.
     */
    static boolean isBuildVsSystemFingerprintTamper(String primaryFp, String systemFp) {
        String primaryBrand = extractFingerprintBrand(primaryFp);
        String systemBrand = extractFingerprintBrand(systemFp);
        if (!primaryBrand.isEmpty() && !systemBrand.isEmpty()
                && !isSocReferencePartitionBrand(primaryBrand)
                && !isSocReferencePartitionBrand(systemBrand)
                && !normalizeBrandFamily(primaryBrand).equals(normalizeBrandFamily(systemBrand))) {
            return true;
        }
        String primaryMajor = extractFingerprintReleaseMajor(primaryFp);
        String systemMajor = extractFingerprintReleaseMajor(systemFp);
        if (!primaryMajor.isEmpty() && !systemMajor.isEmpty()
                && !primaryMajor.equals(systemMajor)) {
            return true;
        }
        return false;
    }

    private static String extractFingerprintReleaseMajor(String fp) {
        if (fp == null || fp.isEmpty()) return "";
        int colon = fp.indexOf(':');
        if (colon < 0 || colon + 1 >= fp.length()) return "";
        int slash = fp.indexOf('/', colon + 1);
        if (slash <= colon + 1) return "";
        String rel = fp.substring(colon + 1, slash).trim();
        int dot = rel.indexOf('.');
        String major = dot > 0 ? rel.substring(0, dot) : rel;
        for (int i = 0; i < major.length(); i++) {
            if (!Character.isDigit(major.charAt(i))) {
                return "";
            }
        }
        return major;
    }

    private static String stripPropPrefix(String location) {
        if (location == null) return "";
        String prefix = "/dev/__properties__/";
        return location.startsWith(prefix) ? location.substring(prefix.length()) : location;
    }

    private static String trimOrEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private static String nonBlankLower(SignalResult<String> result) {
        if (result == null || !result.isSuccess() || result.getValue() == null) return "";
        return result.getValue().trim().toLowerCase(Locale.ROOT);
    }

    private static String lowerOrEmpty(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
