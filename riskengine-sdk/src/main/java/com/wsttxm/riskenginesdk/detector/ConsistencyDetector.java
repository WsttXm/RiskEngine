package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.os.Build;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cross-source self-consistency checks.
 *
 * Every check here compares two or more independent readings of the same fact.
 * This is deliberately different from the signature-matching detectors: it
 * needs no blocklist and does not go stale, because it finds the contradictions
 * a spoofing tool leaves behind rather than recognising the tool itself. A
 * device-modification app that rewrites Build.MODEL but not the vendor
 * partition fingerprint, or that reports eight cores to the framework while
 * procfs shows four, fails here regardless of how new it is.
 */
public class ConsistencyDetector extends BaseDetector {
    private static final Pattern PROCESSOR_LINE =
            Pattern.compile("^processor\\s*:", Pattern.MULTILINE);
    private final SignalSnapshot signals;

    public ConsistencyDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "consistency";
    }

    @Override
    protected DetectionResult detect() {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> weak = new LinkedHashSet<>();
        CheckCoverage coverage = new CheckCoverage();

        checkPartitionFingerprints(strong, coverage);
        checkBuildAgainstProperties(strong, coverage);
        checkCoreCount(strong, coverage);
        checkAbiArch(strong, coverage);
        checkApiRelease(weak, coverage);
        checkFingerprintShape(weak, coverage);
        checkVerifiedBoot(weak, coverage);

        List<String> evidence = new ArrayList<>(strong);
        evidence.addAll(weak);
        if (!strong.isEmpty()) {
            return result(RiskLevel.HIGH, DetectionStatus.DANGER, 7, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (!weak.isEmpty()) {
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 2, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        }
        return safe(coverage);
    }

    /**
     * All partition fingerprints on an unmodified device describe the same
     * build. Spoofing tools rewrite the primary one and miss the rest.
     */
    private void checkPartitionFingerprints(Set<String> evidence, CheckCoverage coverage) {
        try {
            Set<String> distinct = new LinkedHashSet<>();
            int readable = 0;
            for (String property : DetectionLists.PARTITION_FINGERPRINT_PROPERTIES) {
                SignalResult<String> value = signals.getSystemProperty(property);
                if (!value.isSuccess() || value.getValue() == null
                        || value.getValue().isBlank()) {
                    continue;
                }
                readable++;
                distinct.add(value.getValue().trim());
            }
            if (readable < 2) {
                coverage.failure("partition_fingerprints:insufficient_sources");
                return;
            }
            coverage.success();
            if (distinct.size() > 1) {
                evidence.add("partition_fingerprint_mismatch:" + distinct.size()
                        + "_variants_across_" + readable + "_partitions");
            }
        } catch (Exception e) {
            coverage.failure("partition_fingerprints:" + e.getClass().getSimpleName());
        }
    }

    /** Build fields must agree with the ro.product.* properties they derive from. */
    private void checkBuildAgainstProperties(Set<String> evidence, CheckCoverage coverage) {
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
            }
        }
        if (compared == 0) coverage.failure("build_props:no_readable_properties");
        else coverage.success();
    }

    /**
     * Core count from the framework, sysfs and procfs. The framework value is
     * the one a hook would change; the other two require more effort.
     */
    private void checkCoreCount(Set<String> evidence, CheckCoverage coverage) {
        try {
            int runtime = Runtime.getRuntime().availableProcessors();
            int procfs = 0;
            String cpuinfo = ProcfsUtils.readFile("/proc/cpuinfo");
            if (cpuinfo != null && !cpuinfo.isEmpty()) {
                Matcher matcher = PROCESSOR_LINE.matcher(cpuinfo);
                while (matcher.find()) procfs++;
            }
            if (procfs == 0) {
                coverage.failure("core_count:cpuinfo_unavailable");
                return;
            }
            coverage.success();
            if (runtime > 0 && procfs > 0 && runtime != procfs) {
                evidence.add("core_count_mismatch:runtime=" + runtime + ",procfs=" + procfs);
            }
        } catch (Exception e) {
            coverage.failure("core_count:" + e.getClass().getSimpleName());
        }
    }

    /** The primary ABI and the JVM's os.arch describe the same CPU. */
    private void checkAbiArch(Set<String> evidence, CheckCoverage coverage) {
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
                evidence.add("abi_arch_mismatch:abi=" + abis[0] + ",os_arch=" + osArch);
            }
            // A 64-bit ABI list must be consistent with the primary ABI.
            String[] abis64 = Build.SUPPORTED_64_BIT_ABIS;
            boolean claims64 = abis64 != null && abis64.length > 0;
            boolean primaryIs64 = abi.contains("64");
            if (primaryIs64 && !claims64) {
                evidence.add("abi_64bit_mismatch:primary=" + abis[0] + ",no_64bit_list");
            }
        } catch (Exception e) {
            coverage.failure("abi_arch:" + e.getClass().getSimpleName());
        }
    }

    /** SDK_INT and VERSION.RELEASE must map to each other. */
    private void checkApiRelease(Set<String> evidence, CheckCoverage coverage) {
        try {
            int sdk = Build.VERSION.SDK_INT;
            String release = Build.VERSION.RELEASE;
            if (release == null || release.isBlank()) {
                coverage.failure("api_release:no_release");
                return;
            }
            coverage.success();
            int major;
            try {
                String head = release.split("\\.")[0];
                major = Integer.parseInt(head.trim());
            } catch (NumberFormatException e) {
                return;
            }
            int expected = expectedMajorFor(sdk);
            if (expected > 0 && major != expected) {
                evidence.add("api_release_mismatch:sdk=" + sdk + ",release=" + release);
            }
        } catch (Exception e) {
            coverage.failure("api_release:" + e.getClass().getSimpleName());
        }
    }

    private static int expectedMajorFor(int sdk) {
        switch (sdk) {
            case 30: return 11;
            case 31:
            case 32: return 12;
            case 33: return 13;
            case 34: return 14;
            case 35: return 15;
            case 36: return 16;
            default: return -1;
        }
    }

    /** brand/product/device:version/id:type/tags is the required shape. */
    private void checkFingerprintShape(Set<String> evidence, CheckCoverage coverage) {
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
            }
            if (Build.BRAND != null && !Build.BRAND.isBlank()
                    && !fingerprint.toLowerCase(Locale.ROOT)
                    .startsWith(Build.BRAND.toLowerCase(Locale.ROOT) + "/")) {
                evidence.add("fingerprint_brand_mismatch:brand=" + Build.BRAND);
            }
        } catch (Exception e) {
            coverage.failure("fingerprint_shape:" + e.getClass().getSimpleName());
        }
    }

    /**
     * Verified boot state. Recorded as informational: an unlocked bootloader is
     * a legitimate developer choice, not proof of compromise on its own.
     */
    private void checkVerifiedBoot(Set<String> evidence, CheckCoverage coverage) {
        try {
            SignalResult<String> state = signals.getSystemProperty("ro.boot.verifiedbootstate");
            SignalResult<String> locked = signals.getSystemProperty("ro.boot.flash.locked");
            boolean any = false;
            if (state.isSuccess() && state.getValue() != null && !state.getValue().isBlank()) {
                any = true;
                String value = state.getValue().trim().toLowerCase(Locale.ROOT);
                if (!"green".equals(value)) {
                    evidence.add("verified_boot_state:" + value);
                }
            }
            if (locked.isSuccess() && locked.getValue() != null && !locked.getValue().isBlank()) {
                any = true;
                if ("0".equals(locked.getValue().trim())) {
                    evidence.add("bootloader_unlocked");
                }
            }
            if (any) coverage.success();
            else coverage.failure("verified_boot:properties_unavailable");
        } catch (Exception e) {
            CLog.e("Verified boot check failed", e);
            coverage.failure("verified_boot:" + e.getClass().getSimpleName());
        }
    }
}
