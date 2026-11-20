package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.os.Build;
import android.system.Os;
import android.system.StructUtsname;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

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
 * behind by spoofing tools (such as resetprop or Build hooks) while avoiding
 * false positives on stock Treble OEM devices and dynamic CPU hotplugging.
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

        checkPartitionFingerprints(strong, weak, coverage);
        checkBuildAgainstProperties(strong, coverage);
        checkCoreCount(strong, coverage);
        checkAbiArch(strong, coverage);
        checkApiRelease(weak, coverage);
        checkFingerprintShape(weak, coverage);
        checkVerifiedBoot(strong, weak, coverage);
        checkKernelRelease(weak, coverage);

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
     * Checks partition build fingerprints in a Treble-aware way.
     *
     * On Project Treble / GKI OEM devices, vendor/odm partitions legitimately
     * carry a different build ID or date than system after an OTA. What does
     * not legitimately diverge is:
     * 1. ro.build.fingerprint vs ro.system.build.fingerprint;
     * 2. the leading brand across partitions (cross-brand spoofing);
     * 3. release-keys vs test-keys across partitions.
     */
    private void checkPartitionFingerprints(Set<String> strong, Set<String> weak,
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
            if (primary != null && system != null && !primary.equals(system)) {
                strong.add("partition_fingerprint_mismatch:build_vs_system");
            }

            Set<String> brands = new LinkedHashSet<>();
            Set<String> keyTypes = new LinkedHashSet<>();
            for (String fp : values.values()) {
                int slash = fp.indexOf('/');
                if (slash > 0) {
                    brands.add(fp.substring(0, slash).toLowerCase(Locale.ROOT));
                }
                String lower = fp.toLowerCase(Locale.ROOT);
                if (lower.endsWith("/release-keys")) {
                    keyTypes.add("release-keys");
                } else if (lower.endsWith("/test-keys") || lower.endsWith("/dev-keys")) {
                    keyTypes.add("non-release-keys");
                }
            }
            if (brands.size() > 1) {
                strong.add("partition_fingerprint_mismatch:brand_conflict="
                        + String.join(",", brands));
            }
            if (keyTypes.size() > 1) {
                weak.add("partition_keytype_mismatch");
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
     * Core count consistency across Runtime, sysfs possible cores, and procfs.
     *
     * Thermal throttling or power saving legitimately takes cores offline so
     * runtime < possible is normal. What is physically impossible without
     * spoofing is runtime > possible or procfs > possible.
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
                    evidence.add("core_count_mismatch:runtime=" + runtime
                            + ",procfs=" + procfs + ",possible=" + possible);
                }
            } else if (runtime > 0 && procfs > 0 && runtime > procfs) {
                // Without sysfs possible upper bound, only flag runtime exceeding procfs.
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
                evidence.add("api_release_mismatch:sdk=" + sdk + ",release=" + release);
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
     * Verified boot state plus cross-check against raw /proc/cmdline boot
     * parameters to catch resetprop spoofing of ro.boot.* properties.
     */
    private void checkVerifiedBoot(Set<String> strong, Set<String> weak, CheckCoverage coverage) {
        try {
            SignalResult<String> state = signals.getSystemProperty("ro.boot.verifiedbootstate");
            SignalResult<String> locked = signals.getSystemProperty("ro.boot.flash.locked");
            SignalResult<String> vbmeta = signals.getSystemProperty("ro.boot.vbmeta.digest");
            SignalResult<Map<String, String>> cmdline = signals.getProcCmdlineBootProps();

            boolean any = false;
            String propState = nonBlankLower(state);
            if (!propState.isEmpty()) {
                any = true;
                if (!"green".equals(propState)) {
                    weak.add("verified_boot_state:" + propState);
                }
            }
            String propLocked = nonBlankLower(locked);
            if (!propLocked.isEmpty()) {
                any = true;
                if ("0".equals(propLocked)) {
                    weak.add("bootloader_unlocked");
                }
            }
            String propVbmeta = nonBlankLower(vbmeta);

            if (cmdline.isSuccess() && cmdline.getValue() != null && !cmdline.getValue().isEmpty()) {
                any = true;
                Map<String, String> boot = cmdline.getValue();
                String cmdState = lowerOrEmpty(boot.get("androidboot.verifiedbootstate"));
                if (!cmdState.isEmpty() && !propState.isEmpty() && !cmdState.equals(propState)) {
                    strong.add("cmdline_prop_mismatch:verifiedbootstate");
                } else if (!cmdState.isEmpty() && !"green".equals(cmdState) && propState.isEmpty()) {
                    weak.add("verified_boot_state:" + cmdState);
                }

                String cmdLocked = lowerOrEmpty(boot.get("androidboot.flash.locked"));
                if (!cmdLocked.isEmpty() && !propLocked.isEmpty() && !cmdLocked.equals(propLocked)) {
                    strong.add("cmdline_prop_mismatch:flash_locked");
                } else if ("0".equals(cmdLocked) && propLocked.isEmpty()) {
                    weak.add("bootloader_unlocked");
                }

                String cmdVbmeta = lowerOrEmpty(boot.get("androidboot.vbmeta.digest"));
                if (!cmdVbmeta.isEmpty() && !propVbmeta.isEmpty() && !cmdVbmeta.equals(propVbmeta)) {
                    strong.add("cmdline_prop_mismatch:vbmeta_digest");
                }
            }

            // On Android 16+ / userdebug AVDs ro.boot.verifiedbootstate & flash.locked
            // may legitimately be empty while /proc/cmdline is SELinux-restricted.
            // Treat an error-free empty read as covered rather than a false gap.
            boolean propsQueriedCleanly = state.getStatus() == SignalResult.Status.EMPTY
                    || locked.getStatus() == SignalResult.Status.EMPTY
                    || state.isSuccess() || locked.isSuccess();
            if (any || propsQueriedCleanly) coverage.success();
            else coverage.failure("verified_boot:properties_unavailable");
        } catch (Exception e) {
            CLog.e("Verified boot check failed", e);
            coverage.failure("verified_boot:" + e.getClass().getSimpleName());
        }
    }

    /**
     * Production release-keys devices do not ship kernels compiled from a
     * dirty git working tree ("-dirty" suffix in uname.release). KernelSU and
     * custom-boot builds frequently leave "-dirty" in uname while spoofing
     * ro.build.tags=release-keys and ro.boot.verifiedbootstate=green.
     */
    private void checkKernelRelease(Set<String> weak, CheckCoverage coverage) {
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
            }
        } catch (Exception e) {
            coverage.failure("kernel_release:" + e.getClass().getSimpleName());
        }
    }

    private static String nonBlankLower(SignalResult<String> result) {
        if (result == null || !result.isSuccess() || result.getValue() == null) return "";
        return result.getValue().trim().toLowerCase(Locale.ROOT);
    }

    private static String lowerOrEmpty(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
