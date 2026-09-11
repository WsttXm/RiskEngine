package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.os.Build;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Collects CPU topology from sysfs and procfs.
 *
 * Two purposes. As a fingerprint dimension, the core-cluster frequency layout
 * and the implementer/part distribution are hardware-bound. As a consistency
 * input, the core count is read from three independent places so a spoofed
 * value in one of them shows up as a contradiction rather than being trusted.
 */
public class CpuTopologyCollector extends BaseCollector {
    private static final Pattern PROCESSOR_LINE = Pattern.compile("^processor\\s*:", Pattern.MULTILINE);
    private static final Pattern IMPLEMENTER = Pattern.compile("CPU implementer\\s*:\\s*(\\S+)");
    private static final Pattern PART = Pattern.compile("CPU part\\s*:\\s*(\\S+)");

    public CpuTopologyCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "cpu_topology";
    }

    @Override
    protected void collect(CollectorResult result) {
        try {
            result.addValue("runtime_processors",
                    String.valueOf(Runtime.getRuntime().availableProcessors()));

            int sysfsCores = countSysfsCores();
            if (sysfsCores > 0) {
                result.addValue("sysfs_cores", String.valueOf(sysfsCores));
            }

            String cpuinfo = ProcfsUtils.readFile("/proc/cpuinfo");
            if (cpuinfo != null && !cpuinfo.isEmpty()) {
                Matcher processorMatcher = PROCESSOR_LINE.matcher(cpuinfo);
                int procCount = 0;
                while (processorMatcher.find()) procCount++;
                if (procCount > 0) {
                    result.addValue("cpuinfo_processors", String.valueOf(procCount));
                }
                addDistribution(result, cpuinfo);
            }

            collectFrequencies(result, sysfsCores > 0 ? sysfsCores : 8);

            result.addValue("supported_abis", String.join(",", Build.SUPPORTED_ABIS));
            String[] abis64 = Build.SUPPORTED_64_BIT_ABIS;
            result.addValue("has_64bit_abi", String.valueOf(abis64 != null && abis64.length > 0));
            String osArch = System.getProperty("os.arch");
            if (osArch != null && !osArch.isBlank()) {
                result.addValue("os_arch", osArch);
            }
            if (Build.SOC_MODEL != null && !Build.SOC_MODEL.isBlank()) {
                result.addValue("soc_model", Build.SOC_MODEL);
            }
            if (Build.SOC_MANUFACTURER != null && !Build.SOC_MANUFACTURER.isBlank()) {
                result.addValue("soc_manufacturer", Build.SOC_MANUFACTURER);
            }
        } catch (Exception e) {
            CLog.e("CPU topology collection failed", e);
            result.markError(e);
        }
    }

    private static int countSysfsCores() {
        try {
            File dir = new File("/sys/devices/system/cpu");
            File[] entries = dir.listFiles();
            if (entries == null) return -1;
            int count = 0;
            for (File entry : entries) {
                String name = entry.getName();
                if (name.length() > 3 && name.startsWith("cpu")
                        && Character.isDigit(name.charAt(3))) {
                    boolean allDigits = true;
                    for (int i = 3; i < name.length(); i++) {
                        if (!Character.isDigit(name.charAt(i))) {
                            allDigits = false;
                            break;
                        }
                    }
                    if (allDigits) count++;
                }
            }
            return count;
        } catch (Exception e) {
            return -1;
        }
    }

    /** Records the implementer|part multiset, which encodes the big.LITTLE layout. */
    private static void addDistribution(CollectorResult result, String cpuinfo) {
        List<String> pairs = new ArrayList<>();
        Matcher impl = IMPLEMENTER.matcher(cpuinfo);
        Matcher part = PART.matcher(cpuinfo);
        while (impl.find() && part.find()) {
            pairs.add(impl.group(1) + "|" + part.group(1));
        }
        if (pairs.isEmpty()) return;
        Collections.sort(pairs);
        result.addValue("core_distribution", String.join(",", pairs));
    }

    /**
     * Reads per-core min/max scaling frequencies. Distinct clusters are a
     * hardware fact; a flat set of identical frequencies across all cores is
     * typical of emulators and server-hosted cloud instances.
     */
    private static void collectFrequencies(CollectorResult result, int cores) {
        List<String> ranges = new ArrayList<>();
        for (int i = 0; i < Math.min(cores, 16); i++) {
            String min = ProcfsUtils.readFirstLine(
                    "/sys/devices/system/cpu/cpu" + i + "/cpufreq/cpuinfo_min_freq");
            String max = ProcfsUtils.readFirstLine(
                    "/sys/devices/system/cpu/cpu" + i + "/cpufreq/cpuinfo_max_freq");
            if (min == null || max == null || min.isBlank() || max.isBlank()) continue;
            ranges.add(min.trim() + "-" + max.trim());
        }
        if (ranges.isEmpty()) return;
        result.addValue("freq_ranges", String.join(",", ranges));
        long distinct = ranges.stream().distinct().count();
        result.addValue("distinct_freq_clusters", String.valueOf(distinct));
        result.addValue("uniform_frequencies",
                String.valueOf(distinct == 1 && ranges.size() > 2).toLowerCase(Locale.ROOT));
    }
}
