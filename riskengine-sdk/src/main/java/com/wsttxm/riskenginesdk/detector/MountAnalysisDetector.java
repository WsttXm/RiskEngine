package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MountAnalysisDetector extends BaseDetector {
    private final SignalSnapshot signals;

    public MountAnalysisDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public MountAnalysisDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "mount_analysis";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();

        boolean mountsAvailable = checkMounts(evidence);
        boolean mountInfoAvailable = checkMountInfo(evidence);
        CheckCoverage coverage = new CheckCoverage();
        if (mountsAvailable) coverage.success();
        else coverage.failure("proc_mounts_unavailable");
        if (mountInfoAvailable) coverage.success();
        else coverage.failure("proc_mountinfo_unavailable");

        if (!evidence.isEmpty()) {
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (!mountsAvailable && !mountInfoAvailable) {
            return unavailable("procfs_mounts_unavailable");
        }
        return safe(coverage);
    }

    private boolean checkMounts(List<String> evidence) {
        try {
            SignalResult<String> mounts = signals.getTextFile("/proc/mounts");
            if (!mounts.isSuccess() || mounts.getValue() == null) return false;
            for (String line : mounts.getValue().split("\\n")) {
                String lower = line.toLowerCase(Locale.ROOT);
                // Magisk overlay
                if (lower.contains("magisk") || lower.contains("tmpfs /system") ||
                        lower.contains("tmpfs /vendor")) {
                    addUnique(evidence, "magisk_mount");
                }
                // Docker/container markers
                if (lower.contains("docker") || lower.contains("overlay") && lower.contains("lowerdir")) {
                    if (lower.contains("/docker/")) {
                        addUnique(evidence, "docker_mount");
                    }
                }
                // Check for bind mounts on system partitions (common in modification frameworks)
                if (lower.contains("/data/adb/modules")) {
                    addUnique(evidence, "module_mount");
                }
            }
            return true;
        } catch (Exception e) {
            CLog.e("Mount check failed", e);
            return false;
        }
    }

    private boolean checkMountInfo(List<String> evidence) {
        try {
            SignalResult<String> mountInfo = signals.getTextFile("/proc/self/mountinfo");
            if (!mountInfo.isSuccess() || mountInfo.getValue() == null) return false;
            for (String line : mountInfo.getValue().split("\\n")) {
                if (line.contains("magisk") || line.contains("core/mirror")) {
                    addUnique(evidence, "mountinfo:magisk");
                    break;
                }
            }
            return true;
        } catch (Exception e) {
            CLog.e("MountInfo check failed", e);
            return false;
        }
    }

    private void addUnique(List<String> evidence, String signal) {
        if (!evidence.contains(signal)) {
            evidence.add(signal);
        }
    }
}
