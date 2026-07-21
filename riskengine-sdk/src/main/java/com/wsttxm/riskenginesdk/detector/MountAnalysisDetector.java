package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MountAnalysisDetector extends BaseDetector {

    public MountAnalysisDetector(Context context) {
        super(context);
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

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.MEDIUM, String.join("; ", evidence));
        }
        if (!mountsAvailable && !mountInfoAvailable) {
            return unavailable("procfs_mounts_unavailable");
        }
        return safe();
    }

    private boolean checkMounts(List<String> evidence) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/mounts"))) {
            String line;
            while ((line = br.readLine()) != null) {
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
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/mountinfo"))) {
            String line;
            while ((line = br.readLine()) != null) {
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
