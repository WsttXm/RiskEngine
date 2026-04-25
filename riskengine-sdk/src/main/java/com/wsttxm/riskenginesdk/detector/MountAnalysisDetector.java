package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

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

        checkMounts(evidence);
        checkMountInfo(evidence);

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.MEDIUM, String.join("; ", evidence));
        }
        return safe();
    }

    private void checkMounts(List<String> evidence) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/mounts"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                // Magisk overlay
                if (lower.contains("magisk") || lower.contains("tmpfs /system") ||
                        lower.contains("tmpfs /vendor")) {
                    evidence.add("magisk_mount:" + line.trim());
                }
                // Docker/container markers
                if (lower.contains("docker") || lower.contains("overlay") && lower.contains("lowerdir")) {
                    if (lower.contains("/docker/")) {
                        evidence.add("docker_mount:" + line.trim());
                    }
                }
                // Check for bind mounts on system partitions (common in modification frameworks)
                if (lower.contains("/data/adb/modules")) {
                    evidence.add("module_mount:" + line.trim());
                }
            }
        } catch (Exception e) {
            CLog.e("Mount check failed", e);
        }
    }

    private void checkMountInfo(List<String> evidence) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/mountinfo"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("magisk") || line.contains("core/mirror")) {
                    evidence.add("mountinfo:" + line.trim());
                    break;
                }
            }
        } catch (Exception e) {
            CLog.e("MountInfo check failed", e);
        }
    }
}
