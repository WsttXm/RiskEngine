package com.wsttxm.riskenginesdk.detector;

import android.app.ActivityManager;
import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class SandboxDetector extends BaseDetector {

    public SandboxDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "sandbox";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();

        checkProcessCount(evidence);
        checkFdCount(evidence);
        checkMultiUser(evidence);

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.HIGH, String.join("; ", evidence));
        }
        return safe();
    }

    private void checkProcessCount(List<String> evidence) {
        try {
            File procDir = new File("/proc");
            File[] files = procDir.listFiles();
            int processCount = 0;
            if (files != null) {
                for (File f : files) {
                    if (f.isDirectory()) {
                        try {
                            Integer.parseInt(f.getName());
                            processCount++;
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            // Sandbox environments typically have very few processes
            if (processCount > 0 && processCount < 50) {
                evidence.add("low_process_count:" + processCount);
            }
        } catch (Exception e) {
            CLog.e("Process count check failed", e);
        }
    }

    private void checkFdCount(List<String> evidence) {
        try {
            File fdDir = new File("/proc/self/fd");
            File[] fds = fdDir.listFiles();
            if (fds != null) {
                for (File fd : fds) {
                    try {
                        String link = fd.getCanonicalPath();
                        // Check for suspicious fd targets
                        if (link.contains("virtual-app") || link.contains("sandbox") ||
                                link.contains("parallel") || link.contains("dual")) {
                            evidence.add("suspicious_fd:" + link);
                            break;
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            CLog.e("FD check failed", e);
        }
    }

    private void checkMultiUser(List<String> evidence) {
        try {
            int uid = android.os.Process.myUid();
            int userId = uid / 100000;
            if (userId != 0) {
                evidence.add("non_primary_user:" + userId);
            }
        } catch (Exception e) {
            CLog.e("Multi-user check failed", e);
        }
    }
}
