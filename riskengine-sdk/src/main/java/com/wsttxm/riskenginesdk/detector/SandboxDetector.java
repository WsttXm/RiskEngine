package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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

        boolean fdInspectionAvailable = checkFdCount(evidence);

        if (!evidence.isEmpty()) {
            // A virtualized path is useful context, but one path alone is not
            // proof that the current app is executing inside a sandbox.
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence));
        }
        if (!fdInspectionAvailable) {
            return unavailable("procfs_fd_unavailable");
        }
        return safe();
    }

    private boolean checkFdCount(List<String> evidence) {
        try {
            File fdDir = new File("/proc/self/fd");
            File[] fds = fdDir.listFiles();
            if (fds == null) {
                return false;
            }
            for (File fd : fds) {
                try {
                    String marker = findVirtualizationMarker(
                            fd.getCanonicalPath().toLowerCase(Locale.ROOT));
                    if (marker != null) {
                        evidence.add("virtualized_fd:" + marker);
                        break;
                    }
                } catch (Exception ignored) {
                    // Descriptors can disappear while being inspected.
                }
            }
            return true;
        } catch (Exception e) {
            CLog.e("FD check failed", e);
            return false;
        }
    }

    private String findVirtualizationMarker(String path) {
        String[] markers = {
                "/virtual-app/",
                "/virtual/data/",
                "parallel_space",
                "/dualspace/",
                "com.lbe.parallel",
                "com.excelliance.dualaid",
                "com.parallel.space"
        };
        for (String marker : markers) {
            if (path.contains(marker)) {
                return marker;
            }
        }
        return null;
    }

}
