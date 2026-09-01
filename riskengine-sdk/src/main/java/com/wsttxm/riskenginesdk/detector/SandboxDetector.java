package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Process;

import com.wsttxm.riskenginesdk.generated.DetectionLists;
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
        List<String> strong = new ArrayList<>();
        List<String> weak = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        if (checkFdCount(weak)) coverage.success();
        else coverage.failure("procfs_fd_unavailable");
        if (checkDataDir(strong)) coverage.success();
        else coverage.failure("data_dir_unavailable");
        if (checkClassLoader(strong)) coverage.success();
        else coverage.failure("classloader_unavailable");
        if (checkPackages(strong)) coverage.success();
        else coverage.failure("packages_unavailable");

        List<String> evidence = new ArrayList<>(strong);
        evidence.addAll(weak);
        if (!strong.isEmpty()) {
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (!weak.isEmpty()) {
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    evidence, String.join("; ", evidence), coverage);
        }
        return safe(coverage);
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
                }
            }
            return true;
        } catch (Exception e) {
            CLog.e("FD check failed", e);
            return false;
        }
    }

    private boolean checkDataDir(List<String> evidence) {
        try {
            ApplicationInfo info = context.getApplicationInfo();
            String dataDir = info.dataDir == null ? "" : info.dataDir.toLowerCase(Locale.ROOT);
            String pkg = context.getPackageName();
            int appId = Process.myUid() % 100000;
            String expected = "/data/user/0/" + pkg;
            String expectedId = "/data/user/" + appId + "/" + pkg;
            if ((dataDir.contains("virtual") || dataDir.contains("parallel")
                    || dataDir.contains("plugin"))
                    && !dataDir.equals(expected) && !dataDir.equals(expectedId)) {
                evidence.add("virtual_data_dir");
            }
            if (!dataDir.isEmpty() && pkg != null && !dataDir.contains(pkg)
                    && (dataDir.contains("virtual") || dataDir.contains("parallel"))) {
                evidence.add("uid_datadir_mismatch");
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkClassLoader(List<String> evidence) {
        try {
            String name = context.getClassLoader().getClass().getName().toLowerCase(Locale.ROOT);
            if (name.contains("virtualapp") || name.contains("lody")
                    || name.contains("parallel") || name.contains("dual")) {
                evidence.add("virtual_classloader:" + name);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkPackages(List<String> evidence) {
        try {
            PackageManager pm = context.getPackageManager();
            for (String pkg : DetectionLists.SANDBOX_PACKAGES) {
                try {
                    pm.getPackageInfo(pkg, 0);
                    evidence.add("sandbox_pkg:" + pkg);
                } catch (PackageManager.NameNotFoundException ignored) {}
            }
            return true;
        } catch (Exception e) {
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
