package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.List;

public class RootDetector extends BaseDetector {
    private final SignalSnapshot signals;

    private static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su", "/apex/com.android.runtime/bin/su"
    };

    private static final String[] MAGISK_PATHS = {
            "/sbin/.magisk", "/data/adb/magisk",
            "/data/adb/magisk.db", "/data/adb/modules",
            "/cache/.disable_magisk"
    };

    public RootDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public RootDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "root";
    }

    @Override
    protected DetectionResult detect() {
        List<String> strongEvidence = new ArrayList<>();
        List<String> weakEvidence = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        // Check su binary paths
        try {
            boolean pathsAvailable = true;
            for (String path : SU_PATHS) {
                SignalResult<Boolean> exists = signals.getPathExists(path);
                if (!exists.isSuccess()) pathsAvailable = false;
                if (Boolean.TRUE.equals(exists.getValue())) {
                    strongEvidence.add("su_found:" + path);
                }
            }
            if (pathsAvailable) coverage.success();
            else coverage.failure("su_paths:access_failed");
        } catch (SecurityException e) {
            coverage.failure("su_paths:" + e.getClass().getSimpleName());
        }

        // Check Magisk paths
        try {
            boolean pathsAvailable = true;
            for (String path : MAGISK_PATHS) {
                SignalResult<Boolean> exists = signals.getPathExists(path);
                if (!exists.isSuccess()) pathsAvailable = false;
                if (Boolean.TRUE.equals(exists.getValue())) {
                    strongEvidence.add("magisk_found:" + path);
                }
            }
            if (pathsAvailable) coverage.success();
            else coverage.failure("magisk_paths:access_failed");
        } catch (SecurityException e) {
            coverage.failure("magisk_paths:" + e.getClass().getSimpleName());
        }

        // Check SELinux status
        com.wsttxm.riskenginesdk.util.ShellExecutor.Result selinux =
                signals.getShellResult("getenforce");
        if (selinux.isSuccess()) {
            coverage.success();
            if (selinux.getStdout().trim().equalsIgnoreCase("Permissive")) {
                weakEvidence.add("selinux_permissive");
            }
        } else {
            coverage.failure("selinux:" + selinux.getStatus());
        }

        // Native root check
        SignalResult<Boolean> nativeRoot = NativeCollectorBridge.checkRootResult();
        if (nativeRoot.isSuccess() && nativeRoot.getValue() != null) {
            coverage.success();
            if (nativeRoot.getValue()) {
                SignalResult<String> nativeDetails = NativeCollectorBridge.getRootEvidenceResult();
                if (nativeDetails.isSuccess() && nativeDetails.getValue() != null
                        && !nativeDetails.getValue().isEmpty()) {
                    strongEvidence.add("native:" + nativeDetails.getValue());
                } else {
                    strongEvidence.add("native:root_check_positive");
                }
            }
        } else {
            coverage.failure("native_root:" + nativeRoot.getFailureReason());
        }

        // Check build tags
        try {
            String tags = android.os.Build.TAGS;
            if (tags != null && tags.contains("test-keys")) {
                weakEvidence.add("test_keys");
            }
            coverage.success();
        } catch (RuntimeException e) {
            coverage.failure("build_tags:" + e.getClass().getSimpleName());
        }

        List<String> allEvidence = new ArrayList<>(strongEvidence);
        allEvidence.addAll(weakEvidence);
        if (!strongEvidence.isEmpty()) {
            return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    allEvidence, String.join("; ", allEvidence), coverage);
        }
        if (!weakEvidence.isEmpty()) {
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    weakEvidence, String.join("; ", weakEvidence), coverage);
        }
        return safe(coverage);
    }
}
