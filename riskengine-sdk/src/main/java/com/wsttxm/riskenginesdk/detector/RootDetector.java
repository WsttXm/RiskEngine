package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.List;

public class RootDetector extends BaseDetector {
    private final SignalSnapshot signals;

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
        List<String> mediumEvidence = new ArrayList<>();
        List<String> weakEvidence = new ArrayList<>();
        CheckCoverage coverage = new CheckCoverage();

        probePaths("su_found:", DetectionLists.SU_PATHS, strongEvidence, coverage, "su_paths");
        probePaths("magisk_found:", DetectionLists.MAGISK_PATHS, strongEvidence, coverage, "magisk_paths");
        probePaths("ksu_found:", DetectionLists.KERNELSU_PATHS, strongEvidence, coverage, "ksu_paths");
        probePaths("apatch_found:", DetectionLists.APATCH_PATHS, strongEvidence, coverage, "apatch_paths");
        probePaths("modules_found:", DetectionLists.MODULE_PATHS, strongEvidence, coverage, "module_paths");

        SignalResult<Integer> selinux = signals.getSelinuxEnforce();
        if (selinux.isSuccess() && selinux.getValue() != null) {
            coverage.success();
            if (selinux.getValue() == 0) {
                weakEvidence.add("selinux_permissive");
            }
        } else {
            coverage.failure("selinux:" + selinux.getFailureReason());
        }

        SignalResult<Boolean> nativeRoot = NativeCollectorBridge.checkRootResult();
        if (nativeRoot.isSuccess() && nativeRoot.getValue() != null) {
            coverage.success();
            SignalResult<String> nativeDetails = NativeCollectorBridge.getRootEvidenceResult();
            if (nativeDetails.isSuccess() && nativeDetails.getValue() != null
                    && !nativeDetails.getValue().isEmpty()) {
                for (String token : nativeDetails.getValue().split(",")) {
                    String item = token.trim();
                    if (item.isEmpty()) continue;
                    if (item.startsWith("syscall_mismatch")) {
                        mediumEvidence.add("native:" + item);
                    } else if (item.equals("selinux_permissive")) {
                        if (!weakEvidence.contains(item)) weakEvidence.add(item);
                    } else {
                        strongEvidence.add("native:" + item);
                    }
                }
            } else if (Boolean.TRUE.equals(nativeRoot.getValue())) {
                strongEvidence.add("native:root_check_positive");
            }
        } else {
            coverage.failure("native_root:" + nativeRoot.getFailureReason());
        }

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
        allEvidence.addAll(mediumEvidence);
        allEvidence.addAll(weakEvidence);
        if (!strongEvidence.isEmpty()) {
            return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    allEvidence, String.join("; ", allEvidence), coverage);
        }
        if (!mediumEvidence.isEmpty()) {
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    allEvidence, String.join("; ", allEvidence), coverage);
        }
        if (!weakEvidence.isEmpty()) {
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    weakEvidence, String.join("; ", weakEvidence), coverage);
        }
        return safe(coverage);
    }

    private void probePaths(String prefix, String[] paths, List<String> strong,
                            CheckCoverage coverage, String failureKey) {
        try {
            boolean pathsAvailable = true;
            for (String path : paths) {
                SignalResult<Boolean> exists = signals.getPathExists(path);
                if (!exists.isSuccess()) pathsAvailable = false;
                if (Boolean.TRUE.equals(exists.getValue())) {
                    strong.add(prefix + path);
                }
            }
            if (pathsAvailable) coverage.success();
            else coverage.failure(failureKey + ":access_failed");
        } catch (SecurityException e) {
            coverage.failure(failureKey + ":" + e.getClass().getSimpleName());
        }
    }
}
