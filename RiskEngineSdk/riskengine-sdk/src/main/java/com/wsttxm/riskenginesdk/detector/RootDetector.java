package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ShellExecutor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class RootDetector extends BaseDetector {

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
        super(context);
    }

    @Override
    public String getName() {
        return "root";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();

        // Check su binary paths
        for (String path : SU_PATHS) {
            if (new File(path).exists()) {
                evidence.add("su_found:" + path);
            }
        }

        // Check Magisk paths
        for (String path : MAGISK_PATHS) {
            if (new File(path).exists()) {
                evidence.add("magisk_found:" + path);
            }
        }

        // Check SELinux status
        try {
            String enforcing = ShellExecutor.execute("getenforce");
            if (enforcing != null && enforcing.trim().equalsIgnoreCase("Permissive")) {
                evidence.add("selinux_permissive");
            }
        } catch (Exception e) {
            CLog.e("SELinux check failed", e);
        }

        // Native root check
        try {
            if (NativeCollectorBridge.nativeCheckRoot()) {
                String nativeEvidence = NativeCollectorBridge.nativeGetRootEvidence();
                if (nativeEvidence != null && !nativeEvidence.isEmpty()) {
                    evidence.add("native:" + nativeEvidence);
                }
            }
        } catch (Exception e) {
            CLog.e("Native root check failed", e);
        }

        // Check build tags
        String tags = android.os.Build.TAGS;
        if (tags != null && tags.contains("test-keys")) {
            evidence.add("test_keys");
        }

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.HIGH, String.join("; ", evidence));
        }
        return safe();
    }
}
