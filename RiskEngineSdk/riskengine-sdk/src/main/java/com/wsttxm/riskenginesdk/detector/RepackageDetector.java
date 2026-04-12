package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class RepackageDetector extends BaseDetector {

    private String expectedSignature;

    public RepackageDetector(Context context) {
        super(context);
    }

    public void setExpectedSignature(String sha256Hex) {
        this.expectedSignature = sha256Hex;
    }

    @Override
    public String getName() {
        return "repackage";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();

        // Java-level signature check
        String javaSig = getJavaSignature();

        // Native-level signature check (reads APK directly via SVC)
        String nativeSig = null;
        try {
            String apkPath = context.getApplicationInfo().sourceDir;
            nativeSig = NativeCollectorBridge.nativeVerifyApkSignature(apkPath);
        } catch (Exception e) {
            CLog.e("Native signature check failed", e);
        }

        // Cross-validate Java vs Native
        if (javaSig != null && nativeSig != null && !javaSig.equals(nativeSig)) {
            evidence.add("signature_mismatch:java=" + javaSig + ",native=" + nativeSig);
        }

        // Validate against expected signature
        if (expectedSignature != null && javaSig != null && !expectedSignature.equals(javaSig)) {
            evidence.add("unexpected_signature:" + javaSig);
        }

        // Check CREATOR classloader
        try {
            ClassLoader cl = Signature.class.getClassLoader();
            if (cl != null && !cl.getClass().getName().contains("BootClassLoader")) {
                evidence.add("creator_classloader_tampered:" + cl.getClass().getName());
            }
        } catch (Exception ignored) {}

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.DEADLY, String.join("; ", evidence));
        }
        return safe();
    }

    private String getJavaSignature() {
        try {
            PackageInfo pi = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            if (pi.signatures != null && pi.signatures.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(pi.signatures[0].toByteArray());
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }
                return sb.toString();
            }
        } catch (Exception e) {
            CLog.e("Java signature failed", e);
        }
        return null;
    }
}
