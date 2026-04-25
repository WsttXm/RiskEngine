package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.security.MessageDigest;

public class ApkSignatureCollector extends BaseCollector {

    public ApkSignatureCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "apk_signature";
    }

    @Override
    protected void collect(CollectorResult result) {
        collectViaPackageManager(result);
        collectViaClassLoaderCheck(result);
    }

    private void collectViaPackageManager(CollectorResult result) {
        try {
            PackageInfo pi = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            if (pi.signatures != null && pi.signatures.length > 0) {
                Signature sig = pi.signatures[0];
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(sig.toByteArray());
                result.addValue("pm_sha256", bytesToHex(digest));
            }
        } catch (Exception e) {
            CLog.e("ApkSignature pm failed", e);
        }
    }

    private void collectViaClassLoaderCheck(CollectorResult result) {
        try {
            // Check if Signature class CREATOR is loaded by BootClassLoader
            ClassLoader cl = Signature.class.getClassLoader();
            String loaderName = cl != null ? cl.getClass().getName() : "null";
            // BootClassLoader is expected; PathClassLoader indicates tampering
            boolean isBootLoader = loaderName.contains("BootClassLoader");
            result.addValue("creator_classloader", loaderName);
            result.addValue("creator_valid", String.valueOf(isBootLoader));
        } catch (Exception e) {
            CLog.e("ApkSignature classloader check failed", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
