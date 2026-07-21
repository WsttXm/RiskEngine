package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo signingInfo = info.signingInfo;
            if (signingInfo == null) {
                return;
            }
            Signature[] signatures = signingInfo.hasMultipleSigners()
                    ? signingInfo.getApkContentsSigners()
                    : signingInfo.getSigningCertificateHistory();
            List<String> hashes = new ArrayList<>();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Signature signature : signatures) {
                hashes.add(bytesToHex(digest.digest(signature.toByteArray())));
            }
            Collections.sort(hashes);
            if (!hashes.isEmpty()) {
                result.addValue("signing_cert_sha256", String.join(",", hashes));
            }
        } catch (Exception e) {
            CLog.e("APK signature collection failed", e);
            result.markError(e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder output = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) {
            output.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            output.append(Character.forDigit(item & 0x0f, 16));
        }
        return output.toString();
    }
}
