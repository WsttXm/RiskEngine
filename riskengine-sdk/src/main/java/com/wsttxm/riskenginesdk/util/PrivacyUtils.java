package com.wsttxm.riskenginesdk.util;

import android.content.Context;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class PrivacyUtils {
    private PrivacyUtils() {}

    /** Returns a per-application, non-reversible representation of an identifier. */
    public static String hashIdentifier(Context context, String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String scope = context == null ? "riskengine" : context.getPackageName();
            byte[] bytes = digest.digest(
                    (scope + ":" + value).getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                hex.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                hex.append(Character.forDigit(item & 0x0f, 16));
            }
            return hex.toString();
        } catch (Exception e) {
            CLog.e("Identifier hashing failed", e);
            return "";
        }
    }
}
