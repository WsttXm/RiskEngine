package com.wsttxm.riskenginesdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Pluggable digest function used by {@code FingerprintIdBuilder}.
 *
 * <p>The default {@link #SHA256} implementation encodes inputs strictly as UTF-8 and formats
 * the 32-byte digest as a fixed 64-character lowercase zero-padded hexadecimal string.
 */
@FunctionalInterface
public interface FingerprintHasher {

    /** Default UTF-8 SHA-256 hasher producing fixed 64-char zero-padded lowercase hex. */
    FingerprintHasher SHA256 = FingerprintHasher::sha256Utf8;

    String hash(String data);

    static String sha256Utf8(String value) {
        if (value == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                hex.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                hex.append(Character.forDigit(item & 0x0f, 16));
            }
            return hex.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
