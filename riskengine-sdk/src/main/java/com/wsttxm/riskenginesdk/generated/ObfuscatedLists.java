package com.wsttxm.riskenginesdk.generated;

import java.nio.charset.StandardCharsets;

/**
 * Decodes obfuscated artifact strings at runtime.
 *
 * The native mirror of these lists is compiled with a per-site rolling
 * keystream, but that hardening was pointless while the Java copy sat in the
 * DEX as plain string constants: an analyst could read every path, package and
 * property the SDK looks for by running {@code strings} on the classes.dex.
 *
 * The scheme here is deliberately modest and its limit is worth stating: this
 * raises the cost of a casual {@code strings} sweep, it does not defeat an
 * analyst who reads this decoder and replays it. Real protection for a list
 * would mean keeping it only in native, which is the longer-term direction.
 * The values still have to reach Java to drive PackageManager and Settings
 * lookups, so they cannot be native-only today.
 */
final class ObfuscatedLists {
    private ObfuscatedLists() {}

    /**
     * Rolling xorshift keystream keyed per array, matching the native side's
     * construction so the two mirrors stay conceptually identical.
     */
    static String[] decode(int seed, String[] encoded) {
        String[] out = new String[encoded.length];
        for (int i = 0; i < encoded.length; i++) {
            out[i] = decodeOne(seed + i, encoded[i]);
        }
        return out;
    }

    private static String decodeOne(int seed, String encoded) {
        byte[] raw = hexToBytes(encoded);
        int state = mix(seed * 0x01000193 ^ (raw.length * 0x9E3779B9));
        byte[] plain = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) {
            state = mix(state);
            plain[i] = (byte) (raw[i] ^ (byte) (state & 0xFF));
        }
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static int mix(int value) {
        value ^= value << 13;
        value ^= value >>> 17;
        value ^= value << 5;
        return value == 0 ? 0x9E3779B9 : value;
    }

    private static byte[] hexToBytes(String hex) {
        int length = hex.length() / 2;
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** Encodes a value with this scheme. Used by the generator test only. */
    static String encodeOne(int seed, String plain) {
        byte[] raw = plain.getBytes(StandardCharsets.UTF_8);
        int state = mix(seed * 0x01000193 ^ (raw.length * 0x9E3779B9));
        StringBuilder hex = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            state = mix(state);
            int enc = (b ^ (byte) (state & 0xFF)) & 0xFF;
            hex.append(Character.forDigit((enc >>> 4) & 0x0F, 16));
            hex.append(Character.forDigit(enc & 0x0F, 16));
        }
        return hex.toString();
    }
}
