package com.wsttxm.riskenginesdk.util;

import java.util.Locale;

/**
 * Strips Android random Base64/Base64URL installation tokens from package paths
 * (e.g. {@code /data/app/~~<22-24B>==/<pkg>-<22-24B>==/base.apk}) before
 * substring/artifact matching so random tokens containing sequences like
 * {@code ksu}, {@code Riru}, or {@code va} never trigger false positives.
 */
public final class InstallTokenSanitizer {
    private static final int MIN_TILDE_TOKEN_LEN = 16;
    private static final int MAX_TILDE_TOKEN_LEN = 32;
    private static final int MIN_SUFFIX_TOKEN_LEN = 20;
    private static final int MAX_SUFFIX_TOKEN_LEN = 32;

    private InstallTokenSanitizer() {}

    /**
     * Strips Android install-time random Base64 tokens from path segments while
     * preserving the canonical directory hierarchy and package names.
     */
    public static String stripInstallTokens(String path) {
        if (path == null || path.isEmpty()) {
            return path == null ? "" : "";
        }
        String[] segments = path.split("/", -1);
        StringBuilder out = new StringBuilder(path.length());
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                out.append('/');
            }
            out.append(sanitizeSegment(segments[i]));
        }
        return out.toString();
    }

    /**
     * Extracts the application package name from a {@code /data/app/.../*.apk}
     * path after stripping install tokens, or returns {@code null} if the path
     * does not belong to a user-installed application APK.
     */
    public static String extractDataAppApkPackage(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return null;
        }
        String clean = stripInstallTokens(rawPath.trim());
        if (!clean.toLowerCase(Locale.ROOT).endsWith(".apk")) {
            return null;
        }
        if (!clean.startsWith("/data/app/")) {
            return null;
        }
        String rest = clean.substring("/data/app/".length());
        String[] parts = rest.split("/");
        if (parts.length < 2) {
            return null;
        }
        int pkgIndex = "~~".equals(parts[0]) ? 1 : 0;
        if (pkgIndex >= parts.length - 1) {
            return null;
        }
        String candidate = parts[pkgIndex];
        return isLikelyPackageName(candidate) ? candidate : null;
    }

    /**
     * Extracts the top-level package directory owned under {@code /data/user/<uId>/<pkg>},
     * {@code /data/user_de/<uId>/<pkg>}, or {@code /data/data/<pkg>}.
     */
    public static String extractDataOwnerPackage(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return null;
        }
        String clean = stripInstallTokens(rawPath.trim());
        String[] parts = clean.split("/");
        // parts[0] == "" for leading '/'
        if (parts.length >= 5 && "data".equals(parts[1])
                && ("user".equals(parts[2]) || "user_de".equals(parts[2]))
                && isAllDigits(parts[3])) {
            return isLikelyPackageName(parts[4]) ? parts[4] : null;
        }
        if (parts.length >= 4 && "data".equals(parts[1]) && "data".equals(parts[2])) {
            return isLikelyPackageName(parts[3]) ? parts[3] : null;
        }
        return null;
    }

    private static String sanitizeSegment(String segment) {
        if (segment == null || segment.isEmpty()) {
            return "";
        }
        // Android 11+ outer random directory: ~~<22-24 char base64url>==
        if (segment.startsWith("~~")) {
            String token = segment.substring(2);
            if (isBase64Token(token, MIN_TILDE_TOKEN_LEN, MAX_TILDE_TOKEN_LEN)) {
                return "~~";
            }
        }
        // Package directory with appended random token: <pkg>-<22-24 char base64url>==
        // Package names use [A-Za-z0-9_.] and contain at least one '.', never '-'.
        int dash = segment.indexOf('-');
        if (dash > 0 && dash < segment.length() - 1) {
            String prefix = segment.substring(0, dash);
            String suffix = segment.substring(dash + 1);
            if (isLikelyPackageName(prefix)
                    && isBase64Token(suffix, MIN_SUFFIX_TOKEN_LEN, MAX_SUFFIX_TOKEN_LEN)) {
                return prefix;
            }
        }
        return segment;
    }

    private static boolean isBase64Token(String token, int minLen, int maxLen) {
        int len = token.length();
        if (len < minLen || len > maxLen) {
            return false;
        }
        int eqSeen = 0;
        for (int i = 0; i < len; i++) {
            char c = token.charAt(i);
            if (c == '=') {
                eqSeen++;
                if (eqSeen > 2) {
                    return false;
                }
                continue;
            }
            if (eqSeen > 0) {
                return false;
            }
            boolean valid = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '+' || c == '-' || c == '_';
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    public static boolean isLikelyPackageName(String value) {
        if (value == null || value.length() < 3 || value.indexOf('.') <= 0) {
            return false;
        }
        if (value.startsWith(".") || value.endsWith(".")) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '.' || c == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAllDigits(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }
}
