package com.wsttxm.riskenginesdk.detector;

/**
 * Sentinel class intentionally omitted from {@code consumer-rules.pro} so host
 * R8/ProGuard builds rename it in release artifacts. If its runtime simple name
 * remains unchanged on a non-debuggable build, the host likely shipped without
 * code shrinking/obfuscation enabled.
 */
final class ObfuscationSentinel {
    private ObfuscationSentinel() {}

    static boolean isObfuscated() {
        String expected = buildExpectedSimpleName();
        String actual = ObfuscationSentinel.class.getSimpleName();
        return !expected.equals(actual);
    }

    /**
     * Built dynamically at runtime so R8 identifier-name-string rewriting cannot
     * rewrite the literal alongside the renamed sentinel class.
     */
    private static String buildExpectedSimpleName() {
        StringBuilder sb = new StringBuilder(19);
        sb.append("Obfusc");
        sb.append("ation");
        sb.append("Senti");
        sb.append("nel");
        return sb.toString();
    }
}
