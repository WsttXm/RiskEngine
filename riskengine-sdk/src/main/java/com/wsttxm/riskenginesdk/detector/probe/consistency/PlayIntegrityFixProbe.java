package com.wsttxm.riskenginesdk.detector.probe.consistency;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.util.InstallTokenSanitizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Internal probe inside {@code consistency} that detects PlayIntegrityFix /
 * PixelProps spoofing modules via:
 * <ol>
 *   <li>Bionic properties ({@code persist.sys.pihooks*}, {@code persist.sys.pixelprops*},
 *       {@code persist.sys.spoof.gms});</li>
 *   <li>{@link InstallTokenSanitizer}-cleaned {@code /proc/self/maps} runtime loader traces.</li>
 * </ol>
 */
public final class PlayIntegrityFixProbe {

    public static final String EVIDENCE_FAMILY = "prop_tamper";

    private static final String[] CANONICAL_PIF_PROPERTIES = {
            "persist.sys.pihooks.enable",
            "persist.sys.pihooks.disable.gms_props",
            "persist.sys.pihooks.disable.gms_key_attestation_block",
            "persist.sys.pixelprops.gms",
            "persist.sys.pixelprops.pi",
            "persist.sys.spoof.gms"
    };

    private static final String[] MAPS_NEEDLES = {
            "playintegrity",
            "integrityfix",
            "pihooks",
            "pixelprops"
    };

    private PlayIntegrityFixProbe() {}

    /** Immutable outcome of a PlayIntegrityFix probe pass. */
    public static final class ProbeResult {
        private final boolean usable;
        private final List<String> strongTokens;
        private final List<String> mediumTokens;
        private final List<String> weakTokens;
        private final List<EvidenceItem> evidenceItems;

        ProbeResult(boolean usable,
                    List<String> strongTokens,
                    List<String> mediumTokens,
                    List<String> weakTokens,
                    List<EvidenceItem> evidenceItems) {
            this.usable = usable;
            this.strongTokens = Collections.unmodifiableList(strongTokens);
            this.mediumTokens = Collections.unmodifiableList(mediumTokens);
            this.weakTokens = Collections.unmodifiableList(weakTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public boolean isUsable() { return usable; }
        public List<String> getStrongTokens() { return strongTokens; }
        public List<String> getMediumTokens() { return mediumTokens; }
        public List<String> getWeakTokens() { return weakTokens; }
        public List<EvidenceItem> getEvidenceItems() { return evidenceItems; }
        public boolean hasStrong() { return !strongTokens.isEmpty(); }
        public boolean hasMedium() { return !mediumTokens.isEmpty(); }
        public boolean hasAny() { return !evidenceItems.isEmpty(); }
    }

    /** Runs the probe from a native property payload plus {@code signals} maps/properties. */
    public static ProbeResult probe(SignalSnapshot signals, SignalResult<String> nativePifProps) {
        boolean usable = false;
        Map<String, String> propHits = new LinkedHashMap<>();

        if (nativePifProps != null && nativePifProps.isSuccess()
                && nativePifProps.getValue() != null && !nativePifProps.getValue().isEmpty()) {
            NativePayloadCodec.DecodedPayload decoded =
                    NativePayloadCodec.decodePayload(nativePifProps.getValue());
            if (decoded.isOk()) {
                usable = true;
                for (Map<String, String> rec : decoded.getRecords()) {
                    if (!"pif_prop".equals(rec.get("kind"))) {
                        continue;
                    }
                    String key = rec.get("key");
                    String val = rec.get("value");
                    if (isPifPropertyKey(key) && val != null && !val.isBlank()) {
                        propHits.putIfAbsent(key.trim(), val.trim());
                    }
                }
            }
        }

        // Also check seeded properties in SignalSnapshot (useful for JVM tests and fallback).
        if (signals != null) {
            for (String key : CANONICAL_PIF_PROPERTIES) {
                SignalResult<String> res = signals.getSystemProperty(key);
                if (res != null && res.isSuccess() && res.getValue() != null
                        && !res.getValue().isBlank()) {
                    usable = true;
                    propHits.putIfAbsent(key, res.getValue().trim());
                }
            }
        }

        List<String> mapLines = null;
        if (signals != null) {
            SignalResult<List<String>> maps = signals.getSanitizedSelfMaps();
            if (maps != null && maps.isSuccess() && maps.getValue() != null) {
                usable = true;
                mapLines = maps.getValue();
            }
        }

        return evaluate(usable, propHits, mapLines);
    }

    /** Pure evaluation entrypoint for deterministic unit tests. */
    public static ProbeResult evaluate(boolean usable,
                                       Map<String, String> pifProperties,
                                       List<String> rawOrSanitizedMapsLines) {
        if (!usable) {
            return new ProbeResult(false,
                    Collections.emptyList(), Collections.emptyList(),
                    Collections.emptyList(), Collections.emptyList());
        }

        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        Set<String> weak = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        if (pifProperties != null) {
            for (Map.Entry<String, String> entry : pifProperties.entrySet()) {
                String key = entry.getKey();
                String val = entry.getValue();
                if (!isPifPropertyKey(key) || val == null || val.isBlank()) {
                    continue;
                }
                String trimmedKey = key.trim();
                String trimmedVal = val.trim();
                String lowerKey = trimmedKey.toLowerCase(Locale.ROOT);
                String lowerVal = trimmedVal.toLowerCase(Locale.ROOT);

                boolean isDisableFlag = lowerKey.contains("disable");
                boolean isTruthy = "1".equals(lowerVal) || "true".equals(lowerVal);
                boolean isFalsy = "0".equals(lowerVal) || "false".equals(lowerVal);

                if (isDisableFlag && isTruthy) {
                    String token = "pif_prop_present:" + trimmedKey;
                    if (medium.add(token)) {
                        items.add(new EvidenceItem(
                                "pif_prop_present",
                                EvidenceItem.SourceLayer.NATIVE,
                                trimmedKey,
                                trimmedVal,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                    }
                } else if (!isDisableFlag && isFalsy) {
                    String token = "pif_prop_disabled:" + trimmedKey;
                    if (weak.add(token)) {
                        items.add(new EvidenceItem(
                                "pif_prop_disabled",
                                EvidenceItem.SourceLayer.NATIVE,
                                trimmedKey,
                                trimmedVal,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.WEAK));
                    }
                } else {
                    String token = "pif_prop_active:" + trimmedKey;
                    if (strong.add(token)) {
                        items.add(new EvidenceItem(
                                "pif_prop_active",
                                EvidenceItem.SourceLayer.NATIVE,
                                trimmedKey,
                                trimmedVal,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.STRONG));
                    }
                }
            }
        }

        if (rawOrSanitizedMapsLines != null) {
            Set<String> seenPaths = new LinkedHashSet<>();
            for (String line : rawOrSanitizedMapsLines) {
                if (line == null || line.isBlank()) {
                    continue;
                }
                String path = extractMappedPath(line);
                if (path.isEmpty()) {
                    continue;
                }
                String sanitized = InstallTokenSanitizer.stripInstallTokens(path);
                String lower = sanitized.toLowerCase(Locale.ROOT);
                if (!matchesPifMapsPath(lower)) {
                    continue;
                }
                if (!seenPaths.add(sanitized)) {
                    continue;
                }
                String token = "pif_maps_trace:" + sanitized;
                if (strong.add(token)) {
                    items.add(new EvidenceItem(
                            "pif_maps_trace",
                            EvidenceItem.SourceLayer.JAVA,
                            sanitized,
                            lower.contains("(deleted)") ? "deleted_loader" : "mapped",
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                }
            }
        }

        return new ProbeResult(
                true,
                new ArrayList<>(strong),
                new ArrayList<>(medium),
                new ArrayList<>(weak),
                items);
    }

    static boolean isPifPropertyKey(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String lower = key.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("persist.sys.pihooks")
                || lower.startsWith("persist.sys.pixelprops")
                || lower.startsWith("persist.sys.spoof.gms");
    }

    static String extractMappedPath(String mapsLine) {
        if (mapsLine == null) {
            return "";
        }
        String trimmed = mapsLine.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        // Standard /proc/self/maps line: addr perms offset dev inode [pathname...]
        // Also tolerate direct path strings in tests.
        if (trimmed.startsWith("/") || trimmed.startsWith("[")) {
            return trimmed;
        }
        int col = 0;
        int i = 0;
        int len = trimmed.length();
        while (i < len && col < 5) {
            while (i < len && !Character.isWhitespace(trimmed.charAt(i))) {
                i++;
            }
            while (i < len && Character.isWhitespace(trimmed.charAt(i))) {
                i++;
            }
            col++;
        }
        return i < len ? trimmed.substring(i).trim() : "";
    }

    private static boolean matchesPifMapsPath(String lowerPath) {
        for (String needle : MAPS_NEEDLES) {
            if (lowerPath.contains(needle)) {
                return true;
            }
        }
        if (lowerPath.contains("keystore") && containsDelimitedPif(lowerPath)) {
            return true;
        }
        return false;
    }

    private static boolean containsDelimitedPif(String text) {
        int idx = 0;
        while ((idx = text.indexOf("pif", idx)) >= 0) {
            boolean leftOk = idx == 0 || !Character.isLetterOrDigit(text.charAt(idx - 1));
            int end = idx + 3;
            boolean rightOk = end >= text.length() || !Character.isLetterOrDigit(text.charAt(end));
            if (leftOk && rightOk) {
                return true;
            }
            idx += 3;
        }
        return false;
    }
}
