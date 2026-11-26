package com.wsttxm.riskenginesdk.detector.probe.hook;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.HookEvidenceClassifier;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Internal probe inside {@code hook_framework} that decodes native hook and
 * COW-safe self-integrity payloads into legacy tokens plus first-class
 * {@link EvidenceItem} entries.
 */
public final class SelfIntegrityProbe {
    private SelfIntegrityProbe() {}

    public static final class ProbeResult {
        private final NativePayloadCodec.Status status;
        private final int errno;
        private final boolean malformed;
        private final List<String> tokens;
        private final List<EvidenceItem> evidenceItems;
        private final boolean hasSelfIntegrityTamper;

        ProbeResult(NativePayloadCodec.Status status,
                    int errno,
                    boolean malformed,
                    List<String> tokens,
                    List<EvidenceItem> evidenceItems,
                    boolean hasSelfIntegrityTamper) {
            this.status = status;
            this.errno = errno;
            this.malformed = malformed;
            this.tokens = Collections.unmodifiableList(tokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.hasSelfIntegrityTamper = hasSelfIntegrityTamper;
        }

        public NativePayloadCodec.Status getStatus() {
            return status;
        }

        public int getErrno() {
            return errno;
        }

        public boolean isMalformed() {
            return malformed;
        }

        public List<String> getTokens() {
            return tokens;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public boolean hasSelfIntegrityTamper() {
            return hasSelfIntegrityTamper;
        }
    }

    public static boolean isSelfIntegrityToken(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        String lower = token.toLowerCase(Locale.ROOT);
        if (lower.startsWith("native:")) {
            lower = lower.substring("native:".length());
        }
        return lower.equals("text_mismatch")
                || lower.startsWith("text_mismatch:")
                || lower.equals("late_text_mismatch")
                || lower.startsWith("late_text_mismatch:")
                || lower.startsWith("inline_hook:")
                || lower.startsWith("got_hook:")
                || lower.startsWith("jni_self_hook:")
                || lower.startsWith("jni_table_hook:")
                || lower.startsWith("jni_slot_hook:")
                || lower.startsWith("fn_prologue_hook:")
                || lower.startsWith("wx_segment:self")
                || lower.startsWith("late_wx_self");
    }

    public static boolean isSelfIntegrityCode(String code) {
        if (code == null || code.isBlank()) {
            return false;
        }
        String lower = code.toLowerCase(Locale.ROOT);
        return lower.equals("text_mismatch")
                || lower.equals("late_text_mismatch")
                || lower.equals("inline_hook")
                || lower.equals("got_hook")
                || lower.equals("jni_self_hook")
                || lower.equals("jni_table_hook")
                || lower.equals("jni_slot_hook")
                || lower.equals("fn_prologue_hook")
                || lower.equals("wx_segment_self")
                || lower.equals("late_wx_self");
    }

    public static ProbeResult parseNativeHookPayload(String rawPayload) {
        if (rawPayload == null || rawPayload.isEmpty()) {
            return new ProbeResult(NativePayloadCodec.Status.OK, 0, false,
                    Collections.emptyList(), Collections.emptyList(), false);
        }

        if (rawPayload.startsWith("status=")) {
            return parseCodecPayload(rawPayload);
        }
        return parseLegacyCsv(rawPayload);
    }

    private static ProbeResult parseCodecPayload(String rawPayload) {
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(rawPayload);
        if (!decoded.isOk()) {
            // Red line: RESTRICTED / UNSUPPORTED / ERROR or malformed payloads must
            // never become positive threats.
            return new ProbeResult(decoded.getStatus(), decoded.getErrno(), decoded.isMalformed(),
                    Collections.emptyList(), Collections.emptyList(), false);
        }

        Set<String> tokenSet = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();
        boolean selfTamper = false;

        for (Map<String, String> rec : decoded.getRecords()) {
            String token = rec.get("token");
            String code = rec.get("code");
            String location = rec.getOrDefault("location", "");
            String value = rec.getOrDefault("value", "");
            String family = rec.get("family");

            if ((token == null || token.isEmpty()) && code != null && !code.isEmpty()) {
                token = location.isEmpty() ? code : (code + ":" + location);
            }
            if (token == null || token.isBlank()) {
                continue;
            }
            String trimmedToken = token.trim();
            tokenSet.add(trimmedToken);

            String resolvedCode = (code != null && !code.isBlank())
                    ? code.trim()
                    : deriveCodeFromToken(trimmedToken);
            String resolvedFamily = (family != null && !family.isBlank())
                    ? family.trim()
                    : deriveFamily(trimmedToken, resolvedCode);
            EvidenceItem.Rank rank = mapRank(HookEvidenceClassifier.rank(trimmedToken));

            if (isSelfIntegrityToken(trimmedToken) || isSelfIntegrityCode(resolvedCode)) {
                selfTamper = true;
            }

            items.add(new EvidenceItem(
                    resolvedCode,
                    EvidenceItem.SourceLayer.NATIVE,
                    location,
                    value.isEmpty() ? trimmedToken : value,
                    resolvedFamily,
                    rank));
        }

        return new ProbeResult(
                decoded.getStatus(),
                decoded.getErrno(),
                decoded.isMalformed(),
                new ArrayList<>(tokenSet),
                items,
                selfTamper);
    }

    private static ProbeResult parseLegacyCsv(String rawCsv) {
        Set<String> tokenSet = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();
        boolean selfTamper = false;

        for (String piece : rawCsv.split(",")) {
            String token = piece.trim();
            if (token.isEmpty()) continue;
            tokenSet.add(token);

            String code = deriveCodeFromToken(token);
            String location = deriveLocationFromToken(token);
            String family = deriveFamily(token, code);
            EvidenceItem.Rank rank = mapRank(HookEvidenceClassifier.rank(token));

            if (isSelfIntegrityToken(token) || isSelfIntegrityCode(code)) {
                selfTamper = true;
            }
            items.add(new EvidenceItem(
                    code,
                    EvidenceItem.SourceLayer.NATIVE,
                    location,
                    token,
                    family,
                    rank));
        }

        return new ProbeResult(
                NativePayloadCodec.Status.OK,
                0,
                false,
                new ArrayList<>(tokenSet),
                items,
                selfTamper);
    }

    public static EvidenceItem.Rank mapRank(HookEvidenceClassifier.Rank rank) {
        if (rank == null) return EvidenceItem.Rank.INFO;
        switch (rank) {
            case STRONG:
                return EvidenceItem.Rank.STRONG;
            case MEDIUM:
                return EvidenceItem.Rank.MEDIUM;
            case WEAK:
                return EvidenceItem.Rank.WEAK;
            case IGNORE:
            default:
                return EvidenceItem.Rank.INFO;
        }
    }

    private static String deriveCodeFromToken(String token) {
        int colon = token.indexOf(':');
        return colon > 0 ? token.substring(0, colon) : token;
    }

    private static String deriveLocationFromToken(String token) {
        int colon = token.indexOf(':');
        return (colon > 0 && colon + 1 < token.length()) ? token.substring(colon + 1) : "";
    }

    private static String deriveFamily(String token, String code) {
        if (isSelfIntegrityToken(token) || isSelfIntegrityCode(code)) {
            return "hook_integrity";
        }
        return EvidenceFamily.familyOf(token);
    }
}
