package com.wsttxm.riskenginesdk.detector.probe.consistency;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Internal probe inside {@code consistency} that parses native Bionic
 * {@code /dev/__properties__} binary forensics payloads into structured
 * {@code prop_tamper}-family {@link EvidenceItem} entries.
 */
public final class BionicPropProbe {

    public static final String EVIDENCE_FAMILY = "prop_tamper";

    private BionicPropProbe() {}

    /** Immutable outcome of parsing a Bionic {@code prop_area} forensics payload. */
    public static final class ProbeResult {
        private final NativePayloadCodec.Status status;
        private final int errno;
        private final boolean malformed;
        private final int areasScanned;
        private final int roChecked;
        private final List<String> tokens;
        private final List<EvidenceItem> evidenceItems;
        private final boolean hasStrongTamper;
        private final boolean hasAnyTamper;

        ProbeResult(NativePayloadCodec.Status status,
                    int errno,
                    boolean malformed,
                    int areasScanned,
                    int roChecked,
                    List<String> tokens,
                    List<EvidenceItem> evidenceItems,
                    boolean hasStrongTamper,
                    boolean hasAnyTamper) {
            this.status = status == null ? NativePayloadCodec.Status.ERROR : status;
            this.errno = errno;
            this.malformed = malformed;
            this.areasScanned = Math.max(0, areasScanned);
            this.roChecked = Math.max(0, roChecked);
            this.tokens = Collections.unmodifiableList(tokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
            this.hasStrongTamper = hasStrongTamper;
            this.hasAnyTamper = hasAnyTamper;
        }

        public NativePayloadCodec.Status getStatus() { return status; }
        public int getErrno() { return errno; }
        public boolean isMalformed() { return malformed; }
        public boolean isUsable() { return status == NativePayloadCodec.Status.OK && !malformed; }
        public int getAreasScanned() { return areasScanned; }
        public int getRoChecked() { return roChecked; }
        public List<String> getTokens() { return tokens; }
        public List<EvidenceItem> getEvidenceItems() { return evidenceItems; }
        public boolean hasStrongTamper() { return hasStrongTamper; }
        public boolean hasAnyTamper() { return hasAnyTamper; }
    }

    /** Executes the probe using the cached native payload in {@code signals}. */
    public static ProbeResult probe(SignalSnapshot signals) {
        if (signals == null) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED);
        }
        SignalResult<String> raw = signals.getBionicPropForensics();
        if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED);
        }
        return parsePayload(raw.getValue());
    }

    /** Parses a {@link NativePayloadCodec}-encoded payload emitted by {@code bionic_prop_area.cpp}. */
    public static ProbeResult parsePayload(String rawPayload) {
        if (rawPayload == null || rawPayload.isEmpty()) {
            return unavailable(NativePayloadCodec.Status.ERROR);
        }
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(rawPayload);
        if (!decoded.isOk()) {
            // Red line: visibility loss (RESTRICTED/UNSUPPORTED/ERROR/malformed) is NEVER a threat.
            return new ProbeResult(
                    decoded.getStatus(), decoded.getErrno(), decoded.isMalformed(),
                    0, 0, Collections.emptyList(), Collections.emptyList(), false, false);
        }

        int areasScanned = parseIntSafe(decoded.getHeaderField("areas_scanned"));
        int roChecked = parseIntSafe(decoded.getHeaderField("ro_checked"));
        Set<String> tokens = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();
        boolean strong = false;

        for (Map<String, String> rec : decoded.getRecords()) {
            String kind = rec.get("kind");
            if (kind == null || kind.isEmpty()) {
                continue;
            }
            switch (kind) {
                case "hole": {
                    String context = nonEmpty(rec.get("context"), "unknown_area");
                    boolean highPriority = NativePayloadCodec.decodeFlag(rec.get("high_priority"));
                    String count = nonEmpty(rec.get("count"), "1");
                    String ranges = rec.getOrDefault("ranges", "");
                    String code = highPriority ? "prop_area_hole_critical" : "prop_area_hole";
                    EvidenceItem.Rank rank = highPriority
                            ? EvidenceItem.Rank.STRONG : EvidenceItem.Rank.MEDIUM;
                    if (highPriority) {
                        strong = true;
                    }
                    String token = code + ":" + context;
                    String detailVal = ranges.isEmpty()
                            ? ("holes=" + count) : ("holes=" + count + " " + ranges);
                    tokens.add(token);
                    items.add(new EvidenceItem(
                            code,
                            EvidenceItem.SourceLayer.NATIVE,
                            "/dev/__properties__/" + context,
                            detailVal,
                            EVIDENCE_FAMILY,
                            rank));
                    break;
                }
                case "serial_modified": {
                    String prop = nonEmpty(rec.get("prop"), "unknown_ro_prop");
                    String writeCount = nonEmpty(rec.get("write_count"), "1");
                    String serial = rec.getOrDefault("serial", "");
                    String code = "prop_ro_serial_modified";
                    strong = true;
                    tokens.add(code + ":" + prop);
                    items.add(new EvidenceItem(
                            code,
                            EvidenceItem.SourceLayer.NATIVE,
                            prop,
                            serial.isEmpty()
                                    ? ("writes=" + writeCount)
                                    : ("writes=" + writeCount + ",serial=" + serial),
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "nul_tail": {
                    String prop = nonEmpty(rec.get("prop"), "unknown_ro_prop");
                    String cleanVal = rec.getOrDefault("value", "");
                    String nonzeroBytes = nonEmpty(rec.get("nonzero_bytes"), "1");
                    String code = "prop_ro_nul_tail_residual";
                    strong = true;
                    tokens.add(code + ":" + prop);
                    items.add(new EvidenceItem(
                            code,
                            EvidenceItem.SourceLayer.NATIVE,
                            prop,
                            "val=" + cleanVal + ",trailing_nonzero=" + nonzeroBytes,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "meta_anomaly": {
                    String context = nonEmpty(rec.get("context"), "unknown_area");
                    String detail = rec.getOrDefault("detail", "");
                    String code = "prop_area_meta_anomaly";
                    tokens.add(code + ":" + context);
                    items.add(new EvidenceItem(
                            code,
                            EvidenceItem.SourceLayer.NATIVE,
                            "/dev/__properties__/" + context,
                            detail.isEmpty() ? context : detail,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.MEDIUM));
                    break;
                }
                case "selinux_anomaly": {
                    String context = nonEmpty(rec.get("context"), "unknown_area");
                    String xattr = rec.getOrDefault("xattr", "");
                    String code = "prop_area_selinux_anomaly";
                    strong = true;
                    tokens.add(code + ":" + context);
                    items.add(new EvidenceItem(
                            code,
                            EvidenceItem.SourceLayer.NATIVE,
                            "/dev/__properties__/" + context,
                            xattr.isEmpty() ? context : xattr,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                default:
                    break;
            }
        }

        return new ProbeResult(
                decoded.getStatus(),
                decoded.getErrno(),
                decoded.isMalformed(),
                areasScanned,
                roChecked,
                new ArrayList<>(tokens),
                items,
                strong,
                !items.isEmpty());
    }

    private static ProbeResult unavailable(NativePayloadCodec.Status status) {
        return new ProbeResult(
                status, 0, false, 0, 0,
                Collections.emptyList(), Collections.emptyList(), false, false);
    }

    private static int parseIntSafe(String raw) {
        if (raw == null || raw.isEmpty()) return 0;
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String nonEmpty(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }
}
