package com.wsttxm.riskenginesdk.detector.probe.hook;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Internal postponed probe inside {@code hook_framework} that parses native Bionic
 * {@code atexit} array forensics ({@code _ZL7g_array} + LLVM SRA splits, non-blocking
 * {@code pthread_mutex_trylock}, {@code pipe2} read) into structured
 * {@code hook_integrity}-family {@link EvidenceItem} entries.
 */
public final class ZygiskProbe {

    public static final String EVIDENCE_FAMILY = "hook_integrity";
    public static final int MIN_CONTIGUOUS_HOLES = 3;

    private ZygiskProbe() {}

    /** Immutable outcome of parsing a Zygisk {@code atexit} forensics frame. */
    public static final class ProbeResult {
        private final NativePayloadCodec.Status status;
        private final int errno;
        private final boolean malformed;
        private final String state;
        private final int entryCount;
        private final int nullEntryCount;
        private final int anchoredGapCount;
        private final int anonCallbackCount;
        private final List<String> strongTokens;
        private final List<String> mediumTokens;
        private final List<EvidenceItem> evidenceItems;

        ProbeResult(NativePayloadCodec.Status status,
                    int errno,
                    boolean malformed,
                    String state,
                    int entryCount,
                    int nullEntryCount,
                    int anchoredGapCount,
                    int anonCallbackCount,
                    List<String> strongTokens,
                    List<String> mediumTokens,
                    List<EvidenceItem> evidenceItems) {
            this.status = status == null ? NativePayloadCodec.Status.ERROR : status;
            this.errno = errno;
            this.malformed = malformed;
            this.state = state == null ? "UNAVAILABLE" : state;
            this.entryCount = Math.max(0, entryCount);
            this.nullEntryCount = Math.max(0, nullEntryCount);
            this.anchoredGapCount = Math.max(0, anchoredGapCount);
            this.anonCallbackCount = Math.max(0, anonCallbackCount);
            this.strongTokens = Collections.unmodifiableList(strongTokens);
            this.mediumTokens = Collections.unmodifiableList(mediumTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public NativePayloadCodec.Status getStatus() { return status; }
        public int getErrno() { return errno; }
        public boolean isMalformed() { return malformed; }
        public String getState() { return state; }
        public boolean isUsable() { return status == NativePayloadCodec.Status.OK && !malformed; }
        public int getEntryCount() { return entryCount; }
        public int getNullEntryCount() { return nullEntryCount; }
        public int getAnchoredGapCount() { return anchoredGapCount; }
        public int getAnonCallbackCount() { return anonCallbackCount; }
        public List<String> getStrongTokens() { return strongTokens; }
        public List<String> getMediumTokens() { return mediumTokens; }
        public List<EvidenceItem> getEvidenceItems() { return evidenceItems; }
        public boolean hasFindings() { return !evidenceItems.isEmpty(); }
    }

    /** Executes the native Zygisk atexit probe via {@link NativeCollectorBridge}. */
    public static ProbeResult probe() {
        return probe(NativeCollectorBridge::getZygiskAtexitProbeResult);
    }

    /** Executes the probe via an injectable supplier for deterministic unit tests. */
    public static ProbeResult probe(Supplier<SignalResult<String>> nativeSupplier) {
        if (nativeSupplier == null) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED, "UNAVAILABLE");
        }
        SignalResult<String> raw;
        try {
            raw = nativeSupplier.get();
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            return unavailable(NativePayloadCodec.Status.ERROR, "UNAVAILABLE");
        }
        if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED, "UNAVAILABLE");
        }
        return parsePayload(raw.getValue());
    }

    /** Parses a {@link NativePayloadCodec}-encoded payload emitted by {@code zygisk_atexit_probe.cpp}. */
    public static ProbeResult parsePayload(String rawPayload) {
        if (rawPayload == null || rawPayload.isEmpty()) {
            return unavailable(NativePayloadCodec.Status.ERROR, "UNAVAILABLE");
        }
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(rawPayload);
        String state = nonEmpty(decoded.getHeaderField("state"), "UNAVAILABLE");
        if (!decoded.isOk()) {
            // Visibility loss / stripped libc symbols / busy trylock is NEVER a threat.
            return new ProbeResult(
                    decoded.getStatus(), decoded.getErrno(), decoded.isMalformed(), state,
                    0, 0, 0, 0,
                    Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        }

        int entries = parseIntSafe(decoded.getHeaderField("entries"));
        int nullEntries = parseIntSafe(decoded.getHeaderField("null_entries"));
        int anchoredGaps = parseIntSafe(decoded.getHeaderField("anchored_gaps"));
        int anonCallbacks = parseIntSafe(decoded.getHeaderField("anon_callbacks"));

        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        for (Map<String, String> rec : decoded.getRecords()) {
            String kind = rec.get("kind");
            if (kind == null || kind.isEmpty()) {
                continue;
            }
            switch (kind) {
                case "atexit_anon_callback": {
                    String idx = nonEmpty(rec.get("index"), "?");
                    String owner = nonEmpty(rec.get("owner"), "[anon_exec]");
                    strong.add("zygisk_atexit_anon:" + idx);
                    items.add(new EvidenceItem(
                            "zygisk_atexit_anon",
                            EvidenceItem.SourceLayer.NATIVE,
                            owner,
                            "index=" + idx,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "atexit_hole_run": {
                    int count = parseIntSafe(rec.get("count"));
                    if (count < MIN_CONTIGUOUS_HOLES) {
                        continue;
                    }
                    String start = nonEmpty(rec.get("start"), "0");
                    String end = nonEmpty(rec.get("end"), start);
                    medium.add("zygisk_atexit_holes:" + count + "@" + start);
                    items.add(new EvidenceItem(
                            "zygisk_atexit_holes",
                            EvidenceItem.SourceLayer.NATIVE,
                            "atexit[" + start + ".." + end + "]",
                            "holes=" + count,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.MEDIUM));
                    break;
                }
                case "atexit_runtime_drift": {
                    String atexitOwner = nonEmpty(rec.get("atexit_owner"), "<unknown>");
                    String finalizeOwner = nonEmpty(rec.get("finalize_owner"), "<unknown>");
                    strong.add("zygisk_atexit_drift");
                    items.add(new EvidenceItem(
                            "zygisk_atexit_drift",
                            EvidenceItem.SourceLayer.NATIVE,
                            "__cxa_atexit",
                            "atexit=" + atexitOwner + ",finalize=" + finalizeOwner,
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
                state,
                entries,
                nullEntries,
                anchoredGaps,
                anonCallbacks,
                new ArrayList<>(strong),
                new ArrayList<>(medium),
                items);
    }

    private static ProbeResult unavailable(NativePayloadCodec.Status status, String state) {
        return new ProbeResult(
                status, 0, false, state, 0, 0, 0, 0,
                Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
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
