package com.wsttxm.riskenginesdk.detector.probe.root;

import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Internal probe inside {@code root} that parses native SELinux deep audit and
 * zero-PII Netlink policy-reload leak payloads ({@code selinux_audit_probe.cpp})
 * into structured {@code root_fw}-family {@link EvidenceItem} entries.
 */
public final class SelinuxAuditProbe {

    public static final String EVIDENCE_FAMILY = "root_fw";

    private SelinuxAuditProbe() {}

    /** API/targetSdk gating for Netlink {@code RTM_GETLINK} restriction. */
    public static boolean isNetlinkGetLinkRestricted(int apiLevel, int targetSdk) {
        return (apiLevel >= 30 && targetSdk >= 30) || apiLevel >= 33;
    }

    /** API/targetSdk gating for Netlink {@code RTM_GETNEIGH} restriction. */
    public static boolean isNetlinkGetNeighRestricted(int apiLevel, int targetSdk) {
        return apiLevel >= 33 && targetSdk >= 32;
    }

    /** Immutable outcome of parsing an SELinux deep audit payload. */
    public static final class ProbeResult {
        private final NativePayloadCodec.Status status;
        private final int errno;
        private final boolean malformed;
        private final int probesEvaluated;
        private final boolean linkApplicable;
        private final boolean linkEnforced;
        private final boolean neighApplicable;
        private final boolean neighEnforced;
        private final boolean statusAbiEvaluated;
        private final boolean contextControlsComplete;
        private final List<String> strongTokens;
        private final List<EvidenceItem> evidenceItems;

        ProbeResult(NativePayloadCodec.Status status,
                    int errno,
                    boolean malformed,
                    int probesEvaluated,
                    boolean linkApplicable,
                    boolean linkEnforced,
                    boolean neighApplicable,
                    boolean neighEnforced,
                    boolean statusAbiEvaluated,
                    boolean contextControlsComplete,
                    List<String> strongTokens,
                    List<EvidenceItem> evidenceItems) {
            this.status = status == null ? NativePayloadCodec.Status.ERROR : status;
            this.errno = errno;
            this.malformed = malformed;
            this.probesEvaluated = Math.max(0, probesEvaluated);
            this.linkApplicable = linkApplicable;
            this.linkEnforced = linkEnforced;
            this.neighApplicable = neighApplicable;
            this.neighEnforced = neighEnforced;
            this.statusAbiEvaluated = statusAbiEvaluated;
            this.contextControlsComplete = contextControlsComplete;
            this.strongTokens = Collections.unmodifiableList(strongTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public NativePayloadCodec.Status getStatus() { return status; }
        public int getErrno() { return errno; }
        public boolean isMalformed() { return malformed; }
        public boolean isUsable() { return status == NativePayloadCodec.Status.OK && !malformed; }
        public int getProbesEvaluated() { return probesEvaluated; }
        public boolean isLinkApplicable() { return linkApplicable; }
        public boolean isLinkEnforced() { return linkEnforced; }
        public boolean isNeighApplicable() { return neighApplicable; }
        public boolean isNeighEnforced() { return neighEnforced; }
        public boolean isStatusAbiEvaluated() { return statusAbiEvaluated; }
        public boolean isContextControlsComplete() { return contextControlsComplete; }
        public List<String> getStrongTokens() { return strongTokens; }
        public List<EvidenceItem> getEvidenceItems() { return evidenceItems; }
        public boolean hasStrong() { return !strongTokens.isEmpty(); }
        public boolean hasAny() { return !evidenceItems.isEmpty(); }
    }

    /** Executes the probe via the cached payload in {@code signals}. */
    public static ProbeResult probe(SignalSnapshot signals) {
        if (signals == null) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED);
        }
        SignalResult<String> raw = signals.getSelinuxAuditEvidence();
        if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED);
        }
        return parsePayload(raw.getValue());
    }

    /** Parses a {@link NativePayloadCodec}-encoded payload from {@code selinux_audit_probe.cpp}. */
    public static ProbeResult parsePayload(String rawPayload) {
        if (rawPayload == null || rawPayload.isEmpty()) {
            return unavailable(NativePayloadCodec.Status.ERROR);
        }
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(rawPayload);
        if (!decoded.isOk()) {
            return new ProbeResult(
                    decoded.getStatus(), decoded.getErrno(), decoded.isMalformed(),
                    0, false, false, false, false, false, false,
                    Collections.emptyList(), Collections.emptyList());
        }

        int probesEvaluated = parseIntSafe(decoded.getHeaderField("probes_evaluated"));
        boolean linkApp = NativePayloadCodec.decodeFlag(decoded.getHeaderField("link_applicable"));
        boolean linkEnf = NativePayloadCodec.decodeFlag(decoded.getHeaderField("link_enforced"));
        boolean neighApp = NativePayloadCodec.decodeFlag(decoded.getHeaderField("neigh_applicable"));
        boolean neighEnf = NativePayloadCodec.decodeFlag(decoded.getHeaderField("neigh_enforced"));
        boolean statusEval = NativePayloadCodec.decodeFlag(
                decoded.getHeaderField("status_abi_evaluated"));
        boolean ctxComplete = "COMPLETE".equals(decoded.getHeaderField("ctx_probe_state"));

        Set<String> strong = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        for (Map<String, String> rec : decoded.getRecords()) {
            String kind = rec.get("kind");
            if (kind == null || kind.isEmpty()) {
                continue;
            }
            switch (kind) {
                case "netlink_link_leak": {
                    // Strictly allow only abstract interface kinds (zero raw MAC/ifname PII).
                    String ifKind = sanitizeInterfaceKind(rec.get("if_kind"));
                    strong.add("netlink_link_leak:" + ifKind);
                    items.add(new EvidenceItem(
                            "netlink_link_leak",
                            EvidenceItem.SourceLayer.NATIVE,
                            "netlink:rtm_getlink",
                            "if_kind=" + ifKind,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "netlink_neigh_leak": {
                    if (NativePayloadCodec.decodeFlag(rec.get("leaked"))) {
                        strong.add("netlink_neigh_leak");
                        items.add(new EvidenceItem(
                                "netlink_neigh_leak",
                                EvidenceItem.SourceLayer.NATIVE,
                                "netlink:rtm_getneigh",
                                "lan_neighbor_exposed",
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.STRONG));
                    }
                    break;
                }
                case "selinux_status_abi_violation": {
                    String req = nonEmpty(rec.get("request"), "UNKNOWN");
                    strong.add("selinux_status_abi:" + req);
                    items.add(new EvidenceItem(
                            "selinux_status_abi_violation",
                            EvidenceItem.SourceLayer.NATIVE,
                            "/sys/fs/selinux/status",
                            req,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "selinux_status_header_anomaly": {
                    String ver = rec.getOrDefault("version", "?");
                    String enf = rec.getOrDefault("enforcing", "?");
                    strong.add("selinux_status_header_anomaly");
                    items.add(new EvidenceItem(
                            "selinux_status_header_anomaly",
                            EvidenceItem.SourceLayer.NATIVE,
                            "/sys/fs/selinux/status",
                            "version=" + ver + ",enforcing=" + enf,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "selinux_context_type_present": {
                    // Defense-in-depth: ignore any context finding if control groups did not complete.
                    if (!ctxComplete) {
                        break;
                    }
                    String type = nonEmpty(rec.get("type"), "unknown");
                    strong.add("selinux_context_type:" + type);
                    items.add(new EvidenceItem(
                            "selinux_context_type_present",
                            EvidenceItem.SourceLayer.NATIVE,
                            "/proc/thread-self/attr/current",
                            type,
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
                probesEvaluated,
                linkApp,
                linkEnf,
                neighApp,
                neighEnf,
                statusEval,
                ctxComplete,
                new ArrayList<>(strong),
                items);
    }

    private static String sanitizeInterfaceKind(String raw) {
        if (raw == null) {
            return "physical";
        }
        String lower = raw.trim().toLowerCase(Locale.ROOT);
        if ("wifi".equals(lower)) {
            return "wifi";
        }
        if ("ethernet".equals(lower)) {
            return "ethernet";
        }
        return "physical";
    }

    private static ProbeResult unavailable(NativePayloadCodec.Status status) {
        return new ProbeResult(
                status, 0, false, 0, false, false, false, false, false, false,
                Collections.emptyList(), Collections.emptyList());
    }

    private static int parseIntSafe(String raw) {
        if (raw == null || raw.isBlank()) return 0;
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String nonEmpty(String val, String fallback) {
        return (val == null || val.isBlank()) ? fallback : val.trim();
    }
}
