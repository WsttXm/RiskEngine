package com.wsttxm.riskenginesdk.detector.probe.root;

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
 * Internal probe inside {@code root} that parses native kernel root side-channel
 * payloads ({@code kernel_sidechannel.cpp}) into structured {@code root_fw}-family
 * {@link EvidenceItem} entries.
 */
public final class KernelSidechannelProbe {

    public static final String EVIDENCE_FAMILY = "root_fw";

    private KernelSidechannelProbe() {}

    /** Immutable outcome of parsing a kernel side-channel payload. */
    public static final class ProbeResult {
        private final NativePayloadCodec.Status status;
        private final int errno;
        private final boolean malformed;
        private final int probesRun;
        private final boolean kpNegativeTrusted;
        private final boolean timingRan;
        private final int timingConsecutiveHits;
        private final List<String> strongTokens;
        private final List<String> mediumTokens;
        private final List<EvidenceItem> evidenceItems;

        ProbeResult(NativePayloadCodec.Status status,
                    int errno,
                    boolean malformed,
                    int probesRun,
                    boolean kpNegativeTrusted,
                    boolean timingRan,
                    int timingConsecutiveHits,
                    List<String> strongTokens,
                    List<String> mediumTokens,
                    List<EvidenceItem> evidenceItems) {
            this.status = status == null ? NativePayloadCodec.Status.ERROR : status;
            this.errno = errno;
            this.malformed = malformed;
            this.probesRun = Math.max(0, probesRun);
            this.kpNegativeTrusted = kpNegativeTrusted;
            this.timingRan = timingRan;
            this.timingConsecutiveHits = Math.max(0, timingConsecutiveHits);
            this.strongTokens = Collections.unmodifiableList(strongTokens);
            this.mediumTokens = Collections.unmodifiableList(mediumTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public NativePayloadCodec.Status getStatus() { return status; }
        public int getErrno() { return errno; }
        public boolean isMalformed() { return malformed; }
        public boolean isUsable() { return status == NativePayloadCodec.Status.OK && !malformed; }
        public int getProbesRun() { return probesRun; }
        public boolean isKpNegativeTrusted() { return kpNegativeTrusted; }
        public boolean isTimingRan() { return timingRan; }
        public int getTimingConsecutiveHits() { return timingConsecutiveHits; }
        public List<String> getStrongTokens() { return strongTokens; }
        public List<String> getMediumTokens() { return mediumTokens; }
        public List<EvidenceItem> getEvidenceItems() { return evidenceItems; }
        public boolean hasStrong() { return !strongTokens.isEmpty(); }
        public boolean hasMedium() { return !mediumTokens.isEmpty(); }
        public boolean hasAny() { return !evidenceItems.isEmpty(); }
    }

    /** Executes the probe via the cached payload in {@code signals}. */
    public static ProbeResult probe(SignalSnapshot signals, boolean includePostponedTiming) {
        if (signals == null) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED);
        }
        SignalResult<String> raw = signals.getKernelSidechannelEvidence(includePostponedTiming);
        if (raw == null || !raw.isSuccess() || raw.getValue() == null || raw.getValue().isEmpty()) {
            return unavailable(NativePayloadCodec.Status.UNSUPPORTED);
        }
        return parsePayload(raw.getValue());
    }

    /** Parses a {@link NativePayloadCodec}-encoded payload from {@code kernel_sidechannel.cpp}. */
    public static ProbeResult parsePayload(String rawPayload) {
        if (rawPayload == null || rawPayload.isEmpty()) {
            return unavailable(NativePayloadCodec.Status.ERROR);
        }
        NativePayloadCodec.DecodedPayload decoded = NativePayloadCodec.decodePayload(rawPayload);
        if (!decoded.isOk()) {
            // Visibility loss (RESTRICTED / UNSUPPORTED / ERROR / malformed) is NEVER a threat.
            return new ProbeResult(
                    decoded.getStatus(), decoded.getErrno(), decoded.isMalformed(),
                    0, false, false, 0,
                    Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        }

        int probesRun = parseIntSafe(decoded.getHeaderField("probes_run"));
        boolean kpNegTrusted = NativePayloadCodec.decodeFlag(
                decoded.getHeaderField("kp_negative_trusted"));
        boolean timingRan = NativePayloadCodec.decodeFlag(decoded.getHeaderField("timing_ran"));
        int timingHits = parseIntSafe(decoded.getHeaderField("timing_consecutive_hits"));

        Set<String> strong = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        List<EvidenceItem> items = new ArrayList<>();

        for (Map<String, String> rec : decoded.getRecords()) {
            String kind = rec.get("kind");
            if (kind == null || kind.isEmpty()) {
                continue;
            }
            switch (kind) {
                case "kernelpatch_supercall_hello": {
                    String magic = nonEmpty(rec.get("magic"), "0x11581158");
                    String kernel = rec.getOrDefault("kernel", "");
                    String val = "magic=" + magic
                            + (kernel.isEmpty() ? "" : ",kernel=" + kernel);
                    strong.add("kernelpatch_supercall_hello");
                    items.add(new EvidenceItem(
                            "kernelpatch_supercall_hello",
                            EvidenceItem.SourceLayer.NATIVE,
                            "sys_truncate",
                            val,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "kernelpatch_truncate_hit": {
                    String hits = nonEmpty(rec.get("hits"), "1");
                    String checked = nonEmpty(rec.get("checked"), "4");
                    String kernel = rec.getOrDefault("kernel", "");
                    String val = "hits=" + hits + "/" + checked
                            + (kernel.isEmpty() ? "" : ",kernel=" + kernel);
                    strong.add("kernelpatch_truncate_hit");
                    items.add(new EvidenceItem(
                            "kernelpatch_truncate_hit",
                            EvidenceItem.SourceLayer.NATIVE,
                            "sys_truncate",
                            val,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "ksu_reboot_ioctl": {
                    String version = nonEmpty(rec.get("version"), "0");
                    String flags = rec.getOrDefault("flags", "0");
                    String features = rec.getOrDefault("features", "0");
                    boolean safeMode = NativePayloadCodec.decodeFlag(rec.get("safe_mode"));
                    String val = "v" + version + ",flags=" + flags + ",features=" + features
                            + (safeMode ? ",safe_mode=1" : "");
                    strong.add("ksu_reboot_ioctl:v" + version);
                    items.add(new EvidenceItem(
                            "ksu_reboot_ioctl",
                            EvidenceItem.SourceLayer.NATIVE,
                            "sys_reboot",
                            val,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "ksu_driver_fd": {
                    String fd = nonEmpty(rec.get("fd"), "?");
                    String target = nonEmpty(rec.get("target"), "[ksu_driver]");
                    strong.add("ksu_driver_fd:" + fd);
                    items.add(new EvidenceItem(
                            "ksu_driver_fd",
                            EvidenceItem.SourceLayer.NATIVE,
                            "/proc/self/fd/" + fd,
                            target,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "devpts_ksu_xattr": {
                    String path = nonEmpty(rec.get("path"), "/dev/pts");
                    String ctx = nonEmpty(rec.get("context"), "ksu_file");
                    strong.add("devpts_ksu_xattr:" + path);
                    items.add(new EvidenceItem(
                            "devpts_ksu_xattr",
                            EvidenceItem.SourceLayer.NATIVE,
                            path,
                            ctx,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "susfs_setresuid_sigkill": {
                    String uid = rec.getOrDefault("uid", "");
                    String targetUid = rec.getOrDefault("target_uid", "");
                    String val = uid.isEmpty() ? "SIGKILL" : ("uid=" + uid + "->" + targetUid + ",SIGKILL");
                    strong.add("susfs_setresuid_sigkill");
                    items.add(new EvidenceItem(
                            "susfs_setresuid_sigkill",
                            EvidenceItem.SourceLayer.NATIVE,
                            "sys_setresuid",
                            val,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "setresuid_unexpected_success": {
                    String uid = rec.getOrDefault("uid", "");
                    String targetUid = rec.getOrDefault("target_uid", "");
                    String val = uid.isEmpty() ? "succeeded" : ("uid=" + uid + "->" + targetUid);
                    strong.add("setresuid_unexpected_success");
                    items.add(new EvidenceItem(
                            "setresuid_unexpected_success",
                            EvidenceItem.SourceLayer.NATIVE,
                            "sys_setresuid",
                            val,
                            EVIDENCE_FAMILY,
                            EvidenceItem.Rank.STRONG));
                    break;
                }
                case "ksu_prctl_timing_anomaly": {
                    int consec = parseIntSafe(rec.get("consecutive_hits"));
                    // Enforce 3 consecutive same-core hits even on payload side.
                    if (consec >= 3) {
                        String cpu = nonEmpty(rec.get("cpu"), "?");
                        String metrics = nonEmpty(rec.get("metrics"), "hits=" + consec);
                        medium.add("ksu_prctl_timing_anomaly:cpu" + cpu);
                        items.add(new EvidenceItem(
                                "ksu_prctl_timing_anomaly",
                                EvidenceItem.SourceLayer.NATIVE,
                                "cpu" + cpu,
                                metrics,
                                EVIDENCE_FAMILY,
                                EvidenceItem.Rank.MEDIUM));
                    }
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
                probesRun,
                kpNegTrusted,
                timingRan,
                timingHits,
                new ArrayList<>(strong),
                new ArrayList<>(medium),
                items);
    }

    private static ProbeResult unavailable(NativePayloadCodec.Status status) {
        return new ProbeResult(
                status, 0, false, 0, false, false, 0,
                Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
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
