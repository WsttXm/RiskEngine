package com.wsttxm.riskenginesdk.detector.probe.tee;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Keystore2 Grant-Domain isolated-UID chain-split probe.
 *
 * <p>Compares the owner app's {@code Domain.APP} attestation certificate chain SHA-256 against
 * the {@code Domain.GRANT} certificate chain read by an ephemeral dynamic isolated UID
 * ({@code Context.bindIsolatedService} -> {@code RiskIsolatedProbeService}).</p>
 *
 * <p>Catches TrickyStore / Keystore2 main-UID-only interception where either:
 * <ul>
 *   <li>The certificate chain SHA-256 or per-cert digests diverge between {@code Domain.APP} and
 *       {@code Domain.GRANT} (chain split), or</li>
 *   <li>Grant creation or isolated readback returns {@code KEY_NOT_FOUND} after the owner
 *       {@code Domain.APP} already returned a synthetic certificate chain.</li>
 * </ul>
 * Emits {@code tee_grant_chain_split} ({@link EvidenceItem.Rank#STRONG},
 * {@code ISOLATED} + {@code HARDWARE}, family {@code tee_tamper}).</p>
 */
public final class GrantDomainSplitProbe {

    public static final String FAMILY_TEE_TAMPER = TeeNativeProbe.FAMILY_TEE_TAMPER;
    public static final String CODE_GRANT_CHAIN_SPLIT = "tee_grant_chain_split";

    public static final class ProbeResult {
        private final boolean usable;
        private final boolean splitDetected;
        private final String failureReason;
        private final Set<String> strongTokens;
        private final List<EvidenceItem> evidenceItems;

        ProbeResult(
                boolean usable,
                boolean splitDetected,
                String failureReason,
                Set<String> strongTokens,
                List<EvidenceItem> evidenceItems) {
            this.usable = usable;
            this.splitDetected = splitDetected;
            this.failureReason = failureReason;
            this.strongTokens = Collections.unmodifiableSet(strongTokens);
            this.evidenceItems = Collections.unmodifiableList(evidenceItems);
        }

        public boolean isUsable() {
            return usable;
        }

        public boolean isSplitDetected() {
            return splitDetected;
        }

        public String getFailureReason() {
            return failureReason;
        }

        public Set<String> getStrongTokens() {
            return strongTokens;
        }

        public List<EvidenceItem> getEvidenceItems() {
            return evidenceItems;
        }

        public boolean hasFindings() {
            return splitDetected || !strongTokens.isEmpty() || !evidenceItems.isEmpty();
        }
    }

    private static final class ParsedSummary {
        final int certCount;
        final String chainSha256;
        final String[] perCertSha256;

        ParsedSummary(int certCount, String chainSha256, String[] perCertSha256) {
            this.certCount = certCount;
            this.chainSha256 = chainSha256;
            this.perCertSha256 = perCertSha256;
        }
    }

    private GrantDomainSplitProbe() {
    }

    public static ProbeResult run(SignalSnapshot signals, boolean isolatedProbeEnabled) {
        if (!isolatedProbeEnabled) {
            return unavailable("isolated_probe_disabled");
        }
        if (signals == null) {
            return unavailable("signals_unavailable");
        }
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> res =
                signals.getIsolatedGrantReport(true);
        return evaluate(res);
    }

    public static ProbeResult evaluate(SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw) {
        if (raw == null || !raw.isSuccess() || raw.getValue() == null) {
            String reason = raw == null ? "grant_probe_null" : raw.getFailureReason();
            return unavailable(reason == null ? "grant_probe_unavailable" : reason);
        }
        return evaluateReport(raw.getValue());
    }

    public static ProbeResult evaluateReport(IsolatedProbeClient.IsolatedGrantReport report) {
        if (report == null) {
            return unavailable("grant_report_null");
        }

        ParsedSummary app = parseSummary(report.getAppChainSummary());
        if (app == null) {
            return unavailable("owner_chain_summary_invalid");
        }

        IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus status = report.getGrantReadStatus();
        if (status == IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.UNAVAILABLE) {
            return unavailable(report.getDetail() != null ? report.getDetail() : "grant_unavailable");
        }

        if (status == IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.KEY_NOT_FOUND_ON_GRANT
                || status == IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.KEY_NOT_FOUND_ON_READBACK) {
            String reason = status == IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.KEY_NOT_FOUND_ON_GRANT
                    ? "synthetic_key_missing_on_grant"
                    : "synthetic_key_missing_on_isolated_readback";
            return splitFinding(reason + ";app_chain=" + shortHash(app.chainSha256));
        }

        ParsedSummary grant = parseSummary(report.getGrantChainSummary());
        if (grant == null) {
            return unavailable("grant_chain_summary_invalid");
        }

        // Compare chain count, aggregate ordered SHA-256, and per-certificate SHA-256 digests
        int minLen = Math.min(app.perCertSha256.length, grant.perCertSha256.length);
        for (int i = 0; i < minLen; i++) {
            if (!app.perCertSha256[i].equals(grant.perCertSha256[i])) {
                String where = (i == 0) ? "leaf_mismatch" : ("cert_" + i + "_mismatch");
                return splitFinding(where
                        + ";app=" + shortHash(app.perCertSha256[i])
                        + ";grant=" + shortHash(grant.perCertSha256[i]));
            }
        }
        if (app.certCount != grant.certCount || app.perCertSha256.length != grant.perCertSha256.length) {
            return splitFinding("chain_length_mismatch;app=" + app.certCount + ";grant=" + grant.certCount);
        }
        if (!app.chainSha256.equals(grant.chainSha256)) {
            return splitFinding("chain_sha256_mismatch;app=" + shortHash(app.chainSha256)
                    + ";grant=" + shortHash(grant.chainSha256));
        }

        return new ProbeResult(true, false, null, Collections.emptySet(), Collections.emptyList());
    }

    private static ProbeResult splitFinding(String value) {
        Set<String> tokens = new LinkedHashSet<>();
        tokens.add(CODE_GRANT_CHAIN_SPLIT);
        List<EvidenceItem> items = new ArrayList<>(1);
        items.add(new EvidenceItem(
                CODE_GRANT_CHAIN_SPLIT,
                EvidenceItem.SourceLayer.ISOLATED,
                EnumSet.of(EvidenceItem.SourceLayer.ISOLATED, EvidenceItem.SourceLayer.HARDWARE),
                "keystore2:Domain.APP_vs_Domain.GRANT",
                value,
                FAMILY_TEE_TAMPER,
                EvidenceItem.Rank.STRONG));
        return new ProbeResult(true, true, null, tokens, items);
    }

    private static ProbeResult unavailable(String reason) {
        return new ProbeResult(false, false, reason, Collections.emptySet(), Collections.emptyList());
    }

    private static ParsedSummary parseSummary(String raw) {
        if (raw == null || !raw.startsWith("OK|")) {
            return null;
        }
        String[] parts = raw.split("\\|", -1);
        if (parts.length < 4) {
            return null;
        }
        int count;
        try {
            count = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            return null;
        }
        String chainHash = parts[2].trim();
        String certsCsv = parts[3].trim();
        if (count <= 0 || chainHash.isEmpty() || certsCsv.isEmpty()) {
            return null;
        }
        String[] perCert = certsCsv.split(",", -1);
        if (perCert.length != count) {
            return null;
        }
        for (int i = 0; i < perCert.length; i++) {
            perCert[i] = perCert[i].trim();
            if (perCert[i].isEmpty()) {
                return null;
            }
        }
        return new ParsedSummary(count, chainHash, perCert);
    }

    private static String shortHash(String hash) {
        if (hash == null) {
            return "";
        }
        return hash.length() > 16 ? hash.substring(0, 16) : hash;
    }
}
