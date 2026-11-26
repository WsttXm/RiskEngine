package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.AdbInspector;

import java.util.ArrayList;
import java.util.List;

public class AdbDetector extends BaseDetector {
    public static final String EVIDENCE_FAMILY = "adb";

    private final SignalSnapshot signals;

    public AdbDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public AdbDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "adb";
    }

    @Override
    protected DetectionResult detect() {
        AdbInspector.Snapshot snapshot = AdbInspector.collect(signals);
        List<String> details = new ArrayList<>(snapshot.getDetails());
        CheckCoverage coverage = new CheckCoverage();
        for (int i = 0; i < snapshot.getChecksSucceeded(); i++) coverage.success();
        for (String reason : snapshot.getFailureReasons()) coverage.failure(reason);

        if (!snapshot.isEnabled() && !snapshot.isHiddenAdbdContradiction()) {
            return safe(coverage);
        }

        List<EvidenceItem> evidenceItems = buildEvidenceItems(snapshot, details);

        // Hidden-adbd contradiction (init.svc.adbd=stopped / adb_enabled=0 while /dev/socket/adbd
        // or @jdwp-control is actively listening) scores HIGH/7 actionable in ALL scenes.
        if (snapshot.isHiddenAdbdContradiction()) {
            return result(
                    RiskLevel.HIGH,
                    DetectionStatus.DANGER,
                    7,
                    10,
                    false,
                    details,
                    String.join("; ", details),
                    coverage
            ).withEvidenceItems(evidenceItems);
        }

        int score = snapshot.isWifiEnabled() ? 4 : 2;
        RiskLevel level = snapshot.isWifiEnabled() ? RiskLevel.MEDIUM : RiskLevel.LOW;
        return result(
                level,
                DetectionStatus.WARNING,
                score,
                10,
                true,
                details,
                String.join("; ", details),
                coverage
        ).withEvidenceItems(evidenceItems);
    }

    private static List<EvidenceItem> buildEvidenceItems(AdbInspector.Snapshot snapshot,
                                                         List<String> details) {
        List<EvidenceItem> items = new ArrayList<>(details.size());
        for (String token : details) {
            if (token == null || token.isEmpty()) continue;
            if (token.startsWith("adbd_contradiction:")) {
                items.add(new EvidenceItem(
                        "adbd_contradiction",
                        EvidenceItem.SourceLayer.NATIVE,
                        "init.svc.adbd",
                        token.substring("adbd_contradiction:".length()),
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.STRONG));
            } else if (token.startsWith("adbd_hidden_socket:")) {
                items.add(new EvidenceItem(
                        "adbd_hidden_socket",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/dev/socket/adbd",
                        token.substring("adbd_hidden_socket:".length()),
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.STRONG));
            } else if ("adbd_hidden_jdwp_control".equals(token)) {
                items.add(new EvidenceItem(
                        "adbd_hidden_jdwp_control",
                        EvidenceItem.SourceLayer.NATIVE,
                        "@jdwp-control",
                        "observed",
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.STRONG));
            } else if ("settings_adb_wifi_enabled".equals(token)
                    || token.startsWith("adb_tcp_port:")
                    || token.startsWith("adbd_pid_port:")) {
                String code = token.contains(":") ? token.substring(0, token.indexOf(':')) : token;
                String val = token.contains(":") ? token.substring(token.indexOf(':') + 1) : "1";
                items.add(new EvidenceItem(
                        code,
                        EvidenceItem.SourceLayer.JAVA,
                        "adb_wifi",
                        val,
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.MEDIUM));
            } else if (token.startsWith("adbd_socket:") || token.startsWith("jdwp_control_socket:")) {
                String code = token.substring(0, token.indexOf(':'));
                String val = token.substring(token.indexOf(':') + 1);
                items.add(new EvidenceItem(
                        code,
                        EvidenceItem.SourceLayer.NATIVE,
                        code.startsWith("adbd_") ? "/dev/socket/adbd" : "@jdwp-control",
                        val,
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.WEAK));
            } else {
                String code = token.contains(":") ? token.substring(0, token.indexOf(':')) : token;
                String val = token.contains(":") ? token.substring(token.indexOf(':') + 1) : "1";
                items.add(new EvidenceItem(
                        code,
                        EvidenceItem.SourceLayer.JAVA,
                        "adb_usb",
                        val,
                        EVIDENCE_FAMILY,
                        EvidenceItem.Rank.WEAK));
            }
        }
        if (items.isEmpty() && snapshot.isHiddenAdbdContradiction()) {
            items.add(new EvidenceItem(
                    "adbd_contradiction",
                    EvidenceItem.SourceLayer.NATIVE,
                    "/dev/socket/adbd",
                    "hidden_adbd_active",
                    EVIDENCE_FAMILY,
                    EvidenceItem.Rank.STRONG));
        }
        return items;
    }
}
