package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public class ProcessScanDetector extends BaseDetector {
    private final SignalSnapshot signals;
    private static final Map<String, Pattern> PROCESS_PATTERNS = buildPatterns();

    public ProcessScanDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public ProcessScanDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "process_scan";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();
        boolean processListAvailable = false;
        boolean nativeListAvailable = false;

        try {
            SignalResult<List<ProcfsUtils.ProcessInfo>> processes = signals.getProcesses();
            if (processes.isSuccess() && processes.getValue() != null) {
                processListAvailable = true;
                for (ProcfsUtils.ProcessInfo process : processes.getValue()) {
                    String haystack = (process.getComm() + " " + process.getCmdline())
                            .toLowerCase(Locale.ROOT);
                    for (String proc : DetectionLists.PROCESS_TOKENS) {
                        if (containsProcessToken(haystack, proc)) {
                            addUnique(evidence, "suspicious_process:" + proc);
                        }
                    }
                }
            }
        } catch (Exception e) {
            CLog.e("Process scan failed", e);
        }

        try {
            SignalResult<String> nativeTokens = signals.getNativeProcessTokens();
            if (nativeTokens.isSuccess() && nativeTokens.getValue() != null
                    && !nativeTokens.getValue().isEmpty()) {
                nativeListAvailable = true;
                for (String token : nativeTokens.getValue().split(",")) {
                    String item = token.trim();
                    if (!item.isEmpty()) {
                        addUnique(evidence, "native_process:" + item);
                    }
                }
            } else if (nativeTokens.isSuccess()) {
                nativeListAvailable = true;
            }
        } catch (Exception e) {
            CLog.e("Native process scan failed", e);
        }

        if (processListAvailable && nativeListAvailable
                && (javaEvidenceOnly(evidence) || nativeEvidenceOnly(evidence))) {
            evidence.add("process_source_mismatch");
        }

        if (!evidence.isEmpty()) {
            CheckCoverage coverage = processCoverage(processListAvailable, nativeListAvailable);
            boolean high = false;
            for (String item : evidence) {
                String lower = item.toLowerCase(Locale.ROOT);
                if (lower.contains("frida") || lower.contains("magisk") || lower.contains("ksud")
                        || lower.contains("lspd") || lower.contains("zygisk")) {
                    high = true;
                    break;
                }
            }
            if (high) {
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        evidence, String.join("; ", evidence), coverage);
            }
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (!processListAvailable && !nativeListAvailable) {
            return unavailable("process_lists_unavailable");
        }
        return safe(processCoverage(processListAvailable, nativeListAvailable));
    }

    private CheckCoverage processCoverage(boolean processAvailable, boolean nativeAvailable) {
        CheckCoverage coverage = new CheckCoverage();
        if (processAvailable) coverage.success();
        else coverage.failure("process_list_unavailable");
        if (nativeAvailable) coverage.success();
        else coverage.failure("native_process_list_unavailable");
        return coverage;
    }

    public static boolean containsProcessToken(String output, String processName) {
        Pattern pattern = PROCESS_PATTERNS.get(processName);
        return pattern != null && pattern.matcher(output).find();
    }

    private static boolean javaEvidenceOnly(List<String> evidence) {
        boolean javaHit = false;
        boolean nativeHit = false;
        for (String item : evidence) {
            if (item.startsWith("suspicious_process:")) javaHit = true;
            if (item.startsWith("native_process:")) nativeHit = true;
        }
        return javaHit && !nativeHit;
    }

    private static boolean nativeEvidenceOnly(List<String> evidence) {
        boolean javaHit = false;
        boolean nativeHit = false;
        for (String item : evidence) {
            if (item.startsWith("suspicious_process:")) javaHit = true;
            if (item.startsWith("native_process:")) nativeHit = true;
        }
        return nativeHit && !javaHit;
    }

    private static void addUnique(List<String> evidence, String item) {
        if (!evidence.contains(item)) evidence.add(item);
    }

    private static Map<String, Pattern> buildPatterns() {
        Map<String, Pattern> patterns = new LinkedHashMap<>();
        for (String processName : DetectionLists.PROCESS_TOKENS) {
            String boundary = "(^|[\\s/:])" + Pattern.quote(processName) + "($|[\\s:])";
            patterns.put(processName, Pattern.compile(boundary, Pattern.MULTILINE));
        }
        return patterns;
    }
}
