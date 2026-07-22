package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ShellExecutor;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.LinkedHashMap;
import java.util.Map;

public class ProcessScanDetector extends BaseDetector {
    private final SignalSnapshot signals;

    private static final String[] SUSPICIOUS_PROCESSES = {
            "frida", "frida-server", "frida-agent",
            "xposed", "edxposed", "lsposed",
            "magisk", "magiskd", "magisk_daemon",
            "objection",
            "gdb", "gdbserver", "lldb-server",
            "idaq", "android_server", "android_server64",
            "radare2",
            "substrate", "cydia",
    };
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
        boolean serviceListAvailable = false;

        try {
            ShellExecutor.Result ps = signals.getShellResult("ps -ef");
            if (ps.isSuccess()) {
                processListAvailable = true;
                String psOutput = ps.getStdout();
                String lower = psOutput.toLowerCase(Locale.ROOT);
                for (String proc : SUSPICIOUS_PROCESSES) {
                    if (containsProcessToken(lower, proc)) {
                        evidence.add("suspicious_process:" + proc);
                    }
                }
            }
        } catch (Exception e) {
            CLog.e("Process scan failed", e);
        }

        // Also check service list
        try {
            ShellExecutor.Result services = signals.getShellResult("service list");
            if (services.isSuccess()) {
                serviceListAvailable = true;
                String serviceOutput = services.getStdout();
                String lower = serviceOutput.toLowerCase(Locale.ROOT);
                if (lower.contains("xposed") || lower.contains("edxposed")) {
                    evidence.add("suspicious_service:xposed");
                }
            }
        } catch (Exception e) {
            CLog.e("Service scan failed", e);
        }

        if (!evidence.isEmpty()) {
            CheckCoverage coverage = processCoverage(
                    processListAvailable, serviceListAvailable);
            return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                    evidence, String.join("; ", evidence), coverage);
        }
        if (!processListAvailable && !serviceListAvailable) {
            return unavailable("process_and_service_lists_unavailable");
        }
        return safe(processCoverage(processListAvailable, serviceListAvailable));
    }

    private CheckCoverage processCoverage(boolean processAvailable, boolean serviceAvailable) {
        CheckCoverage coverage = new CheckCoverage();
        if (processAvailable) coverage.success();
        else coverage.failure("process_list_unavailable");
        if (serviceAvailable) coverage.success();
        else coverage.failure("service_list_unavailable");
        return coverage;
    }

    private boolean containsProcessToken(String output, String processName) {
        Pattern pattern = PROCESS_PATTERNS.get(processName);
        return pattern != null && pattern.matcher(output).find();
    }

    private static Map<String, Pattern> buildPatterns() {
        Map<String, Pattern> patterns = new LinkedHashMap<>();
        for (String processName : SUSPICIOUS_PROCESSES) {
            String boundary = "(^|[\\s/:])" + Pattern.quote(processName) + "($|[\\s:])";
            patterns.put(processName, Pattern.compile(boundary, Pattern.MULTILINE));
        }
        return patterns;
    }
}
