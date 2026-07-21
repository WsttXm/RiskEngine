package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ShellExecutor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public class ProcessScanDetector extends BaseDetector {

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

    public ProcessScanDetector(Context context) {
        super(context);
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
            String psOutput = ShellExecutor.execute("ps -ef");
            if (psOutput != null && !psOutput.isEmpty()) {
                processListAvailable = true;
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
            String serviceOutput = ShellExecutor.execute("service list");
            if (serviceOutput != null && !serviceOutput.isEmpty()) {
                serviceListAvailable = true;
                String lower = serviceOutput.toLowerCase(Locale.ROOT);
                if (lower.contains("xposed") || lower.contains("edxposed")) {
                    evidence.add("suspicious_service:xposed");
                }
            }
        } catch (Exception e) {
            CLog.e("Service scan failed", e);
        }

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.HIGH, String.join("; ", evidence));
        }
        if (!processListAvailable && !serviceListAvailable) {
            return unavailable("process_and_service_lists_unavailable");
        }
        return safe();
    }

    private boolean containsProcessToken(String output, String processName) {
        String boundary = "(^|[\\s/:])" + Pattern.quote(processName) + "($|[\\s:])";
        return Pattern.compile(boundary, Pattern.MULTILINE).matcher(output).find();
    }
}
