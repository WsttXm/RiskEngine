package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class DebugDetector extends BaseDetector {
    private final SignalSnapshot signals;

    public DebugDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public DebugDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "debug";
    }

    @Override
    protected DetectionResult detect() {
        LinkedHashSet<String> details = new LinkedHashSet<>();
        boolean strongSignal = false;
        boolean mediumSignal = false;
        boolean weakSignal = false;
        CheckCoverage coverage = new CheckCoverage();

        strongSignal |= checkTracerPid(details, coverage);
        weakSignal |= checkDebuggable(details, coverage);
        weakSignal |= checkIdaPort(details, coverage);
        mediumSignal |= checkDebuggerConnection(details, coverage);
        mediumSignal |= checkMapsExecPath(details, coverage);

        if (!details.isEmpty()) {
            List<String> detailList = new ArrayList<>(details);
            if (strongSignal) {
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            }
            if (mediumSignal) {
                return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            }
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, weakSignal,
                    detailList, String.join("; ", detailList), coverage);
        }
        return safe(coverage);
    }

    private boolean checkTracerPid(Set<String> details, CheckCoverage coverage) {
        if (NativeCollectorBridge.isNativeAvailable()) {
            try {
                SignalResult<Integer> nativeTracer = NativeCollectorBridge.getTracerPidResult();
                int tracerPid = nativeTracer.isSuccess() && nativeTracer.getValue() != null
                        ? nativeTracer.getValue() : -1;
                if (tracerPid > 0) {
                    details.add("tracer_pid:" + tracerPid);
                    coverage.success();
                    return true;
                }
                if (tracerPid == 0) {
                    coverage.success();
                    return false;
                }
            } catch (Exception | LinkageError e) {
                CLog.e("Native TracerPid check failed, using procfs", e);
            }
        }
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    int pid = Integer.parseInt(line.split(":")[1].trim());
                    if (pid > 0) {
                        details.add("tracer_pid:" + pid);
                        coverage.success();
                        return true;
                    }
                    coverage.success();
                    return false;
                }
            }
        } catch (Exception e) {
            CLog.e("TracerPid check failed", e);
            coverage.failure("tracer_pid:" + e.getClass().getSimpleName());
            return false;
        }
        coverage.failure("tracer_pid:missing_field");
        return false;
    }

    private boolean checkDebuggable(Set<String> details, CheckCoverage coverage) {
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                details.add("debuggable_flag");
                coverage.success();
                return true;
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Debuggable check failed", e);
            coverage.failure("debuggable:" + e.getClass().getSimpleName());
        }
        return false;
    }

    private boolean checkIdaPort(Set<String> details, CheckCoverage coverage) {
        try {
            SignalResult<Set<Integer>> ports = signals.getLoopbackListeningPorts();
            if (!ports.isSuccess() || ports.getValue() == null) {
                coverage.failure("ida_port:" + ports.getFailureReason());
                return false;
            }
            if (!ports.getValue().contains(23946)) {
                coverage.success();
                return false;
            }
            details.add("ida_port_open:23946");
            coverage.success();
            return true;
        } catch (Exception e) {
            coverage.failure("ida_port:" + e.getClass().getSimpleName());
        }
        return false;
    }

    private boolean checkDebuggerConnection(Set<String> details, CheckCoverage coverage) {
        try {
            if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
                details.add("debugger_connected");
                coverage.success();
                return true;
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Debugger connection check failed", e);
            coverage.failure("debugger_connection:" + e.getClass().getSimpleName());
        }
        return false;
    }

    private boolean checkMapsExecPath(Set<String> details, CheckCoverage coverage) {
        try {
            SignalResult<List<String>> maps = signals.getSelfMaps();
            if (!maps.isSuccess() || maps.getValue() == null) {
                coverage.failure("maps_exec_path:" + maps.getFailureReason());
                return false;
            }
            for (String line : maps.getValue()) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (!lower.contains(" r-x") && !lower.contains(" r--p")) {
                    continue;
                }
                if (lower.contains("android_server")
                        || lower.contains("gdbserver")
                        || lower.contains("lldb")
                        || lower.contains("frida")) {
                    details.add("maps_exec_path:" + matchingTool(lower));
                    coverage.success();
                    return true;
                }
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Maps exec path check failed", e);
            coverage.failure("maps_exec_path:" + e.getClass().getSimpleName());
        }
        return false;
    }

    private String matchingTool(String mapsLine) {
        String[] tools = {"android_server", "gdbserver", "lldb", "frida"};
        for (String tool : tools) {
            if (mapsLine.contains(tool)) {
                return tool;
            }
        }
        return "unknown";
    }
}
