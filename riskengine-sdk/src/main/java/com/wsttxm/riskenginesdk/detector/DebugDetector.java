package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DebugDetector extends BaseDetector {

    public DebugDetector(Context context) {
        super(context);
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
        boolean warnOnly = false;

        strongSignal |= checkTracerPid(details);
        warnOnly |= checkDebuggable(details);
        mediumSignal |= checkIdaPort(details);
        strongSignal |= checkNativePtrace(details);
        mediumSignal |= checkDebuggerConnection(details);
        mediumSignal |= checkMapsExecPath(details);

        if (!details.isEmpty()) {
            List<String> detailList = new ArrayList<>(details);
            if (strongSignal) {
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        detailList, String.join("; ", detailList));
            }
            if (mediumSignal) {
                return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                        detailList, String.join("; ", detailList));
            }
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 2, 10, warnOnly,
                    detailList, String.join("; ", detailList));
        }
        return safe();
    }

    private boolean checkTracerPid(Set<String> details) {
        try {
            int tracerPid = NativeCollectorBridge.nativeGetTracerPid();
            if (tracerPid > 0) {
                details.add("tracer_pid:" + tracerPid);
                return true;
            }
        } catch (Exception e) {
            // Fallback: read from Java
            try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/status"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        int pid = Integer.parseInt(line.split(":")[1].trim());
                        if (pid > 0) {
                            details.add("tracer_pid:" + pid);
                            return true;
                        }
                        break;
                    }
                }
            } catch (Exception ex) {
                CLog.e("TracerPid check failed", ex);
            }
        }
        return false;
    }

    private boolean checkDebuggable(Set<String> details) {
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                details.add("debuggable_flag");
                return true;
            }
        } catch (Exception e) {
            CLog.e("Debuggable check failed", e);
        }
        return false;
    }

    private boolean checkIdaPort(Set<String> details) {
        // IDA default debug port
        try {
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", 23946), 100);
            socket.close();
            details.add("ida_port_open:23946");
            return true;
        } catch (Exception ignored) {}
        return false;
    }

    private boolean checkNativePtrace(Set<String> details) {
        try {
            if (NativeCollectorBridge.nativeCheckPtrace()) {
                details.add("ptrace_detected");
                return true;
            }
        } catch (Exception e) {
            CLog.e("Native ptrace check failed", e);
        }
        return false;
    }

    private boolean checkDebuggerConnection(Set<String> details) {
        try {
            if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
                details.add("debugger_connected");
                return true;
            }
        } catch (Exception e) {
            CLog.e("Debugger connection check failed", e);
        }
        return false;
    }

    private boolean checkMapsExecPath(Set<String> details) {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                if (!lower.contains(" r-x") && !lower.contains(" r--p")) {
                    continue;
                }
                if (lower.contains("android_server")
                        || lower.contains("gdbserver")
                        || lower.contains("lldb")
                        || lower.contains("frida")) {
                    details.add("maps_exec_path:" + line.trim());
                    return true;
                }
            }
        } catch (Exception e) {
            CLog.e("Maps exec path check failed", e);
        }
        return false;
    }
}
