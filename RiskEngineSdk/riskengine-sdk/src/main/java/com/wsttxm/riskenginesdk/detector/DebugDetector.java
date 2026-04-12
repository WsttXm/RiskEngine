package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

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
        List<String> evidence = new ArrayList<>();

        checkTracerPid(evidence);
        checkDebuggable(evidence);
        checkIdaPort(evidence);
        checkNativePtrace(evidence);

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.HIGH, String.join("; ", evidence));
        }
        return safe();
    }

    private void checkTracerPid(List<String> evidence) {
        try {
            int tracerPid = NativeCollectorBridge.nativeGetTracerPid();
            if (tracerPid > 0) {
                evidence.add("tracer_pid:" + tracerPid);
            }
        } catch (Exception e) {
            // Fallback: read from Java
            try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/status"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        int pid = Integer.parseInt(line.split(":")[1].trim());
                        if (pid > 0) {
                            evidence.add("tracer_pid:" + pid);
                        }
                        break;
                    }
                }
            } catch (Exception ex) {
                CLog.e("TracerPid check failed", ex);
            }
        }
    }

    private void checkDebuggable(List<String> evidence) {
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                evidence.add("debuggable_flag");
            }
        } catch (Exception e) {
            CLog.e("Debuggable check failed", e);
        }
    }

    private void checkIdaPort(List<String> evidence) {
        // IDA default debug port
        try {
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", 23946), 100);
            socket.close();
            evidence.add("ida_port_open:23946");
        } catch (Exception ignored) {}
    }

    private void checkNativePtrace(List<String> evidence) {
        try {
            if (NativeCollectorBridge.nativeCheckPtrace()) {
                evidence.add("ptrace_detected");
            }
        } catch (Exception e) {
            CLog.e("Native ptrace check failed", e);
        }
    }
}
