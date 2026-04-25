package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class HookFrameworkDetector extends BaseDetector {

    private static final int DEFAULT_FRIDA_PORT = 27042;
    private static final int PROBE_TIMEOUT_MS = 120;

    public HookFrameworkDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "hook_framework";
    }

    @Override
    protected DetectionResult detect() {
        LinkedHashSet<String> details = new LinkedHashSet<>();
        SignalScore score = new SignalScore();

        checkXposed(details, score);
        checkFrida(details, score);
        checkNativeHooks(details, score);

        if (!details.isEmpty()) {
            List<String> detailList = new ArrayList<>(details);
            if (score.strong >= 2 || (score.strong >= 1 && score.medium >= 2)) {
                return result(RiskLevel.DEADLY, DetectionStatus.DANGER, 10, 10, false,
                        detailList, String.join("; ", detailList));
            }
            if (score.strong >= 1 || score.medium >= 2) {
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        detailList, String.join("; ", detailList));
            }
            return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                    detailList, String.join("; ", detailList));
        }
        return safe();
    }

    private void checkXposed(Set<String> details, SignalScore score) {
        // Check for Xposed's sHookedMethodCallbacks
        try {
            ClassLoader cl = ClassLoader.getSystemClassLoader();
            Class<?> xposedBridge = cl.loadClass("de.robv.android.xposed.XposedBridge");
            if (xposedBridge != null) {
                addMedium(details, score, "xposed_class_found");
                Field field = xposedBridge.getDeclaredField("sHookedMethodCallbacks");
                field.setAccessible(true);
                Object callbacks = field.get(null);
                if (callbacks instanceof Map && !((Map<?, ?>) callbacks).isEmpty()) {
                    addStrong(details, score, "xposed_hooks_active:" + ((Map<?, ?>) callbacks).size());
                }
            }
        } catch (ClassNotFoundException ignored) {
            // Xposed not present
        } catch (Exception e) {
            CLog.e("Xposed check error", e);
        }

        // Check stack trace for Xposed
        try {
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                if (elem.getClassName().contains("xposed") ||
                        elem.getClassName().contains("lsposed") ||
                        elem.getClassName().contains("edxposed")) {
                    addMedium(details, score, "xposed_stack:" + elem.getClassName());
                    break;
                }
            }
        } catch (Exception ignored) {}
    }

    private void checkFrida(Set<String> details, SignalScore score) {
        // Check /proc/self/maps for Frida
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") || lower.contains("gadget")) {
                    addStrong(details, score, "frida_maps:" + line.trim());
                    break;
                }
            }
        } catch (Exception ignored) {}

        // Check Frida default port
        try {
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", DEFAULT_FRIDA_PORT), PROBE_TIMEOUT_MS);
            socket.close();
            addMedium(details, score, "frida_port_open:" + DEFAULT_FRIDA_PORT);
        } catch (Exception ignored) {}

        // Check threads for Frida
        try {
            java.io.File taskDir = new java.io.File("/proc/self/task");
            java.io.File[] tasks = taskDir.listFiles();
            if (tasks != null) {
                for (java.io.File task : tasks) {
                    java.io.File comm = new java.io.File(task, "comm");
                    if (comm.exists()) {
                        try (BufferedReader br = new BufferedReader(new FileReader(comm))) {
                            String threadName = br.readLine();
                            if (threadName != null && (threadName.contains("gum-js-loop") ||
                                    threadName.contains("gmain") ||
                                    threadName.contains("frida"))) {
                                addMedium(details, score, "frida_thread:" + threadName);
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        try {
            Set<Integer> loopbackPorts = ProcfsUtils.findLoopbackListeningPorts();
            for (Integer port : loopbackPorts) {
                if (port == null || port <= 0) {
                    continue;
                }
                String response = ProcfsUtils.probeDbus(port, PROBE_TIMEOUT_MS);
                if (response.toUpperCase().startsWith("REJECT")) {
                    addStrong(details, score, "dbus_reject:" + port);
                }
            }
        } catch (Exception e) {
            CLog.e("D-Bus probe failed", e);
        }

        try {
            List<Integer> pids = ProcfsUtils.findPidsByNameFragments("frida-server", "frida_helper");
            for (Integer pid : pids) {
                addStrong(details, score, "frida_pid:" + pid);
                for (Integer port : ProcfsUtils.findPidLoopbackListeningPorts(pid)) {
                    addStrong(details, score, "frida_pid_port:" + port);
                }
            }
        } catch (Exception e) {
            CLog.e("Frida pid correlation failed", e);
        }
    }

    private void checkNativeHooks(Set<String> details, SignalScore score) {
        try {
            String nativeEvidence = NativeCollectorBridge.nativeGetHookEvidence();
            if (nativeEvidence != null && !nativeEvidence.isEmpty()) {
                for (String item : nativeEvidence.split(",")) {
                    String token = item.trim();
                    if (token.isEmpty()) {
                        continue;
                    }
                    if (token.startsWith("anon_exec:")
                            || token.startsWith("trampoline:")
                            || token.startsWith("sigtrap:")
                            || token.startsWith("maps:frida")
                            || token.startsWith("maps:gadget")) {
                        addStrong(details, score, token);
                    } else if (token.startsWith("thread:")
                            || token.startsWith("maps:xposed")
                            || token.startsWith("maps:substrate")) {
                        addMedium(details, score, token);
                    } else {
                        addWeak(details, score, token);
                    }
                }
            }
        } catch (Exception e) {
            CLog.e("Native hook check failed", e);
        }
    }

    private void addStrong(Set<String> details, SignalScore score, String detail) {
        if (details.add(detail)) {
            score.strong++;
        }
    }

    private void addMedium(Set<String> details, SignalScore score, String detail) {
        if (details.add(detail)) {
            score.medium++;
        }
    }

    private void addWeak(Set<String> details, SignalScore score, String detail) {
        if (details.add(detail)) {
            score.weak++;
        }
    }

    private static final class SignalScore {
        private int strong;
        private int medium;
        private int weak;
    }
}
