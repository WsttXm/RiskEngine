package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ReflectionUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HookFrameworkDetector extends BaseDetector {

    public HookFrameworkDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "hook_framework";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();

        checkXposed(evidence);
        checkFrida(evidence);
        checkNativeHooks(evidence);

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.DEADLY, String.join("; ", evidence));
        }
        return safe();
    }

    private void checkXposed(List<String> evidence) {
        // Check for Xposed's sHookedMethodCallbacks
        try {
            ClassLoader cl = ClassLoader.getSystemClassLoader();
            Class<?> xposedBridge = cl.loadClass("de.robv.android.xposed.XposedBridge");
            if (xposedBridge != null) {
                evidence.add("xposed_class_found");
                Field field = xposedBridge.getDeclaredField("sHookedMethodCallbacks");
                field.setAccessible(true);
                Object callbacks = field.get(null);
                if (callbacks instanceof Map && !((Map<?, ?>) callbacks).isEmpty()) {
                    evidence.add("xposed_hooks_active:" + ((Map<?, ?>) callbacks).size());
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
                    evidence.add("xposed_stack:" + elem.getClassName());
                    break;
                }
            }
        } catch (Exception ignored) {}
    }

    private void checkFrida(List<String> evidence) {
        // Check /proc/self/maps for Frida
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") || lower.contains("gadget")) {
                    evidence.add("frida_maps:" + line.trim());
                    break;
                }
            }
        } catch (Exception ignored) {}

        // Check Frida default port
        try {
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", 27042), 100);
            socket.close();
            evidence.add("frida_port_open:27042");
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
                                evidence.add("frida_thread:" + threadName);
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    private void checkNativeHooks(List<String> evidence) {
        try {
            if (NativeCollectorBridge.nativeCheckHooks()) {
                String nativeEvidence = NativeCollectorBridge.nativeGetHookEvidence();
                if (nativeEvidence != null && !nativeEvidence.isEmpty()) {
                    evidence.add("native:" + nativeEvidence);
                }
            }
        } catch (Exception e) {
            CLog.e("Native hook check failed", e);
        }
    }
}
