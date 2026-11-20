package com.wsttxm.riskenginesdk.detector;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;

public class HookFrameworkDetector extends BaseDetector {

    private static final int DEFAULT_FRIDA_PORT = 27042;
    private final SignalSnapshot signals;

    public HookFrameworkDetector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public HookFrameworkDetector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "hook_framework";
    }

    @Override
    protected DetectionResult detect() {
        LinkedHashSet<String> details = new LinkedHashSet<>();
        SignalScore score = new SignalScore();
        CheckCoverage coverage = new CheckCoverage();

        checkXposed(details, score, coverage);
        checkFrida(details, score, coverage);
        checkNativeHooks(details, score, coverage);
        checkMonitorFindings(details, score, coverage);

        if (!details.isEmpty()) {
            List<String> detailList = new ArrayList<>(details);
            if (score.strong == 0 && score.medium == 0 && score.weak == 0) {
                // Keep loader depth and monitor pass count available for
                // diagnostics, but do not turn context-only data into a hit.
                return result(RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            }
            if (score.strong >= 2 || (score.strong >= 1 && score.medium >= 2)) {
                return result(RiskLevel.DEADLY, DetectionStatus.DANGER, 10, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            }
            if (score.strong >= 1 || score.medium >= 2) {
                return result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            }
            if (score.medium >= 1) {
                return result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 2, 10, true,
                        detailList, String.join("; ", detailList), coverage);
            }
            return result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                    detailList, String.join("; ", detailList), coverage);
        }
        return safe(coverage);
    }

    private void checkXposed(Set<String> details, SignalScore score, CheckCoverage coverage) {
        // Check for Xposed's sHookedMethodCallbacks
        try {
            Class<?> xposedBridge = loadXposedBridge();
            if (xposedBridge != null) {
                addMedium(details, score, "xposed_class_found");
                Field field = xposedBridge.getDeclaredField("sHookedMethodCallbacks");
                field.setAccessible(true);
                Object callbacks = field.get(null);
                if (callbacks instanceof Map && !((Map<?, ?>) callbacks).isEmpty()) {
                    addStrong(details, score, "xposed_hooks_active:" + ((Map<?, ?>) callbacks).size());
                }
            }
            coverage.success();
        } catch (ClassNotFoundException ignored) {
            // Xposed not present
            coverage.success();
        } catch (Exception e) {
            CLog.e("Xposed check error", e);
            coverage.failure("xposed_class:" + e.getClass().getSimpleName());
        }

        // Check stack trace for Xposed
        try {
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName().toLowerCase(Locale.ROOT);
                if (cls.contains("xposed")
                        || cls.contains("lsposed")
                        || cls.contains("edxposed")) {
                    addMedium(details, score, "xposed_stack:" + elem.getClassName());
                    break;
                }
            }
            coverage.success();
        } catch (Exception e) {
            coverage.failure("xposed_stack:" + e.getClass().getSimpleName());
        }
    }

    private Class<?> loadXposedBridge() throws ClassNotFoundException {
        String className = "de.robv.android.xposed.XposedBridge";
        ClassLoader[] loaders = {
                context == null ? null : context.getClassLoader(),
                HookFrameworkDetector.class.getClassLoader(),
                Thread.currentThread().getContextClassLoader(),
                ClassLoader.getSystemClassLoader()
        };
        for (ClassLoader loader : loaders) {
            if (loader == null) {
                continue;
            }
            try {
                return Class.forName(className, false, loader);
            } catch (ClassNotFoundException ignored) {
                // Try the next loader. Injected frameworks are commonly visible
                // from the application loader but not the system loader.
            }
        }
        throw new ClassNotFoundException(className);
    }

    private void checkFrida(Set<String> details, SignalScore score, CheckCoverage coverage) {
        // Check /proc/self/maps for Frida
        try {
            SignalResult<List<String>> maps = signals.getSelfMaps();
            if (!maps.isSuccess() || maps.getValue() == null) {
                coverage.failure("frida_maps:" + maps.getFailureReason());
            } else {
            for (String line : maps.getValue()) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.contains("frida") || lower.contains("libgadget.so")) {
                    addStrong(details, score, "frida_maps");
                    break;
                }
            }
            coverage.success();
            }
        } catch (Exception e) {
            coverage.failure("frida_maps:" + e.getClass().getSimpleName());
        }

        // Observe the TCP table; when the host app holds INTERNET permission,
        // also perform a short loopback D-Bus AUTH handshake on port 27042 so
        // idle frida-server / renamed server daemons are caught even on Android 10+
        // where /proc/net/tcp is SELinux-blocked.
        try {
            SignalResult<Set<Integer>> ports = signals.getLoopbackListeningPorts();
            if (!ports.isSuccess() || ports.getValue() == null) {
                coverage.failure("frida_ports:" + ports.getFailureReason());
            } else if (ports.getValue().contains(DEFAULT_FRIDA_PORT)) {
                addWeak(details, score, "frida_port_open:" + DEFAULT_FRIDA_PORT);
            }
            if (probeFridaDbusLoopback(DEFAULT_FRIDA_PORT)) {
                addStrong(details, score, "frida_dbus_port:" + DEFAULT_FRIDA_PORT);
            }
            if (ports.isSuccess()) coverage.success();
        } catch (Exception e) {
            coverage.failure("frida_ports:" + e.getClass().getSimpleName());
        }

        // Check threads for Frida
        try {
            java.io.File taskDir = new java.io.File("/proc/self/task");
            java.io.File[] tasks = taskDir.listFiles();
            boolean sawGmain = false;
            boolean sawFridaThread = false;
            if (tasks != null) {
                for (java.io.File task : tasks) {
                    java.io.File comm = new java.io.File(task, "comm");
                    if (comm.exists()) {
                        try (BufferedReader br = new BufferedReader(new FileReader(comm))) {
                            String threadName = br.readLine();
                            if (threadName == null) continue;
                            String lower = threadName.toLowerCase(Locale.ROOT);
                            if (lower.contains("gum-js-loop") || lower.contains("frida")) {
                                sawFridaThread = true;
                                addMedium(details, score,
                                        "frida_thread:" + matchingThreadMarker(lower));
                            } else if (lower.contains("gmain")) {
                                sawGmain = true;
                            }
                        }
                    }
                }
            }
            // Standalone gmain belongs to benign GLib apps; only attach as diagnostic
            // context when a Frida-specific thread was also observed.
            if (sawGmain && sawFridaThread) {
                details.add("thread:gmain");
            }
            if (tasks == null) {
                coverage.failure("frida_threads:procfs_unavailable");
            } else {
                coverage.success();
            }
        } catch (Exception e) {
            coverage.failure("frida_threads:" + e.getClass().getSimpleName());
        }

        try {
            SignalResult<List<ProcfsUtils.ProcessInfo>> processes = signals.getProcesses();
            if (!processes.isSuccess() || processes.getValue() == null) {
                coverage.failure("frida_processes:" + processes.getFailureReason());
                return;
            }
            List<Integer> pids = ProcfsUtils.findPidsByNameFragments(
                    processes.getValue(), "frida-server", "frida_helper");
            for (Integer pid : pids) {
                addStrong(details, score, "frida_pid:" + pid);
                for (Integer port : ProcfsUtils.findPidLoopbackListeningPorts(pid)) {
                    addStrong(details, score, "frida_pid_port:" + port);
                }
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Frida pid correlation failed", e);
            coverage.failure("frida_processes:" + e.getClass().getSimpleName());
        }
    }

    private boolean probeFridaDbusLoopback(int port) {
        if (context == null || context.checkSelfPermission(Manifest.permission.INTERNET)
                != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 120);
            socket.setSoTimeout(120);
            OutputStream out = socket.getOutputStream();
            out.write("\0AUTH\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] buf = new byte[64];
            int n = in.read(buf);
            if (n > 0) {
                String reply = new String(buf, 0, n, StandardCharsets.US_ASCII);
                return reply.contains("REJECT");
            }
        } catch (Exception ignored) {
            // Connection refused / timeout means no D-Bus server on this port.
        }
        return false;
    }

    private String matchingThreadMarker(String threadName) {
        if (threadName.contains("gum-js-loop")) return "gum-js-loop";
        if (threadName.contains("frida")) return "frida";
        return "gmain";
    }

    private void checkNativeHooks(Set<String> details, SignalScore score, CheckCoverage coverage) {
        if (!NativeCollectorBridge.isNativeAvailable()) {
            coverage.failure("native_hook:unavailable");
            return;
        }
        try {
            SignalResult<String> nativeResult = NativeCollectorBridge.getHookEvidenceResult();
            if (!nativeResult.isSuccess()) {
                coverage.failure("native_hook:" + nativeResult.getFailureReason());
                return;
            }
            String nativeEvidence = nativeResult.getValue();
            if (nativeEvidence != null && !nativeEvidence.isEmpty()) {
                for (String item : nativeEvidence.split(",")) {
                    String token = item.trim();
                    if (token.isEmpty()) {
                        continue;
                    }
                    switch (com.wsttxm.riskenginesdk.core.HookEvidenceClassifier.rank(token)) {
                        case STRONG:
                            addStrong(details, score, token);
                            break;
                        case MEDIUM:
                            addMedium(details, score, token);
                            break;
                        case IGNORE:
                            details.add(token);
                            break;
                        case WEAK:
                        default:
                            addWeak(details, score, token);
                            break;
                    }
                }
            }
            coverage.success();
        } catch (Exception | LinkageError e) {
            CLog.e("Native hook check failed", e);
            coverage.failure("native_hook:" + e.getClass().getSimpleName());
        }
    }

    /**
     * Consumes what the native background monitor latched since library load.
     *
     * This is the only path that reports tampering installed after the initial
     * snapshot. The pass count is recorded but never scored: it distinguishes
     * "monitored and clean" from "never ran", which the coverage model needs.
     */
    private void checkMonitorFindings(Set<String> details, SignalScore score,
                                      CheckCoverage coverage) {
        if (!NativeCollectorBridge.isNativeAvailable()) {
            coverage.failure("monitor:unavailable");
            return;
        }
        try {
            SignalResult<String> findings = NativeCollectorBridge.getMonitorFindingsResult();
            if (!findings.isSuccess() || findings.getValue() == null) {
                coverage.failure("monitor:" + findings.getFailureReason());
                return;
            }
            coverage.success();
            for (String token : findings.getValue().split(",")) {
                String item = token.trim();
                if (item.isEmpty()) continue;
                switch (com.wsttxm.riskenginesdk.core.HookEvidenceClassifier.rank(item)) {
                    case STRONG:
                        addStrong(details, score, item);
                        break;
                    case MEDIUM:
                        addMedium(details, score, item);
                        break;
                    case IGNORE:
                        details.add(item);
                        break;
                    case WEAK:
                    default:
                        addWeak(details, score, item);
                        break;
                }
            }
        } catch (Exception | LinkageError e) {
            CLog.e("Monitor findings check failed", e);
            coverage.failure("monitor:" + e.getClass().getSimpleName());
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
