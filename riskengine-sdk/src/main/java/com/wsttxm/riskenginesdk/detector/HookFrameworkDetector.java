package com.wsttxm.riskenginesdk.detector;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.HookEvidenceClassifier;
import com.wsttxm.riskenginesdk.detector.probe.hook.LsposedProbe;
import com.wsttxm.riskenginesdk.detector.probe.hook.SelfIntegrityProbe;
import com.wsttxm.riskenginesdk.detector.probe.hook.ZygiskProbe;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
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
    private static final int[] EXTRA_FRIDA_DBUS_PORTS = {27043, 27044, 27045};
    private final SignalSnapshot signals;
    private final PostponedProbeAdapter postponedAdapter;

    /** Injectable seam for deterministic JVM testing of Stage 3 postponed hook probes. */
    public interface PostponedProbeAdapter {
        ZygiskProbe.ProbeResult runZygiskProbe(SignalSnapshot signals);

        LsposedProbe.ProbeResult runLsposedProbe(Context context, SignalSnapshot signals);

        boolean probeExtraFridaDbusPort(int port);
    }

    private PostponedProbeAdapter defaultPostponedAdapter() {
        return new PostponedProbeAdapter() {
            @Override
            public ZygiskProbe.ProbeResult runZygiskProbe(SignalSnapshot sigs) {
                return ZygiskProbe.probe(sigs == null
                        ? NativeCollectorBridge::getZygiskAtexitProbeResult
                        : sigs::getZygiskAtexitProbe);
            }

            @Override
            public LsposedProbe.ProbeResult runLsposedProbe(Context ctx, SignalSnapshot sigs) {
                return LsposedProbe.probe(ctx, sigs);
            }

            @Override
            public boolean probeExtraFridaDbusPort(int port) {
                return probeFridaDbusLoopback(port);
            }
        };
    }

    public HookFrameworkDetector(Context context) {
        this(context, new SignalSnapshot(context), null);
    }

    public HookFrameworkDetector(Context context, SignalSnapshot signals) {
        this(context, signals, null);
    }

    public HookFrameworkDetector(Context context,
                                 SignalSnapshot signals,
                                 PostponedProbeAdapter postponedAdapter) {
        super(context);
        this.signals = signals;
        this.postponedAdapter = postponedAdapter != null
                ? postponedAdapter : defaultPostponedAdapter();
    }

    @Override
    public String getName() {
        return "hook_framework";
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.CRITICAL;
    }

    @Override
    public boolean hasPostponedProbes() {
        return true;
    }

    @Override
    protected DetectionResult detect() {
        LinkedHashSet<String> details = new LinkedHashSet<>();
        List<EvidenceItem> evidenceItems = new ArrayList<>();
        SignalScore score = new SignalScore();
        CheckCoverage coverage = new CheckCoverage();

        checkXposed(details, evidenceItems, score, coverage);
        checkFrida(details, evidenceItems, score, coverage);
        checkNativeHooks(details, evidenceItems, score, coverage);
        checkMonitorFindings(details, evidenceItems, score, coverage);

        if (!details.isEmpty()) {
            List<String> detailList = new ArrayList<>(details);
            DetectionResult base;
            if (score.strong == 0 && score.medium == 0 && score.weak == 0) {
                // Keep loader depth and monitor pass count available for
                // diagnostics, but do not turn context-only data into a hit.
                base = result(RiskLevel.SAFE, DetectionStatus.NORMAL, 0, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            } else if (score.strong >= 2 || (score.strong >= 1 && score.medium >= 2)) {
                base = result(RiskLevel.DEADLY, DetectionStatus.DANGER, 10, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            } else if (score.strong >= 1 || score.medium >= 2) {
                base = result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        detailList, String.join("; ", detailList), coverage);
            } else if (score.medium >= 1) {
                base = result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 2, 10, true,
                        detailList, String.join("; ", detailList), coverage);
            } else {
                base = result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, true,
                        detailList, String.join("; ", detailList), coverage);
            }
            return evidenceItems.isEmpty() ? base : base.withEvidenceItems(evidenceItems);
        }
        return safe(coverage);
    }

    /**
     * Stage 3 postponed pass: runs heavier probes ({@link ZygiskProbe}, {@link LsposedProbe},
     * and bounded extra Frida D-Bus ports 27043–27045 guarded by {@code INTERNET} permission)
     * strictly outside the {@link ScanTier#CRITICAL} fast pass and merges any new findings into
     * {@code priorResult}.
     */
    @Override
    public DetectionResult detectPostponed(DetectionResult priorResult) {
        LinkedHashSet<String> newStrong = new LinkedHashSet<>();
        LinkedHashSet<String> newMedium = new LinkedHashSet<>();
        List<EvidenceItem> newItems = new ArrayList<>();
        int extraSucceeded = 0;

        try {
            ZygiskProbe.ProbeResult zygisk = postponedAdapter.runZygiskProbe(signals);
            if (zygisk != null && zygisk.isUsable()) {
                extraSucceeded++;
                newStrong.addAll(zygisk.getStrongTokens());
                newMedium.addAll(zygisk.getMediumTokens());
                newItems.addAll(zygisk.getEvidenceItems());
            }
        } catch (Exception | LinkageError e) {
            CLog.e("Zygisk postponed probe failed", e);
        }

        try {
            LsposedProbe.ProbeResult lsposed = postponedAdapter.runLsposedProbe(context, signals);
            if (lsposed != null) {
                if (lsposed.getSubProbesRun() > 0) {
                    extraSucceeded++;
                }
                newStrong.addAll(lsposed.getStrongTokens());
                newMedium.addAll(lsposed.getMediumTokens());
                newItems.addAll(lsposed.getEvidenceItems());
            }
        } catch (Exception | LinkageError e) {
            CLog.e("LSPosed postponed probe failed", e);
        }

        try {
            for (int port : EXTRA_FRIDA_DBUS_PORTS) {
                if (postponedAdapter.probeExtraFridaDbusPort(port)) {
                    String token = "frida_dbus_port:" + port;
                    if (newStrong.add(token)) {
                        newItems.add(new EvidenceItem(
                                "frida_dbus_port",
                                EvidenceItem.SourceLayer.JAVA,
                                "127.0.0.1:" + port,
                                "dbus_reject",
                                "frida",
                                EvidenceItem.Rank.STRONG));
                    }
                }
            }
            extraSucceeded++;
        } catch (Exception | LinkageError e) {
            CLog.e("Extra Frida D-Bus port probe failed", e);
        }

        if (newItems.isEmpty() && newStrong.isEmpty() && newMedium.isEmpty()) {
            return priorResult;
        }

        LinkedHashSet<String> mergedDetails = new LinkedHashSet<>();
        List<EvidenceItem> mergedItems = new ArrayList<>();
        SignalScore totalScore = new SignalScore();
        int attempted = extraSucceeded;
        int succeeded = extraSucceeded;
        int failed = 0;
        List<String> failureReasons = new ArrayList<>();

        if (priorResult != null) {
            boolean priorUsable = priorResult.getExecutionStatus() != DetectionExecutionStatus.UNAVAILABLE
                    && priorResult.getExecutionStatus() != DetectionExecutionStatus.ERROR;
            if (priorUsable) {
                ingestTokens(priorResult.getDetails(), mergedDetails, totalScore);
            }
            mergedItems.addAll(priorResult.getEvidenceItems());
            attempted = priorResult.getChecksAttempted() + extraSucceeded;
            succeeded = priorResult.getChecksSucceeded() + extraSucceeded;
            failed = priorResult.getChecksFailed();
            failureReasons.addAll(priorResult.getFailureReasons());
        }

        for (String tok : newStrong) {
            addStrong(mergedDetails, totalScore, tok);
        }
        for (String tok : newMedium) {
            addMedium(mergedDetails, totalScore, tok);
        }
        mergedItems.addAll(newItems);

        RiskLevel level;
        DetectionStatus status;
        int score;
        boolean informational;
        if (totalScore.strong >= 2 || (totalScore.strong >= 1 && totalScore.medium >= 2)) {
            level = RiskLevel.DEADLY;
            status = DetectionStatus.DANGER;
            score = 10;
            informational = false;
        } else if (totalScore.strong >= 1 || totalScore.medium >= 2) {
            level = RiskLevel.HIGH;
            status = DetectionStatus.DANGER;
            score = 8;
            informational = false;
        } else if (totalScore.medium >= 1) {
            level = RiskLevel.MEDIUM;
            status = DetectionStatus.WARNING;
            score = 2;
            informational = true;
        } else {
            level = RiskLevel.LOW;
            status = DetectionStatus.WARNING;
            score = 1;
            informational = true;
        }

        List<String> detailList = new ArrayList<>(mergedDetails);
        DetectionExecutionStatus execStatus = failed > 0
                ? DetectionExecutionStatus.PARTIAL
                : DetectionExecutionStatus.RISK;

        return new DetectionResult(
                getName(),
                level,
                status,
                score,
                10,
                informational,
                execStatus,
                attempted,
                succeeded,
                failed,
                failureReasons,
                detailList,
                mergedItems,
                String.join("; ", detailList)
        ).withScanTier(getScanTier());
    }

    private void checkXposed(Set<String> details, List<EvidenceItem> evidenceItems,
                             SignalScore score, CheckCoverage coverage) {
        // Check for Xposed's sHookedMethodCallbacks
        try {
            Class<?> xposedBridge = loadXposedBridge();
            if (xposedBridge != null) {
                addMedium(details, score, "xposed_class_found");
                evidenceItems.add(new EvidenceItem("xposed_class_found",
                        EvidenceItem.SourceLayer.JAVA, "de.robv.android.xposed.XposedBridge",
                        "class_loaded", "xposed", EvidenceItem.Rank.MEDIUM));
                Field field = xposedBridge.getDeclaredField("sHookedMethodCallbacks");
                field.setAccessible(true);
                Object callbacks = field.get(null);
                if (callbacks instanceof Map && !((Map<?, ?>) callbacks).isEmpty()) {
                    String countStr = String.valueOf(((Map<?, ?>) callbacks).size());
                    addStrong(details, score, "xposed_hooks_active:" + countStr);
                    evidenceItems.add(new EvidenceItem("xposed_hooks_active",
                            EvidenceItem.SourceLayer.JAVA, "sHookedMethodCallbacks",
                            countStr, "xposed", EvidenceItem.Rank.STRONG));
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
                    evidenceItems.add(new EvidenceItem("xposed_stack",
                            EvidenceItem.SourceLayer.JAVA, elem.getClassName(),
                            "stack_frame", "xposed", EvidenceItem.Rank.MEDIUM));
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

    private void checkFrida(Set<String> details, List<EvidenceItem> evidenceItems,
                            SignalScore score, CheckCoverage coverage) {
        // Check /proc/self/maps for Frida
        try {
            SignalResult<List<String>> maps = signals.getSelfMaps();
            if (!maps.isSuccess() || maps.getValue() == null) {
                coverage.failure("frida_maps:" + maps.getFailureReason());
            } else {
            for (String line : maps.getValue()) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.contains("frida") || lower.contains("libgadget.so")) {
                    String mappedPath = extractMapsPath(line);
                    addStrong(details, score, mappedPath.isEmpty()
                            ? "frida_maps" : "frida_maps:" + mappedPath);
                    evidenceItems.add(new EvidenceItem("frida_maps",
                            EvidenceItem.SourceLayer.JAVA, mappedPath,
                            "maps_match", "frida", EvidenceItem.Rank.STRONG));
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
            boolean tcpCheckedOrExpectedRestricted = false;
            if (ports.isSuccess() && ports.getValue() != null) {
                tcpCheckedOrExpectedRestricted = true;
                if (ports.getValue().contains(DEFAULT_FRIDA_PORT)) {
                    addWeak(details, score, "frida_port_open:" + DEFAULT_FRIDA_PORT);
                    evidenceItems.add(new EvidenceItem("frida_port_open",
                            EvidenceItem.SourceLayer.JAVA, "127.0.0.1:" + DEFAULT_FRIDA_PORT,
                            "listening", "frida", EvidenceItem.Rank.WEAK));
                }
            } else if (ports.getStatus() == SignalResult.Status.UNAVAILABLE) {
                // On Android 10+ (API 30+), SELinux restricts /proc/net/tcp{,6} for normal apps.
                // Visibility loss must never degrade a clean device from SAFE to UNKNOWN.
                tcpCheckedOrExpectedRestricted = true;
            } else {
                coverage.failure("frida_ports:" + ports.getFailureReason());
            }
            if (probeFridaDbusLoopback(DEFAULT_FRIDA_PORT)) {
                addStrong(details, score, "frida_dbus_port:" + DEFAULT_FRIDA_PORT);
                evidenceItems.add(new EvidenceItem("frida_dbus_port",
                        EvidenceItem.SourceLayer.JAVA, "127.0.0.1:" + DEFAULT_FRIDA_PORT,
                        "dbus_reject", "frida", EvidenceItem.Rank.STRONG));
            }
            if (tcpCheckedOrExpectedRestricted) coverage.success();
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
                                String marker = matchingThreadMarker(lower);
                                addMedium(details, score, "frida_thread:" + marker);
                                evidenceItems.add(new EvidenceItem("frida_thread",
                                        EvidenceItem.SourceLayer.JAVA, comm.getPath(),
                                        marker, "frida", EvidenceItem.Rank.MEDIUM));
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
                evidenceItems.add(new EvidenceItem("frida_pid",
                        EvidenceItem.SourceLayer.JAVA, "/proc/" + pid,
                        String.valueOf(pid), "frida", EvidenceItem.Rank.STRONG));
                for (Integer port : ProcfsUtils.findPidLoopbackListeningPorts(pid)) {
                    addStrong(details, score, "frida_pid_port:" + port);
                    evidenceItems.add(new EvidenceItem("frida_pid_port",
                            EvidenceItem.SourceLayer.JAVA, "127.0.0.1:" + port,
                            String.valueOf(port), "frida", EvidenceItem.Rank.STRONG));
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
            // Keep CRITICAL fast-path non-blocking / strictly bounded (< 70ms worst-case).
            socket.connect(new InetSocketAddress("127.0.0.1", port), 35);
            socket.setSoTimeout(35);
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

    private static String extractMapsPath(String mapsLine) {
        if (mapsLine == null) return "";
        String[] parts = mapsLine.trim().split("\\s+", 6);
        return parts.length >= 6 ? parts[5].trim() : "";
    }

    private void checkNativeHooks(Set<String> details, List<EvidenceItem> evidenceItems,
                                  SignalScore score, CheckCoverage coverage) {
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
            SelfIntegrityProbe.ProbeResult parsed =
                    SelfIntegrityProbe.parseNativeHookPayload(nativeResult.getValue());
            if (parsed.getStatus() == NativePayloadCodec.Status.ERROR || parsed.isMalformed()) {
                coverage.failure("native_hook:payload_" + parsed.getStatus().name().toLowerCase(Locale.ROOT));
                return;
            }
            if (parsed.getStatus() == NativePayloadCodec.Status.OK) {
                ingestTokens(parsed.getTokens(), details, score);
                evidenceItems.addAll(parsed.getEvidenceItems());
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
    private void checkMonitorFindings(Set<String> details, List<EvidenceItem> evidenceItems,
                                      SignalScore score, CheckCoverage coverage) {
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
            SelfIntegrityProbe.ProbeResult parsed =
                    SelfIntegrityProbe.parseNativeHookPayload(findings.getValue());
            if (parsed.getStatus() == NativePayloadCodec.Status.OK && !parsed.isMalformed()) {
                ingestTokens(parsed.getTokens(), details, score);
                evidenceItems.addAll(parsed.getEvidenceItems());
            }
        } catch (Exception | LinkageError e) {
            CLog.e("Monitor findings check failed", e);
            coverage.failure("monitor:" + e.getClass().getSimpleName());
        }
    }

    private void ingestTokens(List<String> tokens, Set<String> details, SignalScore score) {
        for (String token : tokens) {
            if (token == null || token.isEmpty()) continue;
            switch (HookEvidenceClassifier.rank(token)) {
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
