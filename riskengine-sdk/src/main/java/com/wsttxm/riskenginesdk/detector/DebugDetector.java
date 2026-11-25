package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;

import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * CRITICAL-tier debugger & anti-attach detector ({@code debug}).
 *
 * <p>Consumes dual-path native debug evidence ({@code /proc/self/status},
 * {@code /proc/<pid>/task/<pid>/status}, per-thread {@code status/stat/wchan/comm},
 * and {@code @jdwp-control}) alongside Java {@link Debug} / maps / port checks, emitting
 * structured {@link EvidenceItem} entries under the {@code debugger} family while preserving
 * {@code debuggable_flag}-only informational semantics across all scenes.
 */
public class DebugDetector extends BaseDetector {
    private static final String FAMILY_DEBUGGER = "debugger";

    private final SignalSnapshot signals;
    private final DebugEnvironment env;

    public DebugDetector(Context context) {
        this(context, new SignalSnapshot(context), null);
    }

    public DebugDetector(Context context, SignalSnapshot signals) {
        this(context, signals, null);
    }

    /** Internal test seam for deterministic pure-JVM unit tests (not part of public SDK contract). */
    public static DebugDetector createForTest(Context context,
                                              SignalSnapshot signals,
                                              DebugEnvironment env) {
        return new DebugDetector(context, signals, env);
    }

    DebugDetector(Context context, SignalSnapshot signals, DebugEnvironment env) {
        super(context);
        this.signals = signals != null ? signals : new SignalSnapshot(context);
        this.env = env != null ? env : new AndroidDebugEnvironment();
    }

    @Override
    public String getName() {
        return "debug";
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.CRITICAL;
    }

    @Override
    protected DetectionResult detect() {
        LinkedHashSet<String> details = new LinkedHashSet<>();
        Map<String, EvidenceItem> evidenceByKey = new LinkedHashMap<>();
        SignalFlags flags = new SignalFlags();
        CheckCoverage coverage = new CheckCoverage();

        boolean debuggableApp = checkDebuggable(details, evidenceByKey, flags, coverage);
        checkNativeAndProcfsDebugSignals(details, evidenceByKey, flags, coverage, debuggableApp);
        checkIdaPort(details, evidenceByKey, flags, coverage);
        checkDebuggerConnection(details, evidenceByKey, flags, coverage);
        checkMapsExecPath(details, evidenceByKey, flags, coverage);

        DetectionResult result;
        if (!details.isEmpty()) {
            List<String> detailList = new ArrayList<>(details);
            String evidence = String.join("; ", detailList);
            if (flags.strong) {
                result = result(RiskLevel.HIGH, DetectionStatus.DANGER, 8, 10, false,
                        detailList, evidence, coverage);
            } else if (flags.medium) {
                result = result(RiskLevel.MEDIUM, DetectionStatus.WARNING, 4, 10, false,
                        detailList, evidence, coverage);
            } else {
                result = result(RiskLevel.LOW, DetectionStatus.WARNING, 1, 10, flags.weak,
                        detailList, evidence, coverage);
            }
        } else {
            result = safe(coverage);
        }

        if (!evidenceByKey.isEmpty()) {
            result = result.withEvidenceItems(new ArrayList<>(evidenceByKey.values()));
        }
        return result;
    }

    private void checkNativeAndProcfsDebugSignals(Set<String> details,
                                                  Map<String, EvidenceItem> evidenceByKey,
                                                  SignalFlags flags,
                                                  CheckCoverage coverage,
                                                  boolean debuggableApp) {
        // 1. Prefer rich NativePayloadCodec frame (dual-path TracerPid, stat 't', wchan, JDWP)
        try {
            SignalResult<String> nativeEv = env.getNativeDebugEvidence();
            if (nativeEv != null && nativeEv.isSuccess() && nativeEv.getValue() != null
                    && !nativeEv.getValue().isBlank()) {
                NativePayloadCodec.DecodedPayload decoded =
                        NativePayloadCodec.decodePayload(nativeEv.getValue());
                if (decoded != null && !decoded.isMalformed()
                        && decoded.getStatus() == NativePayloadCodec.Status.OK) {
                    applyNativeDebugPayload(decoded, details, evidenceByKey, flags, debuggableApp);
                    coverage.success();
                    return;
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Native debug evidence frame failed, falling back to TracerPid", e);
        }

        // 2. Fallback to legacy native TracerPid integer JNI call
        try {
            SignalResult<Integer> nativeTracer = env.getNativeTracerPid();
            if (nativeTracer != null && nativeTracer.isSuccess() && nativeTracer.getValue() != null) {
                int tracerPid = nativeTracer.getValue();
                if (tracerPid > 0) {
                    addFinding(details, evidenceByKey, "tracer_pid:" + tracerPid,
                            "tracer_pid", EvidenceItem.SourceLayer.NATIVE,
                            "/proc/self/status", String.valueOf(tracerPid),
                            EvidenceItem.Rank.STRONG);
                    flags.strong = true;
                    coverage.success();
                    return;
                }
                if (tracerPid == 0) {
                    coverage.success();
                    return;
                }
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            CLog.e("Native TracerPid check failed, using procfs", e);
        }

        // 3. Final Java procfs fallback
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    int pid = Integer.parseInt(line.split(":")[1].trim());
                    if (pid > 0) {
                        addFinding(details, evidenceByKey, "tracer_pid:" + pid,
                                "tracer_pid", EvidenceItem.SourceLayer.JAVA,
                                "/proc/self/status", String.valueOf(pid),
                                EvidenceItem.Rank.STRONG);
                        flags.strong = true;
                    }
                    coverage.success();
                    return;
                }
            }
        } catch (Exception e) {
            CLog.e("TracerPid check failed", e);
            coverage.failure("tracer_pid:" + e.getClass().getSimpleName());
            return;
        }
        coverage.failure("tracer_pid:missing_field");
    }

    private static void applyNativeDebugPayload(NativePayloadCodec.DecodedPayload decoded,
                                                Set<String> details,
                                                Map<String, EvidenceItem> evidenceByKey,
                                                SignalFlags flags,
                                                boolean debuggableApp) {
        for (Map<String, String> record : decoded.getRecords()) {
            String code = record.get("code");
            String value = record.get("value");
            String loc = record.get("loc");
            if (code == null || code.isBlank()) continue;
            String val = value == null ? "" : value;
            String location = loc == null ? "" : loc;

            switch (code) {
                case "tracer_pid":
                    addFinding(details, evidenceByKey, "tracer_pid:" + val,
                            "tracer_pid", EvidenceItem.SourceLayer.NATIVE,
                            location, val, EvidenceItem.Rank.STRONG);
                    flags.strong = true;
                    break;
                case "tracer_pid_mismatch":
                    addFinding(details, evidenceByKey, "tracer_pid_mismatch:" + val,
                            "tracer_pid_mismatch", EvidenceItem.SourceLayer.NATIVE,
                            location, val, EvidenceItem.Rank.STRONG);
                    flags.strong = true;
                    break;
                case "stat_tracing_stop":
                    addFinding(details, evidenceByKey, "stat_tracing_stop:" + val,
                            "stat_tracing_stop", EvidenceItem.SourceLayer.NATIVE,
                            location, val, EvidenceItem.Rank.STRONG);
                    flags.strong = true;
                    break;
                case "wchan_ptrace_stop":
                    addFinding(details, evidenceByKey, "wchan_ptrace_stop:" + val,
                            "wchan_ptrace_stop", EvidenceItem.SourceLayer.NATIVE,
                            location, val, EvidenceItem.Rank.STRONG);
                    flags.strong = true;
                    break;
                case "jdwp_thread":
                    // On Android 11+, ART spawns an idle "ADB-JDWP Connection Control Thread"
                    // automatically for every FLAG_DEBUGGABLE build even with no debugger attached.
                    // Keep informational on debuggable builds; score MEDIUM on release builds.
                    if (debuggableApp) {
                        addFinding(details, evidenceByKey, "jdwp_thread:" + val,
                                "jdwp_thread", EvidenceItem.SourceLayer.NATIVE,
                                location, val, EvidenceItem.Rank.INFO);
                        flags.weak = true;
                    } else {
                        addFinding(details, evidenceByKey, "jdwp_thread:" + val,
                                "jdwp_thread", EvidenceItem.SourceLayer.NATIVE,
                                location, val, EvidenceItem.Rank.MEDIUM);
                        flags.medium = true;
                    }
                    break;
                case "jdwp_socket":
                    if (debuggableApp) {
                        addFinding(details, evidenceByKey, "jdwp_socket:" + val,
                                "jdwp_socket", EvidenceItem.SourceLayer.NATIVE,
                                location, val, EvidenceItem.Rank.INFO);
                        flags.weak = true;
                    } else {
                        addFinding(details, evidenceByKey, "jdwp_socket:" + val,
                                "jdwp_socket", EvidenceItem.SourceLayer.NATIVE,
                                location, val, EvidenceItem.Rank.MEDIUM);
                        flags.medium = true;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    private boolean checkDebuggable(Set<String> details,
                                    Map<String, EvidenceItem> evidenceByKey,
                                    SignalFlags flags,
                                    CheckCoverage coverage) {
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                addFinding(details, evidenceByKey, "debuggable_flag",
                        "debuggable_flag", EvidenceItem.SourceLayer.JAVA,
                        "ApplicationInfo.flags", "FLAG_DEBUGGABLE",
                        EvidenceItem.Rank.INFO);
                flags.weak = true;
                coverage.success();
                return true;
            }
            coverage.success();
            return false;
        } catch (Exception | LinkageError e) {
            CLog.e("Debuggable check failed", e);
            coverage.failure("debuggable:" + e.getClass().getSimpleName());
            return false;
        }
    }

    private void checkIdaPort(Set<String> details,
                              Map<String, EvidenceItem> evidenceByKey,
                              SignalFlags flags,
                              CheckCoverage coverage) {
        try {
            SignalResult<Set<Integer>> ports = signals.getLoopbackListeningPorts();
            if (ports.getStatus() == SignalResult.Status.UNAVAILABLE) {
                // On Android 10+ (API 30+), SELinux restricts /proc/net/tcp{,6} for normal apps.
                // Visibility loss must never degrade a clean device from SAFE to UNKNOWN.
                coverage.success();
                return;
            }
            if (!ports.isSuccess() || ports.getValue() == null) {
                coverage.failure("ida_port:" + ports.getFailureReason());
                return;
            }
            if (!ports.getValue().contains(23946)) {
                coverage.success();
                return;
            }
            addFinding(details, evidenceByKey, "ida_port_open:23946",
                    "ida_port_open", EvidenceItem.SourceLayer.JAVA,
                    "127.0.0.1:23946", "23946", EvidenceItem.Rank.WEAK);
            flags.weak = true;
            coverage.success();
        } catch (Exception e) {
            coverage.failure("ida_port:" + e.getClass().getSimpleName());
        }
    }

    private void checkDebuggerConnection(Set<String> details,
                                         Map<String, EvidenceItem> evidenceByKey,
                                         SignalFlags flags,
                                         CheckCoverage coverage) {
        try {
            if (env.isDebuggerConnected() || env.isWaitingForDebugger()) {
                addFinding(details, evidenceByKey, "debugger_connected",
                        "debugger_connected", EvidenceItem.SourceLayer.JAVA,
                        "android.os.Debug", "connected_or_waiting",
                        EvidenceItem.Rank.MEDIUM);
                flags.medium = true;
                coverage.success();
                return;
            }
            coverage.success();
        } catch (Exception | LinkageError e) {
            CLog.e("Debugger connection check failed", e);
            coverage.failure("debugger_connection:" + e.getClass().getSimpleName());
        }
    }

    private void checkMapsExecPath(Set<String> details,
                                   Map<String, EvidenceItem> evidenceByKey,
                                   SignalFlags flags,
                                   CheckCoverage coverage) {
        try {
            SignalResult<List<String>> maps = signals.getSelfMaps();
            if (!maps.isSuccess() || maps.getValue() == null) {
                coverage.failure("maps_exec_path:" + maps.getFailureReason());
                return;
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
                    String tool = matchingTool(lower);
                    String mappedPath = extractMapsPath(line);
                    String token = mappedPath.isEmpty()
                            ? "maps_exec_path:" + tool
                            : "maps_exec_path:" + tool + ":" + mappedPath;
                    addFinding(details, evidenceByKey, token,
                            "maps_exec_path", EvidenceItem.SourceLayer.JAVA,
                            mappedPath.isEmpty() ? "/proc/self/maps" : mappedPath,
                            tool, EvidenceItem.Rank.MEDIUM);
                    flags.medium = true;
                    coverage.success();
                    return;
                }
            }
            coverage.success();
        } catch (Exception e) {
            CLog.e("Maps exec path check failed", e);
            coverage.failure("maps_exec_path:" + e.getClass().getSimpleName());
        }
    }

    private static void addFinding(Set<String> details,
                                   Map<String, EvidenceItem> evidenceByKey,
                                   String detailToken,
                                   String code,
                                   EvidenceItem.SourceLayer source,
                                   String location,
                                   String value,
                                   EvidenceItem.Rank rank) {
        details.add(detailToken);
        String key = code + "|" + (location == null ? "" : location);
        EvidenceItem item = new EvidenceItem(
                code, source, location, value, FAMILY_DEBUGGER, rank);
        EvidenceItem existing = evidenceByKey.get(key);
        evidenceByKey.put(key, existing == null ? item : existing.mergeWith(item));
    }

    private static String matchingTool(String mapsLine) {
        String[] tools = {"android_server", "gdbserver", "lldb", "frida"};
        for (String tool : tools) {
            if (mapsLine.contains(tool)) {
                return tool;
            }
        }
        return "unknown";
    }

    private static String extractMapsPath(String mapsLine) {
        if (mapsLine == null) return "";
        String[] parts = mapsLine.trim().split("\\s+", 6);
        return parts.length >= 6 ? parts[5].trim() : "";
    }

    private static final class SignalFlags {
        boolean strong;
        boolean medium;
        boolean weak;
    }

    /** Environment abstraction for deterministic pure-JVM unit tests. */
    public interface DebugEnvironment {
        SignalResult<String> getNativeDebugEvidence();
        SignalResult<Integer> getNativeTracerPid();
        boolean isDebuggerConnected();
        boolean isWaitingForDebugger();
    }

    private static final class AndroidDebugEnvironment implements DebugEnvironment {
        @Override
        public SignalResult<String> getNativeDebugEvidence() {
            if (!NativeCollectorBridge.isNativeAvailable()) {
                return SignalResult.unavailable("native_library_unavailable");
            }
            return NativeCollectorBridge.getDebugEvidenceResult();
        }

        @Override
        public SignalResult<Integer> getNativeTracerPid() {
            if (!NativeCollectorBridge.isNativeAvailable()) {
                return SignalResult.unavailable("native_library_unavailable");
            }
            return NativeCollectorBridge.getTracerPidResult();
        }

        @Override
        public boolean isDebuggerConnected() {
            return Debug.isDebuggerConnected();
        }

        @Override
        public boolean isWaitingForDebugger() {
            return Debug.waitingForDebugger();
        }
    }
}
