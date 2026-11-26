package com.wsttxm.riskenginesdk.util;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.collector.native_layer.NativePayloadCodec;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AdbInspector {

    public static final long DEBOUNCE_DELAY_MS = 1500L;

    private AdbInspector() {}

    /** Injectable seam for deterministic zero-sleep JVM tests of conditional 2-sample debounce. */
    public interface ProtocolProbeAdapter {
        SignalResult<String> readNativeAdbProtocol();

        /** Reads {@code Settings.Global.ADB_ENABLED} (0/1), or {@code null} when unreadable. */
        Integer readSettingsAdbEnabled(Context context);

        /** Reads {@code Settings.Global "adb_wifi_enabled"} (0/1), or {@code null} when unreadable. */
        Integer readSettingsAdbWifiEnabled(Context context);

        void sleepMs(long millis) throws InterruptedException;
    }

    private static final ProtocolProbeAdapter DEFAULT_ADAPTER = new ProtocolProbeAdapter() {
        @Override
        public SignalResult<String> readNativeAdbProtocol() {
            return NativeCollectorBridge.getAdbProtocolEvidenceResult();
        }

        @Override
        public Integer readSettingsAdbEnabled(Context context) {
            if (context == null) return null;
            ContentResolver resolver = context.getContentResolver();
            if (resolver == null) return null;
            return Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0);
        }

        @Override
        public Integer readSettingsAdbWifiEnabled(Context context) {
            if (context == null) return null;
            ContentResolver resolver = context.getContentResolver();
            if (resolver == null) return null;
            return Settings.Global.getInt(resolver, "adb_wifi_enabled", 0);
        }

        @Override
        public void sleepMs(long millis) throws InterruptedException {
            if (millis > 0L) {
                Thread.sleep(millis);
            }
        }
    };

    private static final class ProtocolSample {
        final boolean nativeAvailable;
        final String adbdSocketState;
        final String jdwpControlState;
        final String initSvcAdbd;
        final Boolean settingsAdbEnabled;
        final Boolean settingsAdbWifiEnabled;

        ProtocolSample(boolean nativeAvailable,
                       String adbdSocketState,
                       String jdwpControlState,
                       String initSvcAdbd,
                       Boolean settingsAdbEnabled,
                       Boolean settingsAdbWifiEnabled) {
            this.nativeAvailable = nativeAvailable;
            this.adbdSocketState = adbdSocketState == null ? "unknown" : adbdSocketState;
            this.jdwpControlState = jdwpControlState == null ? "unavailable" : jdwpControlState;
            this.initSvcAdbd = initSvcAdbd == null ? "" : initSvcAdbd;
            this.settingsAdbEnabled = settingsAdbEnabled;
            this.settingsAdbWifiEnabled = settingsAdbWifiEnabled;
        }

        boolean isAdbdSocketLive() {
            return "present".equals(adbdSocketState) || "present_denied".equals(adbdSocketState);
        }

        boolean isJdwpControlLive() {
            return "observed".equals(jdwpControlState);
        }

        boolean isProtocolLive() {
            return isAdbdSocketLive() || isJdwpControlLive();
        }

        boolean isInitSvcStopped() {
            return "stopped".equalsIgnoreCase(initSvcAdbd);
        }

        boolean isSettingsDisabled() {
            return Boolean.FALSE.equals(settingsAdbEnabled)
                    && !Boolean.TRUE.equals(settingsAdbWifiEnabled);
        }

        boolean isHiddenContradiction(boolean hasAdbdPid) {
            boolean live = isProtocolLive() || hasAdbdPid;
            if (!live) {
                return false;
            }
            if (isInitSvcStopped()) {
                return true;
            }
            // If Settings explicitly report ADB disabled (0) while kernel socket / @jdwp-control
            // is actively listening, that is a hidden-adbd contradiction.
            return isProtocolLive() && isSettingsDisabled();
        }

        boolean isTransientSplit() {
            boolean socketKnown = isAdbdSocketLive() || "absent".equals(adbdSocketState);
            boolean jdwpKnown = isJdwpControlLive() || "not_observed".equals(jdwpControlState);
            return socketKnown && jdwpKnown && (isAdbdSocketLive() != isJdwpControlLive());
        }
    }

    public static final class Snapshot {
        private final List<String> details = new ArrayList<>();
        private String summary = "disabled";
        private boolean enabled;
        private boolean wifiEnabled;
        private boolean hiddenAdbdContradiction;
        private boolean debounced;
        private String adbdSocketState = "unknown";
        private String jdwpControlState = "unavailable";
        private String initSvcAdbd = "";
        private int tcpPort = -1;
        private int checksAttempted;
        private int checksSucceeded;
        private final List<String> failureReasons = new ArrayList<>();

        public List<String> getDetails() {
            return Collections.unmodifiableList(new ArrayList<>(details));
        }
        public String getSummary() { return summary; }
        public boolean isEnabled() { return enabled; }
        public boolean isWifiEnabled() { return wifiEnabled; }
        public boolean isHiddenAdbdContradiction() { return hiddenAdbdContradiction; }
        public boolean isDebounced() { return debounced; }
        public String getAdbdSocketState() { return adbdSocketState; }
        public String getJdwpControlState() { return jdwpControlState; }
        public String getInitSvcAdbd() { return initSvcAdbd; }
        public int getTcpPort() { return tcpPort; }
        public int getChecksAttempted() { return checksAttempted; }
        public int getChecksSucceeded() { return checksSucceeded; }
        public List<String> getFailureReasons() {
            return Collections.unmodifiableList(new ArrayList<>(failureReasons));
        }
        private void success() { checksAttempted++; checksSucceeded++; }
        private void failure(String reason) {
            checksAttempted++;
            failureReasons.add(reason);
        }
        private void addUniqueDetail(String token) {
            if (!details.contains(token)) {
                details.add(token);
            }
        }
    }

    public static Snapshot collect(Context context) {
        return collectUncached(context, null);
    }

    public static Snapshot collect(SignalSnapshot signals) {
        SignalResult<Snapshot> result = signals.getAdbState();
        if (!result.isSuccess() || result.getValue() == null) {
            throw new IllegalStateException("ADB signals unavailable: " + result.getFailureReason());
        }
        return result.getValue();
    }

    public static Snapshot collectUncached(Context context, SignalSnapshot signals) {
        return collectWithAdapter(context, signals, DEFAULT_ADAPTER);
    }

    /** Executes ADB inspection with an injectable protocol/sleep adapter for unit testing. */
    public static Snapshot collectWithAdapter(Context context,
                                              SignalSnapshot signals,
                                              ProtocolProbeAdapter adapter) {
        ProtocolProbeAdapter effAdapter = adapter != null ? adapter : DEFAULT_ADAPTER;
        Snapshot snapshot = new Snapshot();

        Boolean settingsAdbEnabled = null;
        try {
            Integer val = effAdapter.readSettingsAdbEnabled(context);
            if (val != null) {
                settingsAdbEnabled = (val == 1);
                if (val == 1) {
                    snapshot.enabled = true;
                    snapshot.addUniqueDetail("settings_adb_enabled");
                }
                snapshot.success();
            } else {
                snapshot.failure("settings_adb:unavailable");
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            snapshot.failure("settings_adb:" + e.getClass().getSimpleName());
        }

        Boolean settingsAdbWifiEnabled = null;
        try {
            Integer val = effAdapter.readSettingsAdbWifiEnabled(context);
            if (val != null) {
                settingsAdbWifiEnabled = (val == 1);
                if (val == 1) {
                    snapshot.enabled = true;
                    snapshot.wifiEnabled = true;
                    snapshot.addUniqueDetail("settings_adb_wifi_enabled");
                }
                snapshot.success();
            } else {
                snapshot.failure("settings_adb_wifi:unavailable");
            }
        } catch (Exception | LinkageError | OutOfMemoryError e) {
            snapshot.failure("settings_adb_wifi:" + e.getClass().getSimpleName());
        }

        String tcpPortProp;
        if (signals != null) {
            SignalResult<String> servicePort = signals.getSystemProperty("service.adb.tcp.port");
            SignalResult<String> persistPort = signals.getSystemProperty("persist.adb.tcp.port");
            tcpPortProp = firstNonBlank(valueOf(servicePort), valueOf(persistPort));
            if (servicePort.isSuccess() || persistPort.isSuccess()) {
                snapshot.success();
            } else {
                snapshot.failure("adb_properties:" + servicePort.getStatus()
                        + "/" + persistPort.getStatus());
            }
        } else {
            tcpPortProp = firstNonBlank(
                    getNativeProperty("service.adb.tcp.port"),
                    getNativeProperty("persist.adb.tcp.port"));
            if (NativeCollectorBridge.isNativeAvailable()) {
                snapshot.success();
            } else {
                snapshot.failure("adb_properties:native_unavailable");
            }
        }
        Integer port = parsePort(tcpPortProp);
        if (port != null && port > 0) {
            snapshot.enabled = true;
            snapshot.wifiEnabled = true;
            snapshot.tcpPort = port;
            snapshot.addUniqueDetail("adb_tcp_port:" + port);
        }

        // A listening port alone is not proof of ADB: any app can bind 5555.
        // Only correlate sockets that are owned by an actual adbd process.
        List<Integer> adbdPids;
        if (signals == null) {
            adbdPids = ProcfsUtils.findPidsByProcessNames("adbd");
            snapshot.success();
        } else {
            SignalResult<List<ProcfsUtils.ProcessInfo>> processes = signals.getProcesses();
            adbdPids = processes.isSuccess() && processes.getValue() != null
                    ? ProcfsUtils.findPidsByProcessNames(processes.getValue(), "adbd")
                    : Collections.emptyList();
            if (processes.isSuccess()) snapshot.success();
            else snapshot.failure("process_snapshot_unavailable");
        }
        if (!adbdPids.isEmpty()) {
            snapshot.enabled = true;
            snapshot.addUniqueDetail("adbd_process:" + adbdPids.get(0));
            for (Integer pid : adbdPids) {
                Set<Integer> pidPorts = ProcfsUtils.findPidLoopbackListeningPorts(pid);
                for (Integer pidPort : pidPorts) {
                    snapshot.addUniqueDetail("adbd_pid_port:" + pidPort);
                    snapshot.wifiEnabled = true;
                }
            }
        }

        String usbFunctions = ProcfsUtils.readFirstLine(
                "/sys/class/android_usb/android0/functions");
        if (containsAdbFunction(usbFunctions)) {
            snapshot.enabled = true;
            snapshot.addUniqueDetail("usb_function:adb");
        }

        String usbState = ProcfsUtils.readFirstLine(
                "/sys/class/usb_composite/adb/state");
        if (!usbState.isEmpty() && isConfiguredState(usbState)) {
            snapshot.enabled = true;
            snapshot.addUniqueDetail("usb_state:" + usbState.toLowerCase(Locale.ROOT));
        }

        // Protocol-level native checks (/dev/socket/adbd EACCES control + @jdwp-control +
        // init.svc.adbd) with CONDITIONAL 2-sample debounce (0 sleep on clean consistent devices).
        ProtocolSample sample1 = sampleProtocol(
                context, effAdapter, settingsAdbEnabled, settingsAdbWifiEnabled);
        if (sample1.nativeAvailable) {
            snapshot.success();
            ProtocolSample finalSample = sample1;
            boolean hasPid = !adbdPids.isEmpty();
            boolean sample1Contradiction = sample1.isHiddenContradiction(hasPid);
            boolean needDebounce = sample1Contradiction || sample1.isTransientSplit();

            if (needDebounce) {
                try {
                    effAdapter.sleepMs(DEBOUNCE_DELAY_MS);
                    snapshot.debounced = true;
                    Boolean reAdb = readSettingSafe(context, effAdapter, true);
                    Boolean reWifi = readSettingSafe(context, effAdapter, false);
                    ProtocolSample sample2 = sampleProtocol(context, effAdapter, reAdb, reWifi);
                    if (sample2.nativeAvailable) {
                        finalSample = sample2;
                    }
                    // Confirm contradiction ONLY when BOTH samples persistently exhibit it
                    // (eliminates 1.5s USB unplug / adbd stop-start transition false positives).
                    if (sample1Contradiction && finalSample.isHiddenContradiction(hasPid)) {
                        recordHiddenContradiction(snapshot, finalSample);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            snapshot.adbdSocketState = finalSample.adbdSocketState;
            snapshot.jdwpControlState = finalSample.jdwpControlState;
            snapshot.initSvcAdbd = finalSample.initSvcAdbd;

            if (!snapshot.hiddenAdbdContradiction) {
                // Non-contradictory protocol observation corroborates normal ADB status.
                if (finalSample.isAdbdSocketLive() && finalSample.isJdwpControlLive()) {
                    snapshot.enabled = true;
                    snapshot.addUniqueDetail("adbd_socket:" + finalSample.adbdSocketState);
                    snapshot.addUniqueDetail("jdwp_control_socket:observed");
                }
            }
        }

        if (snapshot.hiddenAdbdContradiction) {
            snapshot.summary = "hidden_contradiction";
        } else if (snapshot.enabled) {
            snapshot.summary = snapshot.wifiEnabled ? "enabled_wifi" : "enabled";
        } else {
            snapshot.summary = "disabled";
        }
        return snapshot;
    }

    private static void recordHiddenContradiction(Snapshot snapshot, ProtocolSample sample) {
        snapshot.hiddenAdbdContradiction = true;
        snapshot.enabled = true;
        if (sample.isInitSvcStopped()) {
            snapshot.addUniqueDetail("adbd_contradiction:init_svc_adbd_stopped");
        } else if (sample.isSettingsDisabled()) {
            snapshot.addUniqueDetail("adbd_contradiction:settings_adb_disabled");
        }
        if (sample.isAdbdSocketLive()) {
            snapshot.addUniqueDetail("adbd_hidden_socket:" + sample.adbdSocketState);
        }
        if (sample.isJdwpControlLive()) {
            snapshot.addUniqueDetail("adbd_hidden_jdwp_control");
        }
    }

    private static ProtocolSample sampleProtocol(Context context,
                                                 ProtocolProbeAdapter adapter,
                                                 Boolean settingsAdbEnabled,
                                                 Boolean settingsAdbWifiEnabled) {
        try {
            SignalResult<String> raw = adapter.readNativeAdbProtocol();
            if (raw == null || !raw.isSuccess() || raw.getValue() == null
                    || raw.getValue().isEmpty()) {
                return new ProtocolSample(false, "unknown", "unavailable", "",
                        settingsAdbEnabled, settingsAdbWifiEnabled);
            }
            NativePayloadCodec.DecodedPayload decoded =
                    NativePayloadCodec.decodePayload(raw.getValue());
            if (!decoded.isOk()) {
                return new ProtocolSample(false, "unknown", "unavailable", "",
                        settingsAdbEnabled, settingsAdbWifiEnabled);
            }
            return new ProtocolSample(
                    true,
                    decoded.getHeaderField("adbd_socket"),
                    decoded.getHeaderField("jdwp_control"),
                    decoded.getHeaderField("init_svc_adbd"),
                    settingsAdbEnabled,
                    settingsAdbWifiEnabled);
        } catch (Exception | LinkageError e) {
            return new ProtocolSample(false, "unknown", "unavailable", "",
                    settingsAdbEnabled, settingsAdbWifiEnabled);
        }
    }

    private static Boolean readSettingSafe(Context context,
                                           ProtocolProbeAdapter adapter,
                                           boolean primary) {
        try {
            Integer val = primary
                    ? adapter.readSettingsAdbEnabled(context)
                    : adapter.readSettingsAdbWifiEnabled(context);
            return val == null ? null : (val == 1);
        } catch (Exception e) {
            return null;
        }
    }

    private static String valueOf(SignalResult<String> result) {
        return result != null && result.isSuccess() && result.getValue() != null
                ? result.getValue() : "";
    }

    private static boolean isConfiguredState(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.contains("configured")
                || lower.contains("connected")
                || "1".equals(lower);
    }

    private static boolean containsAdbFunction(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        for (String function : value.toLowerCase(Locale.ROOT).split(",")) {
            if ("adb".equals(function.trim())) {
                return true;
            }
        }
        return false;
    }

    private static String getNativeProperty(String name) {
        if (!NativeCollectorBridge.isNativeAvailable()) {
            return "";
        }
        try {
            return NativeCollectorBridge.getSystemProperty(name);
        } catch (Exception | LinkageError e) {
            return "";
        }
    }

    private static Integer parsePort(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || "-1".equals(trimmed)) {
            return null;
        }
        try {
            return Integer.parseInt(trimmed);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return "";
    }
}
