package com.wsttxm.riskenginesdk.util;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AdbInspector {

    private AdbInspector() {}

    public static final class Snapshot {
        private final List<String> details = new ArrayList<>();
        private String summary = "disabled";
        private boolean enabled;
        private boolean wifiEnabled;
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
        Snapshot snapshot = new Snapshot();
        ContentResolver resolver = context.getContentResolver();

        try {
            int adbEnabled = Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0);
            if (adbEnabled == 1) {
                snapshot.enabled = true;
                snapshot.details.add("settings_adb_enabled");
            }
            snapshot.success();
        } catch (Exception e) {
            snapshot.failure("settings_adb:" + e.getClass().getSimpleName());
        }

        try {
            int adbWifiEnabled = Settings.Global.getInt(resolver, "adb_wifi_enabled", 0);
            if (adbWifiEnabled == 1) {
                snapshot.enabled = true;
                snapshot.wifiEnabled = true;
                snapshot.details.add("settings_adb_wifi_enabled");
            }
            snapshot.success();
        } catch (Exception e) {
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
            snapshot.success();
        }
        if (tcpPortProp.isEmpty() && signals == null) {
            tcpPortProp = firstNonBlank(
                    ShellExecutor.executeResult("getprop service.adb.tcp.port").getStdout(),
                    ShellExecutor.executeResult("getprop persist.adb.tcp.port").getStdout());
        }
        Integer port = parsePort(tcpPortProp);
        if (port != null && port > 0) {
            snapshot.enabled = true;
            snapshot.wifiEnabled = true;
            snapshot.tcpPort = port;
            snapshot.details.add("adb_tcp_port:" + port);
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
            snapshot.details.add("adbd_process:" + adbdPids.get(0));
            for (Integer pid : adbdPids) {
                Set<Integer> pidPorts = ProcfsUtils.findPidLoopbackListeningPorts(pid);
                for (Integer pidPort : pidPorts) {
                    snapshot.details.add("adbd_pid_port:" + pidPort);
                    snapshot.wifiEnabled = true;
                }
            }
        }

        String usbFunctions = ProcfsUtils.readFirstLine(
                "/sys/class/android_usb/android0/functions");
        if (containsAdbFunction(usbFunctions)) {
            snapshot.enabled = true;
            snapshot.details.add("usb_function:adb");
        }

        String usbState = ProcfsUtils.readFirstLine(
                "/sys/class/usb_composite/adb/state");
        if (!usbState.isEmpty() && isConfiguredState(usbState)) {
            snapshot.enabled = true;
            snapshot.details.add("usb_state:" + usbState.toLowerCase(Locale.ROOT));
        }

        snapshot.summary = snapshot.enabled
                ? (snapshot.wifiEnabled ? "enabled_wifi" : "enabled")
                : "disabled";
        return snapshot;
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
