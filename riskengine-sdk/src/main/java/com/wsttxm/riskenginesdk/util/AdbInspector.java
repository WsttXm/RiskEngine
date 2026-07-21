package com.wsttxm.riskenginesdk.util;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;

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

        public List<String> getDetails() {
            return Collections.unmodifiableList(new ArrayList<>(details));
        }
        public String getSummary() { return summary; }
        public boolean isEnabled() { return enabled; }
        public boolean isWifiEnabled() { return wifiEnabled; }
        public int getTcpPort() { return tcpPort; }
    }

    public static Snapshot collect(Context context) {
        Snapshot snapshot = new Snapshot();
        ContentResolver resolver = context.getContentResolver();

        int adbEnabled = Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0);
        if (adbEnabled == 1) {
            snapshot.enabled = true;
            snapshot.details.add("settings_adb_enabled");
        }

        int adbWifiEnabled = Settings.Global.getInt(resolver, "adb_wifi_enabled", 0);
        if (adbWifiEnabled == 1) {
            snapshot.enabled = true;
            snapshot.wifiEnabled = true;
            snapshot.details.add("settings_adb_wifi_enabled");
        }

        String tcpPortProp = firstNonBlank(
                getNativeProperty("service.adb.tcp.port"),
                getNativeProperty("persist.adb.tcp.port")
        );
        if (tcpPortProp.isEmpty()) {
            tcpPortProp = firstNonBlank(
                    ShellExecutor.execute("getprop service.adb.tcp.port"),
                    ShellExecutor.execute("getprop persist.adb.tcp.port"));
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
        List<Integer> adbdPids = ProcfsUtils.findPidsByProcessNames("adbd");
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
