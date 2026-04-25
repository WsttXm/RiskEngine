package com.wsttxm.riskenginesdk.util;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class ProcfsUtils {

    private static final String TCP_LISTEN = "0A";

    private ProcfsUtils() {}

    public static final class TcpEntry {
        private final String localAddress;
        private final int localPort;
        private final String state;

        public TcpEntry(String localAddress, int localPort, String state) {
            this.localAddress = localAddress;
            this.localPort = localPort;
            this.state = state;
        }

        public String getLocalAddress() { return localAddress; }
        public int getLocalPort() { return localPort; }
        public String getState() { return state; }
        public boolean isListening() { return TCP_LISTEN.equalsIgnoreCase(state); }
        public boolean isLoopback() {
            return "127.0.0.1".equals(localAddress)
                    || "::1".equals(localAddress)
                    || "0.0.0.0".equals(localAddress)
                    || "::".equals(localAddress);
        }
    }

    public static List<TcpEntry> readTcpTable(String path) {
        List<TcpEntry> entries = new ArrayList<>();
        File file = new File(path);
        if (!file.exists() || !file.canRead()) {
            return entries;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            boolean headerSkipped = false;
            while ((line = reader.readLine()) != null) {
                if (!headerSkipped) {
                    headerSkipped = true;
                    continue;
                }
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+");
                if (parts.length < 4) {
                    continue;
                }
                String[] local = parts[1].split(":");
                if (local.length != 2) {
                    continue;
                }
                String addressHex = local[0];
                String portHex = local[1];
                String state = parts[3];
                int port;
                try {
                    port = Integer.parseInt(portHex, 16);
                } catch (NumberFormatException ignored) {
                    continue;
                }
                entries.add(new TcpEntry(decodeAddress(addressHex), port, state));
            }
        } catch (IOException e) {
            CLog.e("Failed to read tcp table: " + path, e);
        }
        return entries;
    }

    public static Set<Integer> findLoopbackListeningPorts() {
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        collectLoopbackPorts("/proc/net/tcp", ports);
        collectLoopbackPorts("/proc/net/tcp6", ports);
        return ports;
    }

    public static Set<Integer> findPidLoopbackListeningPorts(int pid) {
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        collectLoopbackPorts("/proc/" + pid + "/net/tcp", ports);
        collectLoopbackPorts("/proc/" + pid + "/net/tcp6", ports);
        return ports;
    }

    public static List<Integer> findPidsByNameFragments(String... keywords) {
        List<Integer> pids = new ArrayList<>();
        File proc = new File("/proc");
        File[] dirs = proc.listFiles();
        if (dirs == null) {
            return pids;
        }
        for (File dir : dirs) {
            if (!dir.isDirectory()) {
                continue;
            }
            String name = dir.getName();
            if (!name.matches("\\d+")) {
                continue;
            }
            String comm = readFirstLine(new File(dir, "comm").getAbsolutePath());
            String cmdline = readCmdline(Integer.parseInt(name));
            String haystack = (comm + " " + cmdline).toLowerCase(Locale.ROOT);
            for (String keyword : keywords) {
                if (haystack.contains(keyword.toLowerCase(Locale.ROOT))) {
                    pids.add(Integer.parseInt(name));
                    break;
                }
            }
        }
        return pids;
    }

    public static String readCmdline(int pid) {
        String raw = readFile("/proc/" + pid + "/cmdline");
        if (raw == null) {
            return "";
        }
        return raw.replace('\0', ' ').trim();
    }

    public static String readFirstLine(String path) {
        File file = new File(path);
        if (!file.exists() || !file.canRead()) {
            return "";
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line = reader.readLine();
            return line != null ? line.trim() : "";
        } catch (IOException e) {
            return "";
        }
    }

    public static String readFile(String path) {
        File file = new File(path);
        if (!file.exists() || !file.canRead()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (builder.length() > 0) {
                    builder.append('\n');
                }
                builder.append(line);
            }
        } catch (IOException e) {
            return "";
        }
        return builder.toString();
    }

    public static String readSelfCmdline() {
        String cmdline = readFile("/proc/self/cmdline");
        if (cmdline == null) {
            return "";
        }
        return cmdline.replace('\0', ' ').trim();
    }

    public static List<String> collectContainerSignals(Context context) {
        List<String> signals = new ArrayList<>();
        String[] cgroupPaths = {"/proc/1/cgroup", "/proc/self/cgroup"};
        String[] cgroupKeywords = {"docker", "lxc", "container", "kubepods", "podman"};
        for (String path : cgroupPaths) {
            String content = readFile(path).toLowerCase(Locale.ROOT);
            for (String keyword : cgroupKeywords) {
                if (!content.isEmpty() && content.contains(keyword)) {
                    signals.add("cgroup:" + keyword);
                    break;
                }
            }
        }

        String mountInfo = readFile("/proc/self/mountinfo").toLowerCase(Locale.ROOT);
        if (mountInfo.contains(" overlay ")) {
            signals.add("mount_overlay");
        }

        String cmdline = readSelfCmdline();
        if (!cmdline.isEmpty() && context != null) {
            String packageName = context.getPackageName();
            if (packageName != null && !packageName.isEmpty() && !cmdline.contains(packageName)) {
                signals.add("cmdline_mismatch:" + cmdline);
            }
        }

        return signals;
    }

    public static String probeDbus(int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            socket.getOutputStream().write("\0AUTH\r\n".getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            byte[] buffer = new byte[96];
            int read = socket.getInputStream().read(buffer);
            if (read <= 0) {
                return "";
            }
            return new String(buffer, 0, read, StandardCharsets.US_ASCII).trim();
        } catch (Exception ignored) {
            return "";
        }
    }

    private static void collectLoopbackPorts(String path, Set<Integer> ports) {
        for (TcpEntry entry : readTcpTable(path)) {
            if (entry.isListening() && entry.isLoopback()) {
                ports.add(entry.getLocalPort());
            }
        }
    }

    private static String decodeAddress(String value) {
        if (value == null) {
            return "";
        }
        if (value.length() == 8) {
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                int index = (3 - i) * 2;
                bytes[i] = (byte) Integer.parseInt(value.substring(index, index + 2), 16);
            }
            try {
                return InetAddress.getByAddress(bytes).getHostAddress();
            } catch (Exception ignored) {
                return value;
            }
        }
        if ("00000000000000000000000001000000".equalsIgnoreCase(value)) {
            return "::1";
        }
        if ("00000000000000000000000000000000".equalsIgnoreCase(value)) {
            return "::";
        }
        return value;
    }
}
