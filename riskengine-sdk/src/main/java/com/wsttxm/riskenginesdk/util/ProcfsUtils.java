package com.wsttxm.riskenginesdk.util;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
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
        private final String inode;

        public TcpEntry(String localAddress, int localPort, String state, String inode) {
            this.localAddress = localAddress;
            this.localPort = localPort;
            this.state = state;
            this.inode = inode;
        }

        public String getLocalAddress() { return localAddress; }
        public int getLocalPort() { return localPort; }
        public String getState() { return state; }
        public String getInode() { return inode; }
        public boolean isListening() { return TCP_LISTEN.equalsIgnoreCase(state); }
        public boolean isLoopback() {
            return "127.0.0.1".equals(localAddress)
                    || "::1".equals(localAddress)
                    || "0.0.0.0".equals(localAddress)
                    || "::".equals(localAddress);
        }
    }

    public static final class ProcessInfo {
        private final int pid;
        private final String comm;
        private final String cmdline;

        public ProcessInfo(int pid, String comm, String cmdline) {
            this.pid = pid;
            this.comm = comm == null ? "" : comm;
            this.cmdline = cmdline == null ? "" : cmdline;
        }

        public int getPid() { return pid; }
        public String getComm() { return comm; }
        public String getCmdline() { return cmdline; }
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
                if (parts.length < 10) {
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
                entries.add(new TcpEntry(decodeAddress(addressHex), port, state, parts[9]));
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
        Set<String> socketInodes = readPidSocketInodes(pid);
        if (socketInodes.isEmpty()) {
            return ports;
        }
        collectOwnedLoopbackPorts("/proc/" + pid + "/net/tcp", socketInodes, ports);
        collectOwnedLoopbackPorts("/proc/" + pid + "/net/tcp6", socketInodes, ports);
        return ports;
    }

    public static List<Integer> findPidsByNameFragments(String... keywords) {
        return findPidsByNameFragments(snapshotProcesses(), keywords);
    }

    public static List<Integer> findPidsByNameFragments(List<ProcessInfo> processes,
                                                        String... keywords) {
        List<Integer> pids = new ArrayList<>();
        if (keywords == null || keywords.length == 0) {
            return pids;
        }
        for (ProcessInfo process : processes) {
            String haystack = (process.getComm() + " " + process.getCmdline())
                    .toLowerCase(Locale.ROOT);
            for (String keyword : keywords) {
                if (keyword == null || keyword.isBlank()) {
                    continue;
                }
                if (haystack.contains(keyword.toLowerCase(Locale.ROOT))) {
                    pids.add(process.getPid());
                    break;
                }
            }
        }
        return pids;
    }

    public static List<Integer> findPidsByProcessNames(String... processNames) {
        return findPidsByProcessNames(snapshotProcesses(), processNames);
    }

    public static List<Integer> findPidsByProcessNames(List<ProcessInfo> processes,
                                                       String... processNames) {
        LinkedHashSet<String> expected = new LinkedHashSet<>();
        if (processNames == null || processNames.length == 0) {
            return new ArrayList<>();
        }
        for (String processName : processNames) {
            if (processName != null && !processName.isBlank()) {
                expected.add(processName.toLowerCase(Locale.ROOT));
            }
        }

        List<Integer> pids = new ArrayList<>();
        if (expected.isEmpty()) {
            return pids;
        }
        for (ProcessInfo process : processes) {
            if (matchesProcessName(process.getComm(), process.getCmdline(), expected)) {
                pids.add(process.getPid());
            }
        }
        return pids;
    }

    public static List<ProcessInfo> snapshotProcesses() {
        List<ProcessInfo> processes = new ArrayList<>();
        File[] dirs = new File("/proc").listFiles();
        if (dirs == null) return processes;
        for (File dir : dirs) {
            String name = dir.getName();
            if (!dir.isDirectory() || !name.matches("\\d+")) continue;
            try {
                int pid = Integer.parseInt(name);
                processes.add(new ProcessInfo(pid,
                        readFirstLine(new File(dir, "comm").getAbsolutePath()),
                        readCmdline(pid)));
            } catch (NumberFormatException ignored) {
                // PID disappeared or overflowed during the scan.
            }
        }
        return processes;
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
                signals.add("cmdline_mismatch");
            }
        }

        return signals;
    }

    private static void collectLoopbackPorts(String path, Set<Integer> ports) {
        for (TcpEntry entry : readTcpTable(path)) {
            if (entry.isListening() && entry.isLoopback()) {
                ports.add(entry.getLocalPort());
            }
        }
    }

    private static void collectOwnedLoopbackPorts(String path,
                                                  Set<String> socketInodes,
                                                  Set<Integer> ports) {
        for (TcpEntry entry : readTcpTable(path)) {
            if (entry.isListening()
                    && entry.isLoopback()
                    && socketInodes.contains(entry.getInode())) {
                ports.add(entry.getLocalPort());
            }
        }
    }

    private static Set<String> readPidSocketInodes(int pid) {
        LinkedHashSet<String> inodes = new LinkedHashSet<>();
        File fdDirectory = new File("/proc/" + pid + "/fd");
        File[] descriptors = fdDirectory.listFiles();
        if (descriptors == null) {
            return inodes;
        }
        for (File descriptor : descriptors) {
            try {
                String target = Files.readSymbolicLink(descriptor.toPath()).toString();
                if (target.startsWith("socket:[") && target.endsWith("]")) {
                    inodes.add(target.substring(8, target.length() - 1));
                }
            } catch (Exception ignored) {
                // Procfs descriptors may disappear while being inspected.
            }
        }
        return inodes;
    }

    private static boolean matchesProcessName(String comm,
                                              String cmdline,
                                              Set<String> expected) {
        String normalizedComm = comm == null ? "" : comm.trim().toLowerCase(Locale.ROOT);
        if (expected.contains(normalizedComm)) {
            return true;
        }
        if (cmdline == null || cmdline.isBlank()) {
            return false;
        }
        String executable = cmdline.trim().split("\\s+", 2)[0];
        int slash = executable.lastIndexOf('/');
        if (slash >= 0) {
            executable = executable.substring(slash + 1);
        }
        return expected.contains(executable.toLowerCase(Locale.ROOT));
    }

    private static String decodeAddress(String value) {
        if (value == null) {
            return "";
        }
        if (value.length() == 8) {
            byte[] bytes = new byte[4];
            try {
                for (int i = 0; i < 4; i++) {
                    int index = (3 - i) * 2;
                    bytes[i] = (byte) Integer.parseInt(
                            value.substring(index, index + 2), 16);
                }
            } catch (NumberFormatException ignored) {
                return value;
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
