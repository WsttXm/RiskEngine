package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.DebugDetector;
import com.wsttxm.riskenginesdk.detector.HookFrameworkDetector;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProcfsUtilsTest {
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private final List<ProcfsUtils.ProcessInfo> processes = Arrays.asList(
            new ProcfsUtils.ProcessInfo(101, "adbd", "/system/bin/adbd --root_seclabel"),
            new ProcfsUtils.ProcessInfo(202, "app_process64", "org.lsposed.manager"),
            new ProcfsUtils.ProcessInfo(303, "frida-server", "/data/local/tmp/frida-server")
    );

    @Test
    public void exactProcessMatchUsesSharedSnapshot() {
        assertEquals(Arrays.asList(101),
                ProcfsUtils.findPidsByProcessNames(processes, "adbd"));
    }

    @Test
    public void fragmentMatchChecksCommAndCmdlineCaseInsensitively() {
        assertEquals(Arrays.asList(202, 303),
                ProcfsUtils.findPidsByNameFragments(processes, "LSPOSED", "frida"));
    }

    @Test
    public void loopbackPortsResultDistinguishesUnreadableFromEmptySuccess() throws Exception {
        // 1. Both tcp & tcp6 unreadable/missing -> UNAVAILABLE (never silent empty SUCCESS).
        SignalResult<Set<Integer>> unreadable = ProcfsUtils.findLoopbackListeningPortsResult(
                "/nonexistent/riskengine_proc_net_tcp",
                "/nonexistent/riskengine_proc_net_tcp6");
        assertFalse(unreadable.isSuccess());
        assertEquals(SignalResult.Status.UNAVAILABLE, unreadable.getStatus());
        assertEquals("proc_net_tcp_unreadable", unreadable.getFailureReason());

        // 2. Readable table with header only -> SUCCESS with empty port set.
        File emptyTcp = tempFolder.newFile("tcp_empty");
        Files.write(emptyTcp.toPath(),
                ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
                        .getBytes(StandardCharsets.UTF_8));
        SignalResult<Set<Integer>> emptySuccess = ProcfsUtils.findLoopbackListeningPortsResult(
                emptyTcp.getAbsolutePath(), "/nonexistent/tcp6");
        assertTrue(emptySuccess.isSuccess());
        assertTrue(emptySuccess.getValue().isEmpty());

        // 3. Readable table with 127.0.0.1:27042 (0x69A2) in LISTEN state (0A).
        File activeTcp = tempFolder.newFile("tcp_frida");
        Files.write(activeTcp.toPath(),
                ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                        + "   0: 0100007F:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999\n")
                        .getBytes(StandardCharsets.UTF_8));
        SignalResult<Set<Integer>> parsed = ProcfsUtils.findLoopbackListeningPortsResult(
                activeTcp.getAbsolutePath(), "/nonexistent/tcp6");
        assertTrue(parsed.isSuccess());
        assertTrue(parsed.getValue().contains(27042));

        // 4. SELinux-restricted (UNAVAILABLE) /proc/net/tcp must NOT degrade clean devices from SAFE to UNKNOWN,
        //    while genuine ERROR still records PARTIAL coverage.
        SignalSnapshot restrictedSnap = new SignalSnapshot(null);
        restrictedSnap.seedSelfMapsForTest(SignalResult.success(List.of(
                "700000-710000 r-xp 0000 00:00 10 /system/lib64/libc.so")));
        restrictedSnap.seedProcessesForTest(SignalResult.success(List.of()));
        restrictedSnap.seedLoopbackListeningPortsForTest(
                SignalResult.unavailable("proc_net_tcp_unreadable"));
        DetectionResult hookClean = new HookFrameworkDetector(null, restrictedSnap).call();
        assertEquals(RiskLevel.SAFE, hookClean.getRiskLevel());
        assertTrue(hookClean.getDetails().isEmpty());
        assertFalse(hookClean.getFailureReasons().stream()
                .anyMatch(r -> r.startsWith("frida_ports:")));

        DetectionResult debugClean = DebugDetector.createForTest(
                null, restrictedSnap, new DebugDetector.DebugEnvironment() {
                    @Override public SignalResult<String> getNativeDebugEvidence() {
                        return SignalResult.success("status=OK\terrno=0\ttracer_pid=0");
                    }
                    @Override public SignalResult<Integer> getNativeTracerPid() {
                        return SignalResult.success(0);
                    }
                    @Override public boolean isDebuggerConnected() { return false; }
                    @Override public boolean isWaitingForDebugger() { return false; }
                }).call();
        assertEquals(RiskLevel.SAFE, debugClean.getRiskLevel());
        assertFalse(debugClean.getFailureReasons().stream()
                .anyMatch(r -> r.startsWith("ida_port:")));

        SignalSnapshot errorSnap = new SignalSnapshot(null);
        errorSnap.seedSelfMapsForTest(SignalResult.success(List.of(
                "700000-710000 r-xp 0000 00:00 10 /system/lib64/libc.so")));
        errorSnap.seedProcessesForTest(SignalResult.success(List.of()));
        errorSnap.seedLoopbackListeningPortsForTest(SignalResult.error("IOException"));
        DetectionResult hookError = new HookFrameworkDetector(null, errorSnap).call();
        assertEquals(DetectionExecutionStatus.PARTIAL, hookError.getExecutionStatus());
        assertTrue(hookError.getFailureReasons().stream()
                .anyMatch(r -> r.startsWith("frida_ports:")));
    }
}
