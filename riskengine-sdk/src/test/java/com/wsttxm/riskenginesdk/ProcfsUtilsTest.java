package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class ProcfsUtilsTest {
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
}
