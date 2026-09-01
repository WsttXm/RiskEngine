package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.detector.ProcessScanDetector;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProcessPatternNegativeTest {
    @Test
    public void substringFridaDoesNotMatch() {
        assertFalse(ProcessScanDetector.containsProcessToken(
                "com.example.fridgedoor", "frida"));
        assertTrue(ProcessScanDetector.containsProcessToken(
                "root     12  1  0  00:00:00 frida-server", "frida-server"));
    }

    @Test
    public void gdbWordBoundaryAvoidsHelperNames() {
        assertFalse(ProcessScanDetector.containsProcessToken("mdgdbhelper", "gdb"));
        assertTrue(ProcessScanDetector.containsProcessToken("/system/bin/gdbserver :5039",
                "gdbserver"));
    }
}
