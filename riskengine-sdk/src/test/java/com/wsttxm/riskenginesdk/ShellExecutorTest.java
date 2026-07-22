package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.util.ShellExecutor;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ShellExecutorTest {
    @Test
    public void invalidCommandHasStructuredFailure() {
        ShellExecutor.Result result = ShellExecutor.executeResult("", 1000);
        assertEquals(ShellExecutor.Status.INVALID_COMMAND, result.getStatus());
        assertFalse(result.isSuccess());
        assertEquals("", result.getStdout());
    }
}
