package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.util.AdbInspector;

import org.junit.Test;

import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import com.wsttxm.riskenginesdk.util.ShellExecutor;

public class SignalSnapshotTest {
    @Test
    public void expensiveSignalOutcomeIsMemoizedUntilReset() {
        SignalSnapshot snapshot = new SignalSnapshot(null);

        SignalResult<AdbInspector.Snapshot> first = snapshot.getAdbState();
        SignalResult<AdbInspector.Snapshot> second = snapshot.getAdbState();
        assertSame(first, second);

        snapshot.reset();
        assertNotSame(first, snapshot.getAdbState());
    }

    @Test
    public void shellOutcomeIsMemoizedWithinOneReport() {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        ShellExecutor.Result first = snapshot.getShellResult("");
        assertSame(first, snapshot.getShellResult(""));
        snapshot.reset();
        assertNotSame(first, snapshot.getShellResult(""));
    }
}
