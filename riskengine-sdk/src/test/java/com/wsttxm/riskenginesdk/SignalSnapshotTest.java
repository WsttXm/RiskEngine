package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.util.AdbInspector;

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
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

    @Test
    public void independentSignalsDoNotSerializeOnGlobalSnapshotMonitor() throws Exception {
        SignalSnapshot snapshot = new SignalSnapshot(null);
        CountDownLatch completed = new CountDownLatch(1);
        AtomicReference<SignalResult<?>> mapsResult = new AtomicReference<>();
        AtomicReference<SignalResult<?>> sigResult = new AtomicReference<>();

        // Holding the SignalSnapshot instance monitor must not block independent signal getters
        // (regression guard for CRITICAL-tier AppIntegrityDetector vs HookFrameworkDetector lock contention).
        synchronized (snapshot) {
            Thread worker = new Thread(() -> {
                mapsResult.set(snapshot.getSelfMaps());
                sigResult.set(snapshot.getNativeApkSigningInfo());
                completed.countDown();
            });
            worker.start();
            assertTrue("Independent SignalSnapshot getters blocked on global monitor",
                    completed.await(2, TimeUnit.SECONDS));
            worker.join(2_000L);
        }

        assertNotNull(mapsResult.get());
        assertNotNull(sigResult.get());
    }
}
