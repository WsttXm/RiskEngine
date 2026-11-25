package com.wsttxm.riskenginesdk;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.IBinder;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;
import com.wsttxm.riskenginesdk.detector.probe.tee.GrantDomainSplitProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.process.IsolatedProbeClient;

import org.junit.Test;

import java.security.UnrecoverableKeyException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * Unit tests for P3-6: {@link IsolatedProbeClient#probeGrantDomainChain},
 * {@link GrantDomainSplitProbe}, and {@code RiskIsolatedProbeService} fail-closed boundaries.
 */
public class GrantDomainSplitProbeTest {

    private static final String CHAIN_A =
            "OK|2|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    + "|1111111111111111111111111111111111111111111111111111111111111111,"
                    + "2222222222222222222222222222222222222222222222222222222222222222";
    private static final String CHAIN_B_FORGED_LEAF =
            "OK|2|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    + "|9999999999999999999999999999999999999999999999999999999999999999,"
                    + "2222222222222222222222222222222222222222222222222222222222222222";
    private static final String CHAIN_C_DIFFERENT_LENGTH =
            "OK|3|cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    + "|1111111111111111111111111111111111111111111111111111111111111111,"
                    + "2222222222222222222222222222222222222222222222222222222222222222,"
                    + "3333333333333333333333333333333333333333333333333333333333333333";

    private static final class ServiceSpecificException extends RuntimeException {
        public final int errorCode;

        ServiceSpecificException(int errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
        }
    }

    @Test
    public void serviceFailClosedRefusesNonIsolatedBindAndTransactions() {
        assertNull(IsolatedProbeClient.bindGrantServiceForTest(() -> false, id -> CHAIN_A, new Intent()));
        assertNotNull(IsolatedProbeClient.bindGrantServiceForTest(() -> true, id -> CHAIN_A, new Intent()));

        try {
            IsolatedProbeClient.readGrantedChainForTest(() -> false, id -> CHAIN_A, 42L);
            fail("Expected SecurityException for non-isolated grant read transaction");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("isolated"));
        }
        try {
            IsolatedProbeClient.getIsolatedUidForTest(() -> false);
            fail("Expected SecurityException for non-isolated UID transaction");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("isolated"));
        }
        assertEquals(CHAIN_A, IsolatedProbeClient.readGrantedChainForTest(() -> true, id -> CHAIN_A, 42L));
    }

    @Test
    public void cleanMatchingAppAndGrantChainsProduceZeroFpAndAlwaysCleanup() {
        FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, false);
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, adapter);

        assertTrue(raw.isSuccess());
        assertNotNull(raw.getValue());
        assertEquals(IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.OK,
                raw.getValue().getGrantReadStatus());
        assertNotNull(adapter.lastInstanceName.get());
        assertTrue(adapter.lastInstanceName.get().startsWith("grant_"));

        GrantDomainSplitProbe.ProbeResult result = GrantDomainSplitProbe.evaluate(raw);
        assertTrue(result.isUsable());
        assertFalse(result.isSplitDetected());
        assertFalse(result.hasFindings());

        // Strict finally cleanup verification
        assertEquals(1, adapter.revokeCount.get());
        assertTrue(adapter.deleteCount.get() >= 1);
        assertEquals(1, adapter.unbindCount.get());
    }

    @Test
    public void mismatchedAppVsGrantChainEmitsStrongIsolatedHardwareSplitEvidence() {
        FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_B_FORGED_LEAF, CHAIN_A, false);
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, adapter);

        assertTrue(raw.isSuccess());
        GrantDomainSplitProbe.ProbeResult result = GrantDomainSplitProbe.evaluate(raw);
        assertTrue(result.isUsable());
        assertTrue(result.isSplitDetected());
        assertTrue(result.getStrongTokens().contains(GrantDomainSplitProbe.CODE_GRANT_CHAIN_SPLIT));
        assertEquals(1, result.getEvidenceItems().size());

        EvidenceItem item = result.getEvidenceItems().get(0);
        assertEquals(GrantDomainSplitProbe.CODE_GRANT_CHAIN_SPLIT, item.getCode());
        assertEquals(GrantDomainSplitProbe.FAMILY_TEE_TAMPER, item.getEvidenceFamily());
        assertEquals(EvidenceItem.Rank.STRONG, item.getRank());
        assertTrue(item.getMergedSources().contains(EvidenceItem.SourceLayer.ISOLATED));
        assertTrue(item.getMergedSources().contains(EvidenceItem.SourceLayer.HARDWARE));
        assertTrue(item.getValue().contains("leaf_mismatch"));

        // Cleanup still runs deterministically
        assertEquals(1, adapter.revokeCount.get());
        assertEquals(1, adapter.unbindCount.get());
    }

    @Test
    public void missingSyntheticGrantKeyOnGrantOrReadbackTriggersSplitAndCleansUp() {
        // Case 1: TrickyStore synthesized key in Domain.APP, so Keystore2 grant() throws KEY_NOT_FOUND
        FakeGrantAdapter keyNotFoundOnGrant = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, true);
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw1 =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, keyNotFoundOnGrant);
        assertTrue(raw1.isSuccess());
        assertEquals(IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.KEY_NOT_FOUND_ON_GRANT,
                raw1.getValue().getGrantReadStatus());

        GrantDomainSplitProbe.ProbeResult res1 = GrantDomainSplitProbe.evaluate(raw1);
        assertTrue(res1.isUsable());
        assertTrue(res1.isSplitDetected());
        assertTrue(res1.getStrongTokens().contains(GrantDomainSplitProbe.CODE_GRANT_CHAIN_SPLIT));
        assertEquals(0, keyNotFoundOnGrant.revokeCount.get()); // grant never created
        assertTrue(keyNotFoundOnGrant.deleteCount.get() >= 1);
        assertEquals(1, keyNotFoundOnGrant.unbindCount.get());

        // Case 1b: Path B IKeystoreService.grant throws ServiceSpecificException(errorCode=7)
        FakeGrantAdapter sseKeyNotFound = new FakeGrantAdapter(
                34, true, CHAIN_A, CHAIN_A,
                new ServiceSpecificException(7, "Error::Rc(r#KEY_NOT_FOUND) (code 7)"));
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw1b =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, sseKeyNotFound);
        assertTrue(raw1b.isSuccess());
        assertEquals(IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.KEY_NOT_FOUND_ON_GRANT,
                raw1b.getValue().getGrantReadStatus());
        assertTrue(GrantDomainSplitProbe.evaluate(raw1b).isSplitDetected());
        assertEquals(1, sseKeyNotFound.deleteCount.get());
        assertEquals(1, sseKeyNotFound.unbindCount.get());

        // Case 2: Isolated Domain.GRANT readback returns KEY_NOT_FOUND
        FakeGrantAdapter keyNotFoundOnRead = new FakeGrantAdapter(
                34, true, CHAIN_A, "KEY_NOT_FOUND|ServiceSpecificException", false);
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw2 =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, keyNotFoundOnRead);
        assertTrue(raw2.isSuccess());
        GrantDomainSplitProbe.ProbeResult res2 = GrantDomainSplitProbe.evaluate(raw2);
        assertTrue(res2.isUsable());
        assertTrue(res2.isSplitDetected());
        assertEquals(1, keyNotFoundOnRead.revokeCount.get());
        assertEquals(1, keyNotFoundOnRead.unbindCount.get());
    }

    @Test
    public void disabledApiBelow31OrToolsNodeRemoveDegradeCleanlyToUnavailableWithZeroFp() {
        FakeGrantAdapter validAdapter = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, false);

        // Disabled via config
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> disabled =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), false, 500L, validAdapter);
        assertEquals(SignalResult.Status.UNAVAILABLE, disabled.getStatus());
        assertEquals("isolated_probe_disabled", disabled.getFailureReason());
        assertFalse(GrantDomainSplitProbe.evaluate(disabled).hasFindings());

        // API 30 (< 31)
        FakeGrantAdapter api30 = new FakeGrantAdapter(30, true, CHAIN_A, CHAIN_A, false);
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> oldApi =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, api30);
        assertEquals(SignalResult.Status.UNAVAILABLE, oldApi.getStatus());
        assertEquals("api_below_31", oldApi.getFailureReason());

        // Stripped via host tools:node="remove"
        FakeGrantAdapter stripped = new FakeGrantAdapter(34, false, CHAIN_A, CHAIN_A, false);
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> removed =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, stripped);
        assertEquals(SignalResult.Status.UNAVAILABLE, removed.getStatus());
        assertEquals("isolated_service_not_declared", removed.getFailureReason());
        assertEquals(0, stripped.unbindCount.get());

        // SignalSnapshot disabled & seeded cache behavior
        SignalSnapshot snap = new SignalSnapshot(null);
        assertFalse(GrantDomainSplitProbe.run(snap, false).isUsable());
        snap.seedIsolatedGrantReportForTest(SignalResult.success(
                new IsolatedProbeClient.IsolatedGrantReport(
                        CHAIN_B_FORGED_LEAF,
                        CHAIN_A,
                        IsolatedProbeClient.IsolatedGrantReport.GrantReadStatus.OK,
                        99012,
                        15L,
                        "ok")));
        GrantDomainSplitProbe.ProbeResult seededRes = GrantDomainSplitProbe.run(snap, true);
        assertTrue(seededRes.isUsable());
        assertTrue(seededRes.isSplitDetected());
    }

    @Test
    public void chainLengthMismatchEmitsSplitEvidence() {
        FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_C_DIFFERENT_LENGTH, CHAIN_A, null);
        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, adapter);
        assertTrue(raw.isSuccess());
        GrantDomainSplitProbe.ProbeResult result = GrantDomainSplitProbe.evaluate(raw);
        assertTrue(result.isUsable());
        assertTrue(result.isSplitDetected());
        assertTrue(result.getEvidenceItems().get(0).getValue().contains("chain_length_mismatch"));
        assertEquals(1, adapter.revokeCount.get());
        assertEquals(1, adapter.deleteCount.get());
        assertEquals(1, adapter.unbindCount.get());
    }

    @Test
    public void nonKeyNotFoundErrorsDuringGrantDegradeToUnavailableWithZeroFp() {
        Exception[] visibilityErrors = new Exception[] {
                new ClassNotFoundException("android.security.keystore.KeyStoreManager not found"),
                new SecurityException("KEY_NOT_FOUND denied by SELinux"),
                new UnsupportedOperationException("grantKeyAccess method not found"),
                new ServiceSpecificException(6, "PERMISSION_DENIED (code 6) key_not_found")
        };
        for (Exception err : visibilityErrors) {
            FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, err);
            SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                    IsolatedProbeClient.probeGrantDomainChainForTest(
                            stubContext(), true, 500L, adapter);
            assertEquals("Expected UNAVAILABLE for " + err,
                    SignalResult.Status.UNAVAILABLE, raw.getStatus());
            GrantDomainSplitProbe.ProbeResult res = GrantDomainSplitProbe.evaluate(raw);
            assertFalse("Must produce 0 FP for " + err, res.hasFindings());
            assertEquals(0, adapter.revokeCount.get());
            assertEquals(1, adapter.deleteCount.get());
            assertEquals(1, adapter.unbindCount.get());
        }
    }

    @Test
    public void connectTimeoutAlwaysUnbindsWithoutGrantingOrLeaking() {
        FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, null);
        adapter.connectBehavior = FakeGrantAdapter.ConnectBehavior.HANG;

        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 80L, adapter);
        assertEquals(SignalResult.Status.UNAVAILABLE, raw.getStatus());
        assertFalse(GrantDomainSplitProbe.evaluate(raw).hasFindings());
        assertEquals(0, adapter.grantCallCount.get());
        assertEquals(0, adapter.deleteCount.get());
        assertEquals(1, adapter.unbindCount.get());
    }

    @Test
    public void nullBindingRefusalAlwaysUnbindsWithZeroFp() {
        FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, null);
        adapter.connectBehavior = FakeGrantAdapter.ConnectBehavior.NULL_BINDING;

        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 300L, adapter);
        assertEquals(SignalResult.Status.UNAVAILABLE, raw.getStatus());
        assertEquals("isolated_service_refused_non_isolated", raw.getFailureReason());
        assertFalse(GrantDomainSplitProbe.evaluate(raw).hasFindings());
        assertEquals(0, adapter.grantCallCount.get());
        assertEquals(0, adapter.deleteCount.get());
        assertEquals(1, adapter.unbindCount.get());
    }

    @Test
    public void slowKeygenTimeoutPreventsGrantAndDeletesPersistedKeyAfterSettling() throws Exception {
        CountDownLatch allowKeygenFinish = new CountDownLatch(1);
        CountDownLatch workerCleanedUp = new CountDownLatch(1);
        Set<String> persistedAliases = ConcurrentHashMap.newKeySet();

        FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, null) {
            @Override
            public String generateEphemeralAppChainSummary(String alias, byte[] challenge) {
                try {
                    // Simulate uninterruptible native KeyMint binder call finishing after outer timeout
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                    while (System.nanoTime() < deadline) {
                        try {
                            if (allowKeygenFinish.await(50, TimeUnit.MILLISECONDS)) {
                                break;
                            }
                        } catch (InterruptedException ignored) {
                            // Keep simulating uninterruptible synchronous IPC
                        }
                    }
                } finally {
                    persistedAliases.add(alias);
                }
                return super.generateEphemeralAppChainSummary(alias, challenge);
            }

            @Override
            public void deleteEphemeralAlias(String alias) {
                super.deleteEphemeralAlias(alias);
                if (persistedAliases.remove(alias)) {
                    workerCleanedUp.countDown();
                }
            }
        };

        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 80L, adapter);
        assertEquals(SignalResult.Status.UNAVAILABLE, raw.getStatus());
        assertEquals("isolated_grant_probe_timeout", raw.getFailureReason());
        assertEquals(1, adapter.unbindCount.get());

        // Release slow keygen after outer timeout & outer cleanup already ran
        allowKeygenFinish.countDown();
        assertTrue("Worker finally must delete alias persisted after outer timeout",
                workerCleanedUp.await(2, TimeUnit.SECONDS));
        assertTrue("No ephemeral alias may remain persisted", persistedAliases.isEmpty());
        assertEquals("Cancelled worker must never call grantKeyAccess after timeout",
                0, adapter.grantCallCount.get());
    }

    @Test
    public void readbackExceptionAlwaysRevokesDeletesAndUnbinds() {
        FakeGrantAdapter adapter = new FakeGrantAdapter(34, true, CHAIN_A, CHAIN_A, null);
        adapter.readbackException = new IllegalStateException("binder dead during readback");

        SignalResult<IsolatedProbeClient.IsolatedGrantReport> raw =
                IsolatedProbeClient.probeGrantDomainChainForTest(
                        stubContext(), true, 500L, adapter);
        assertEquals(SignalResult.Status.UNAVAILABLE, raw.getStatus());
        assertFalse(GrantDomainSplitProbe.evaluate(raw).hasFindings());
        assertEquals(1, adapter.grantCallCount.get());
        assertEquals(1, adapter.revokeCount.get());
        assertEquals(1, adapter.deleteCount.get());
        assertEquals(1, adapter.unbindCount.get());
    }

    private static class FakeGrantAdapter implements IsolatedProbeClient.GrantProbeAdapter {
        enum ConnectBehavior { CONNECT, HANG, NULL_BINDING }

        final int sdkInt;
        final boolean serviceDeclared;
        final String appSummary;
        final String grantSummary;
        final Exception grantException;
        ConnectBehavior connectBehavior = ConnectBehavior.CONNECT;
        Exception readbackException;

        final AtomicInteger grantCallCount = new AtomicInteger();
        final AtomicInteger revokeCount = new AtomicInteger();
        final AtomicInteger deleteCount = new AtomicInteger();
        final AtomicInteger unbindCount = new AtomicInteger();
        final AtomicReference<String> lastInstanceName = new AtomicReference<>();

        FakeGrantAdapter(
                int sdkInt,
                boolean serviceDeclared,
                String appSummary,
                String grantSummary,
                boolean throwKeyNotFoundOnGrant) {
            this(sdkInt, serviceDeclared, appSummary, grantSummary,
                    throwKeyNotFoundOnGrant
                            ? new UnrecoverableKeyException("No key found by the given alias")
                            : null);
        }

        FakeGrantAdapter(
                int sdkInt,
                boolean serviceDeclared,
                String appSummary,
                String grantSummary,
                Exception grantException) {
            this.sdkInt = sdkInt;
            this.serviceDeclared = serviceDeclared;
            this.appSummary = appSummary;
            this.grantSummary = grantSummary;
            this.grantException = grantException;
        }

        @Override
        public int getSdkInt() {
            return sdkInt;
        }

        @Override
        public boolean isServiceDeclared(Context context, Intent intent) {
            return serviceDeclared;
        }

        @Override
        public boolean bindIsolated(
                Context context, Intent intent, String instanceName, ServiceConnection connection) {
            lastInstanceName.set(instanceName);
            if (connectBehavior == ConnectBehavior.CONNECT) {
                connection.onServiceConnected(null, new Binder());
            } else if (connectBehavior == ConnectBehavior.NULL_BINDING) {
                connection.onNullBinding(null);
            }
            return true;
        }

        @Override
        public void unbind(Context context, ServiceConnection connection) {
            unbindCount.incrementAndGet();
        }

        @Override
        public int transactGetIsolatedUid(IBinder binder) {
            return 99042;
        }

        @Override
        public String transactReadGrantedChain(IBinder binder, long grantId) throws Exception {
            if (readbackException != null) {
                throw readbackException;
            }
            return grantSummary;
        }

        @Override
        public String generateEphemeralAppChainSummary(String alias, byte[] challenge) {
            assertEquals(32, challenge.length);
            return appSummary;
        }

        @Override
        public long grantKeyAccess(Context context, String alias, int granteeUid) throws Exception {
            grantCallCount.incrementAndGet();
            if (grantException != null) {
                throw grantException;
            }
            return 123456789L;
        }

        @Override
        public void revokeKeyAccess(Context context, String alias, int granteeUid) {
            revokeCount.incrementAndGet();
        }

        @Override
        public void deleteEphemeralAlias(String alias) {
            deleteCount.incrementAndGet();
        }
    }

    private static Context stubContext() {
        return new ContextWrapper(null) {
            @Override
            public Context getApplicationContext() {
                return this;
            }
        };
    }
}
