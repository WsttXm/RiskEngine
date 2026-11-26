package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaUidVisibilityProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HmaUidVisibilityProbeTest {

    private static final int SELF_UID = 10200;
    private static final String SELF_PKG = "com.host.banking";

    private static String cleanSeccompFrame() {
        return "status=OK\terrno=0\n"
                + "kind=seccomp_uid\tinstall_status=installed\tinstall_error=0\t"
                + "kernel_major=5\tkernel_minor=15\tqueried=10000\tnotified=10000\t"
                + "first_suppressed=-1\tlast_suppressed=-1\tquery_outcome=complete\t"
                + "query_error=0\tself_notified=1";
    }

    @Test
    public void detectsHiddenActiveForeignAppUidAndExcludesSelfSystemAndIsolated() {
        int visibleUid = 10201;
        int hiddenUid = 10202;

        String activeFrame = "status=OK\terrno=0\tfirst_uid=10000\tlast_uid=19999\t"
                + "checked=10000\tactive_count=5\tcomplete=1\n"
                + "kind=active_uid\tuid=1000\n"       // system UID -> must be excluded
                + "kind=active_uid\tuid=10200\n"      // self UID -> must be excluded
                + "kind=active_uid\tuid=10201\n"      // visible foreign app
                + "kind=active_uid\tuid=10202\n"      // hidden foreign app (HMA!)
                + "kind=active_uid\tuid=99001";       // isolated UID -> must be excluded

        Map<Integer, String[]> pkgMap = new HashMap<>();
        pkgMap.put(SELF_UID, new String[]{SELF_PKG});
        pkgMap.put(visibleUid, new String[]{"com.android.chrome"});
        pkgMap.put(hiddenUid, null); // HMA hides it from getPackagesForUid

        HmaUidVisibilityProbe probe = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, true,
                (f, l) -> {
                    if (f == hiddenUid && l == hiddenUid) {
                        return SignalResult.success("status=OK\terrno=0\tcomplete=1\nkind=active_uid\tuid=" + hiddenUid);
                    }
                    return SignalResult.success(activeFrame);
                },
                (f, l) -> SignalResult.success(cleanSeccompFrame()),
                pkgMap,
                new AtomicLong(0L),
                0L));

        HmaUidVisibilityProbe.ProbeOutcome outcome = probe.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.DETECTED, outcome.getState());
        assertTrue(outcome.isDetected());
        assertEquals(1, outcome.getEvidenceItems().size());
        EvidenceItem item = outcome.getEvidenceItems().get(0);
        assertEquals("hma_uid_visibility_hidden", item.getCode());
        assertEquals("hma_hiding", item.getEvidenceFamily());
        assertEquals(EvidenceItem.Rank.STRONG, item.getRank());
        assertEquals(EvidenceItem.SourceLayer.NATIVE, item.getPrimarySource());
        assertEquals("hidden_count=1", item.getValue());
    }

    @Test
    public void detectsSeccompForeignListenerAndSuppressedNotificationsWithZeroPermissions() {
        String foreignFrame = "status=OK\terrno=0\n"
                + "kind=seccomp_uid\tinstall_status=foreign_listener\tinstall_error=16\t"
                + "kernel_major=6\tkernel_minor=1\tqueried=0\tnotified=0\t"
                + "first_suppressed=-1\tlast_suppressed=-1\tquery_outcome=not_run\t"
                + "query_error=0\tself_notified=0";

        HmaUidVisibilityProbe probe1 = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false, // even WITHOUT QUERY_ALL_PACKAGES!
                (f, l) -> SignalResult.unavailable("skipped"),
                (f, l) -> SignalResult.success(foreignFrame),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome out1 = probe1.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.DETECTED, out1.getState());
        assertEquals("hma_seccomp_foreign_listener", out1.getEvidenceItems().get(0).getCode());
        assertEquals("hma_hiding", out1.getEvidenceItems().get(0).getEvidenceFamily());

        String suppressedFrame = "status=OK\terrno=0\n"
                + "kind=seccomp_uid\tinstall_status=installed\tinstall_error=0\t"
                + "kernel_major=6\tkernel_minor=1\tqueried=10000\tnotified=9995\t"
                + "first_suppressed=10250\tlast_suppressed=10254\tquery_outcome=complete\t"
                + "query_error=0\tself_notified=1";

        HmaUidVisibilityProbe probe2 = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false,
                (f, l) -> SignalResult.unavailable("skipped"),
                (f, l) -> SignalResult.success(suppressedFrame),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome out2 = probe2.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.DETECTED, out2.getState());
        assertEquals("hma_seccomp_suppressed", out2.getEvidenceItems().get(0).getCode());
        assertTrue(out2.getEvidenceItems().get(0).getValue().contains("suppressed=5"));
    }

    @Test
    public void cleanStockParityProducesZeroFalsePositivesWithOrWithoutFullVisibility() {
        String activeFrame = "status=OK\terrno=0\tcomplete=1\n"
                + "kind=active_uid\tuid=10200\n"
                + "kind=active_uid\tuid=10205";
        Map<Integer, String[]> pkgMap = new HashMap<>();
        pkgMap.put(SELF_UID, new String[]{SELF_PKG});
        pkgMap.put(10205, new String[]{"com.google.android.gms"});

        HmaUidVisibilityProbe withPerm = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, true,
                (f, l) -> SignalResult.success(activeFrame),
                (f, l) -> SignalResult.success(cleanSeccompFrame()),
                pkgMap,
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outWith = withPerm.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.CLEAN, outWith.getState());
        assertFalse(outWith.isDetected());

        // Without QUERY_ALL_PACKAGES, foreign UID lookup is skipped cleanly -> zero FP
        HmaUidVisibilityProbe withoutPerm = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false,
                (f, l) -> SignalResult.success(activeFrame),
                (f, l) -> SignalResult.success(cleanSeccompFrame()),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outWithout = withoutPerm.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.CLEAN, outWithout.getState());
        assertFalse(outWithout.isDetected());
    }

    @Test
    public void kernelUnsupportedSelinuxRestrictedAndMalformedPayloadsDegradeGracefully() {
        HmaUidVisibilityProbe unsupported = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false,
                (f, l) -> SignalResult.success("status=UNSUPPORTED\terrno=38"),
                (f, l) -> SignalResult.success("status=UNSUPPORTED\terrno=38\nkind=seccomp_uid\tinstall_status=unsupported\tinstall_error=38"),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outUnsupported = unsupported.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.UNSUPPORTED, outUnsupported.getState());
        assertFalse(outUnsupported.isDetected());

        HmaUidVisibilityProbe restricted = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, true,
                (f, l) -> SignalResult.success("status=RESTRICTED\terrno=13"),
                (f, l) -> SignalResult.success("status=RESTRICTED\terrno=13\nkind=seccomp_uid\tinstall_status=restricted\tinstall_error=13"),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outRestricted = restricted.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.UNAVAILABLE, outRestricted.getState());
        assertFalse(outRestricted.isDetected());

        HmaUidVisibilityProbe malformed = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, true,
                (f, l) -> SignalResult.success("not-a-valid-frame"),
                (f, l) -> SignalResult.success("also-malformed"),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outMalformed = malformed.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.UNAVAILABLE, outMalformed.getState());
        assertFalse(outMalformed.isDetected());
    }

    @Test
    public void selfControlFailureAndBudgetTruncationHandledSafely() {
        String activeFrame = "status=OK\terrno=0\tcomplete=1\n"
                + "kind=active_uid\tuid=10202";

        // Self-control fails (self UID missing from getPackagesForUid) -> must NOT flag 10202!
        HmaUidVisibilityProbe brokenControl = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, true,
                (f, l) -> SignalResult.success(activeFrame),
                (f, l) -> SignalResult.success("status=UNSUPPORTED\terrno=38"),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        assertFalse(brokenControl.probe().isDetected());

        // Time budget exceeded -> PARTIAL without false positive
        Map<Integer, String[]> pkgMap = new HashMap<>();
        pkgMap.put(SELF_UID, new String[]{SELF_PKG});
        pkgMap.put(10202, new String[]{"com.example.ok"});
        HmaUidVisibilityProbe budgetHit = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, true,
                (f, l) -> SignalResult.success(activeFrame),
                (f, l) -> SignalResult.success(cleanSeccompFrame()),
                pkgMap,
                new AtomicLong(0L),
                1500L), // advances clock past 1000ms budget immediately
                1000L);
        HmaUidVisibilityProbe.ProbeOutcome outPartial = budgetHit.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.PARTIAL, outPartial.getState());
        assertTrue(outPartial.isTruncated());
        assertFalse(outPartial.isDetected());
    }

    @Test
    public void malformedSeccompCountsAndBoundsNeverProduceFalsePositive() {
        // Missing notified field in status=OK seccomp_uid record must degrade to UNAVAILABLE
        String missingNotified = "status=OK\terrno=0\n"
                + "kind=seccomp_uid\tinstall_status=installed\tinstall_error=0\t"
                + "queried=10000\tquery_outcome=complete\tquery_error=0";
        HmaUidVisibilityProbe probeMissing = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false,
                (f, l) -> SignalResult.unavailable("skipped"),
                (f, l) -> SignalResult.success(missingNotified),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outMissing = probeMissing.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.UNAVAILABLE, outMissing.getState());
        assertFalse(outMissing.isDetected());

        // Out-of-range suppressed bounds must degrade to UNAVAILABLE
        String badBounds = "status=OK\terrno=0\n"
                + "kind=seccomp_uid\tinstall_status=installed\tinstall_error=0\t"
                + "queried=10000\tnotified=9999\tfirst_suppressed=-1\tlast_suppressed=-1\t"
                + "query_outcome=complete\tquery_error=0";
        HmaUidVisibilityProbe probeBadBounds = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false,
                (f, l) -> SignalResult.unavailable("skipped"),
                (f, l) -> SignalResult.success(badBounds),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outBadBounds = probeBadBounds.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.UNAVAILABLE, outBadBounds.getState());
        assertFalse(outBadBounds.isDetected());
    }

    @Test
    public void seccompTrappedQueryDetectsWhileInstallTrapAndExitedUidDegradeCleanly() {
        // query_outcome=trapped -> positive hma_seccomp_query_trapped
        String queryTrapped = "status=OK\terrno=0\n"
                + "kind=seccomp_uid\tinstall_status=installed\tinstall_error=0\t"
                + "queried=0\tnotified=5\tfirst_suppressed=-1\tlast_suppressed=-1\t"
                + "query_outcome=trapped\tquery_error=31\tself_notified=0";
        HmaUidVisibilityProbe probeTrapped = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false,
                (f, l) -> SignalResult.unavailable("skipped"),
                (f, l) -> SignalResult.success(queryTrapped),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outTrapped = probeTrapped.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.DETECTED, outTrapped.getState());
        assertEquals("hma_seccomp_query_trapped", outTrapped.getEvidenceItems().get(0).getCode());

        // install_trapped -> UNAVAILABLE (0 FP)
        String installTrapped = "status=OK\terrno=0\n"
                + "kind=seccomp_uid\tinstall_status=install_trapped\tinstall_error=31\t"
                + "queried=0\tnotified=0\tfirst_suppressed=-1\tlast_suppressed=-1\t"
                + "query_outcome=not_run\tquery_error=0\tself_notified=0";
        HmaUidVisibilityProbe probeInstallTrap = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, false,
                (f, l) -> SignalResult.unavailable("skipped"),
                (f, l) -> SignalResult.success(installTrapped),
                new HashMap<>(),
                new AtomicLong(0L),
                0L));
        assertEquals(HmaUidVisibilityProbe.ProbeState.UNAVAILABLE, probeInstallTrap.probe().getState());
        assertFalse(probeInstallTrap.probe().isDetected());

        // Transient process exits before single-UID recheck -> CLEAN (0 FP)
        int exitingUid = 10299;
        String activeFrame = "status=OK\terrno=0\tcomplete=1\nkind=active_uid\tuid=" + exitingUid;
        Map<Integer, String[]> pkgMap = new HashMap<>();
        pkgMap.put(SELF_UID, new String[]{SELF_PKG});
        HmaUidVisibilityProbe probeExited = new HmaUidVisibilityProbe(new FakeEnv(
                SELF_UID, SELF_PKG, true,
                (f, l) -> {
                    if (f == exitingUid && l == exitingUid) {
                        return SignalResult.success("status=OK\terrno=0\tcomplete=1");
                    }
                    return SignalResult.success(activeFrame);
                },
                (f, l) -> SignalResult.success(cleanSeccompFrame()),
                pkgMap,
                new AtomicLong(0L),
                0L));
        HmaUidVisibilityProbe.ProbeOutcome outExited = probeExited.probe();
        assertEquals(HmaUidVisibilityProbe.ProbeState.CLEAN, outExited.getState());
        assertFalse(outExited.isDetected());
    }

    private interface RangeFn {
        SignalResult<String> call(int firstUid, int lastUid);
    }

    private static final class FakeEnv implements HmaUidVisibilityProbe.Environment {
        private final int myUid;
        private final String myPkg;
        private final boolean fullVisibility;
        private final RangeFn activeScan;
        private final RangeFn seccompProbe;
        private final Map<Integer, String[]> packagesByUid;
        private final AtomicLong clock;
        private final long clockStep;

        FakeEnv(int myUid,
                String myPkg,
                boolean fullVisibility,
                RangeFn activeScan,
                RangeFn seccompProbe,
                Map<Integer, String[]> packagesByUid,
                AtomicLong clock,
                long clockStep) {
            this.myUid = myUid;
            this.myPkg = myPkg;
            this.fullVisibility = fullVisibility;
            this.activeScan = activeScan;
            this.seccompProbe = seccompProbe;
            this.packagesByUid = packagesByUid;
            this.clock = clock;
            this.clockStep = clockStep;
        }

        @Override public int getMyUid() { return myUid; }
        @Override public String getMyPackageName() { return myPkg; }
        @Override public boolean hasFullPackageVisibility() { return fullVisibility; }
        @Override public SignalResult<String> scanActiveAppUids(int firstUid, int lastUid) {
            return activeScan.call(firstUid, lastUid);
        }
        @Override public SignalResult<String> probeSeccompUidFilter(int firstUid, int lastUid) {
            return seccompProbe.call(firstUid, lastUid);
        }
        @Override public String[] getPackagesForUid(int uid) {
            return packagesByUid.get(uid);
        }
        @Override public long elapsedRealtimeMs() {
            return clock.getAndAdd(clockStep);
        }
    }
}
