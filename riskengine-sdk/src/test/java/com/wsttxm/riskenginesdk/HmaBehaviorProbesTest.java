package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.detector.probe.threat.HmaCrossUserProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaOrderedBroadcastProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaPermissionServiceProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThanoxIpcProbe;
import com.wsttxm.riskenginesdk.model.EvidenceItem;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HmaBehaviorProbesTest {

    private static final String CALLER_PKG = "com.host.banking";
    private static final String TARGET_PKG = "me.weishu.kernelsu";

    // ==================== 1. HmaCrossUserProbe ====================

    @Test
    public void crossUserProbeDetectsExceptionSuppressionWithValidControls() {
        HmaCrossUserProbe probe = new HmaCrossUserProbe(new HmaCrossUserProbe.CrossUserAdapter() {
            @Override public String getCallerPackageName() { return CALLER_PKG; }
            @Override public HmaCrossUserProbe.CallOutcome queryPackageInfoAnyUser(String pkg) {
                return CALLER_PKG.equals(pkg)
                        ? HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION
                        : HmaCrossUserProbe.CallOutcome.NAME_NOT_FOUND;
            }
            @Override public HmaCrossUserProbe.CallOutcome queryApplicationInfoAnyUser(String pkg) {
                return HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
            }
            @Override public HmaCrossUserProbe.CallOutcome sendCrossUserBroadcast(String pkg) {
                return CALLER_PKG.equals(pkg)
                        ? HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION
                        : HmaCrossUserProbe.CallOutcome.NULL_OR_RETURNED;
            }
        });

        HmaCrossUserProbe.ProbeOutcome outcome = probe.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaCrossUserProbe.ProbeState.DETECTED, outcome.getState());
        assertTrue(outcome.isDetected());
        assertTrue(outcome.getSuppressedPackages().contains(TARGET_PKG));
        assertEquals(2, outcome.getEvidenceItems().size());
        for (EvidenceItem item : outcome.getEvidenceItems()) {
            assertEquals("hma_cross_user_suppression", item.getCode());
            assertEquals("hma_hiding", item.getEvidenceFamily());
            assertEquals(EvidenceItem.Rank.STRONG, item.getRank());
        }
    }

    @Test
    public void crossUserProbeStockCleanAndControlFailureProduceZeroFalsePositives() {
        // Stock Android: both caller and target throw SecurityException -> CLEAN
        HmaCrossUserProbe stock = new HmaCrossUserProbe(new HmaCrossUserProbe.CrossUserAdapter() {
            @Override public String getCallerPackageName() { return CALLER_PKG; }
            @Override public HmaCrossUserProbe.CallOutcome queryPackageInfoAnyUser(String pkg) {
                return HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
            }
            @Override public HmaCrossUserProbe.CallOutcome queryApplicationInfoAnyUser(String pkg) {
                return HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
            }
        });
        HmaCrossUserProbe.ProbeOutcome cleanOut = stock.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaCrossUserProbe.ProbeState.CLEAN, cleanOut.getState());
        assertFalse(cleanOut.isDetected());

        // OEM quirk where caller control returns NameNotFound instead of SecurityException -> UNAVAILABLE
        HmaCrossUserProbe brokenCtrl = new HmaCrossUserProbe(new HmaCrossUserProbe.CrossUserAdapter() {
            @Override public String getCallerPackageName() { return CALLER_PKG; }
            @Override public HmaCrossUserProbe.CallOutcome queryPackageInfoAnyUser(String pkg) {
                return HmaCrossUserProbe.CallOutcome.NAME_NOT_FOUND;
            }
            @Override public HmaCrossUserProbe.CallOutcome queryApplicationInfoAnyUser(String pkg) {
                return HmaCrossUserProbe.CallOutcome.NAME_NOT_FOUND;
            }
        });
        HmaCrossUserProbe.ProbeOutcome ctrlOut = brokenCtrl.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaCrossUserProbe.ProbeState.UNAVAILABLE, ctrlOut.getState());
        assertFalse(ctrlOut.isDetected());
    }

    // ==================== 2. HmaOrderedBroadcastProbe ====================

    @Test
    public void orderedBroadcastDetectsHmaOss173OrderedTrueAndHmaOss164MissingResultTo() {
        // HMA-OSS #173: target receives resultTo with isOrderedBroadcast() == true
        HmaOrderedBroadcastProbe probe173 = new HmaOrderedBroadcastProbe(
                new HmaOrderedBroadcastProbe.BroadcastTransport() {
                    @Override public String getCallerPackageName() { return CALLER_PKG; }
                    @Override public HmaOrderedBroadcastProbe.CallbackObservation sendAndAwait(String pkg) {
                        if (CALLER_PKG.equals(pkg)) {
                            return HmaOrderedBroadcastProbe.CallbackObservation.cleanConsistent();
                        }
                        return new HmaOrderedBroadcastProbe.CallbackObservation(
                                true, true, false, true, true,
                                HmaOrderedBroadcastProbe.CallbackFailure.NONE);
                    }
                    @Override public long elapsedRealtimeMs() { return 0L; }
                });
        HmaOrderedBroadcastProbe.ProbeOutcome out173 =
                probe173.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaOrderedBroadcastProbe.ProbeState.DETECTED, out173.getState());
        assertEquals("hma_ordered_broadcast_semantic", out173.getEvidenceItems().get(0).getCode());
        assertEquals("hma_hiding", out173.getEvidenceItems().get(0).getEvidenceFamily());

        // HMA-OSS #164: target repeatedly drops final resultTo while self-controls pass
        HmaOrderedBroadcastProbe probe164 = new HmaOrderedBroadcastProbe(
                new HmaOrderedBroadcastProbe.BroadcastTransport() {
                    @Override public String getCallerPackageName() { return CALLER_PKG; }
                    @Override public HmaOrderedBroadcastProbe.CallbackObservation sendAndAwait(String pkg) {
                        return CALLER_PKG.equals(pkg)
                                ? HmaOrderedBroadcastProbe.CallbackObservation.cleanConsistent()
                                : HmaOrderedBroadcastProbe.CallbackObservation.timedOut();
                    }
                    @Override public long elapsedRealtimeMs() { return 0L; }
                });
        HmaOrderedBroadcastProbe.ProbeOutcome out164 =
                probe164.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaOrderedBroadcastProbe.ProbeState.DETECTED, out164.getState());
        assertEquals("hma_ordered_broadcast_missing_result",
                out164.getEvidenceItems().get(0).getCode());
        assertEquals("hma_hiding", out164.getEvidenceItems().get(0).getEvidenceFamily());
    }

    @Test
    public void orderedBroadcastCleanAndControlFailureProduceZeroFalsePositives() {
        HmaOrderedBroadcastProbe clean = new HmaOrderedBroadcastProbe(
                new HmaOrderedBroadcastProbe.BroadcastTransport() {
                    @Override public String getCallerPackageName() { return CALLER_PKG; }
                    @Override public HmaOrderedBroadcastProbe.CallbackObservation sendAndAwait(String pkg) {
                        return HmaOrderedBroadcastProbe.CallbackObservation.cleanConsistent();
                    }
                    @Override public long elapsedRealtimeMs() { return 0L; }
                });
        HmaOrderedBroadcastProbe.ProbeOutcome cleanOut =
                clean.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaOrderedBroadcastProbe.ProbeState.CLEAN, cleanOut.getState());
        assertFalse(cleanOut.isDetected());

        // Initial self-control fails -> UNAVAILABLE, target never flagged
        AtomicInteger targetCalls = new AtomicInteger();
        HmaOrderedBroadcastProbe badCtrl = new HmaOrderedBroadcastProbe(
                new HmaOrderedBroadcastProbe.BroadcastTransport() {
                    @Override public String getCallerPackageName() { return CALLER_PKG; }
                    @Override public HmaOrderedBroadcastProbe.CallbackObservation sendAndAwait(String pkg) {
                        if (!CALLER_PKG.equals(pkg)) targetCalls.incrementAndGet();
                        return HmaOrderedBroadcastProbe.CallbackObservation.timedOut();
                    }
                    @Override public long elapsedRealtimeMs() { return 0L; }
                });
        HmaOrderedBroadcastProbe.ProbeOutcome ctrlOut =
                badCtrl.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaOrderedBroadcastProbe.ProbeState.UNAVAILABLE, ctrlOut.getState());
        assertFalse(ctrlOut.isDetected());
        assertEquals(0, targetCalls.get());
    }

    // ==================== 3. HmaPermissionServiceProbe ====================

    @Test
    public void permissionServiceProbeGatedToApi35DetectsHiddenUidAndMarksBudgetTruncationPartial() {
        // API 34 -> UNSUPPORTED
        HmaPermissionServiceProbe api34 = new HmaPermissionServiceProbe(
                new FakePermEnv(34, 10200, true, new HashMap<>(), new HashMap<>(),
                        new AtomicLong(0L), 0L));
        assertEquals(HmaPermissionServiceProbe.ProbeState.UNSUPPORTED, api34.probe().getState());

        // API 35 with hidden UID 10250 holding ACCESS_WIFI_STATE while getPackagesForUid is empty -> DETECTED
        Map<Integer, List<String>> grantedPerms = new HashMap<>();
        grantedPerms.put(10200, Collections.singletonList("android.permission.INTERNET"));
        grantedPerms.put(10250, Collections.singletonList("android.permission.ACCESS_WIFI_STATE"));
        Map<Integer, String[]> pkgs = new HashMap<>();
        pkgs.put(10200, new String[]{CALLER_PKG});
        pkgs.put(10250, new String[0]);

        HmaPermissionServiceProbe detected = new HmaPermissionServiceProbe(
                new FakePermEnv(35, 10200, true, grantedPerms, pkgs, new AtomicLong(0L), 0L));
        HmaPermissionServiceProbe.ProbeOutcome outDetected = detected.probe();
        assertEquals(HmaPermissionServiceProbe.ProbeState.DETECTED, outDetected.getState());
        assertEquals("hma_permission_service_diff", outDetected.getEvidenceItems().get(0).getCode());
        assertEquals("hma_hiding", outDetected.getEvidenceItems().get(0).getEvidenceFamily());

        // API 36 clean device hitting 1000ms wall-clock budget -> PARTIAL (0 FP)
        Map<Integer, List<String>> cleanPerms = new HashMap<>();
        cleanPerms.put(10200, Collections.singletonList("android.permission.INTERNET"));
        Map<Integer, String[]> cleanPkgs = new HashMap<>();
        cleanPkgs.put(10200, new String[]{CALLER_PKG});
        HmaPermissionServiceProbe truncated = new HmaPermissionServiceProbe(
                new FakePermEnv(36, 10200, true, cleanPerms, cleanPkgs,
                        new AtomicLong(0L), 500L), // 2 steps exceed 1000ms budget
                1000L);
        HmaPermissionServiceProbe.ProbeOutcome outPartial = truncated.probe();
        assertEquals(HmaPermissionServiceProbe.ProbeState.PARTIAL, outPartial.getState());
        assertTrue(outPartial.isTruncated());
        assertFalse(outPartial.isDetected());
    }

    // ==================== 4. ThanoxIpcProbe ====================

    @Test
    public void thanoxIpcMatchesExactDescriptorAndIgnoresOriginOsAndStockDropBox() {
        // Exact Thanox descriptor -> DETECTED
        ThanoxIpcProbe matched = new ThanoxIpcProbe(() -> new ThanoxIpcProbe.TransactOutcome(
                ThanoxIpcProbe.TransactOutcome.Kind.RETURNED_BINDER,
                "github.tornaco.android.thanos.core.IThanos",
                "returned_binder"));
        ThanoxIpcProbe.ProbeOutcome outMatched = matched.probe();
        assertEquals(ThanoxIpcProbe.ProbeState.DETECTED, outMatched.getState());
        assertEquals("thanox_ipc_active", outMatched.getEvidenceItems().get(0).getCode());
        assertEquals("hma_hiding", outMatched.getEvidenceItems().get(0).getEvidenceFamily());
        assertEquals(EvidenceItem.Rank.STRONG, outMatched.getEvidenceItems().get(0).getRank());

        // OriginOS / stock dropbox returning a non-Thanos Binder descriptor -> CLEAN (0 FP!)
        ThanoxIpcProbe originOs = new ThanoxIpcProbe(() -> new ThanoxIpcProbe.TransactOutcome(
                ThanoxIpcProbe.TransactOutcome.Kind.RETURNED_BINDER,
                "com.vivo.services.dropbox.IVivoDropBoxService",
                "returned_binder"));
        ThanoxIpcProbe.ProbeOutcome outOrigin = originOs.probe();
        assertEquals(ThanoxIpcProbe.ProbeState.CLEAN, outOrigin.getState());
        assertFalse(outOrigin.isDetected());
        assertEquals("com.vivo.services.dropbox.IVivoDropBoxService",
                outOrigin.getObservedDescriptor());

        // Stock dropbox not handling Thanox transaction -> CLEAN (0 FP)
        ThanoxIpcProbe stock = new ThanoxIpcProbe(() -> new ThanoxIpcProbe.TransactOutcome(
                ThanoxIpcProbe.TransactOutcome.Kind.NOT_HANDLED, null, "not_handled"));
        assertEquals(ThanoxIpcProbe.ProbeState.CLEAN, stock.probe().getState());
        assertFalse(stock.probe().isDetected());
    }

    @Test
    public void crossUserPostControlFailureAndTransientSingleHitProduceZeroFalsePositives() {
        // Post-scan control fails -> MUST invalidate suppressed target (0 FP)
        AtomicInteger callerCalls = new AtomicInteger();
        HmaCrossUserProbe postCtrlFail = new HmaCrossUserProbe(new HmaCrossUserProbe.CrossUserAdapter() {
            @Override public String getCallerPackageName() { return CALLER_PKG; }
            @Override public HmaCrossUserProbe.CallOutcome queryPackageInfoAnyUser(String pkg) {
                if (CALLER_PKG.equals(pkg)) {
                    return callerCalls.incrementAndGet() == 1
                            ? HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION
                            : HmaCrossUserProbe.CallOutcome.NAME_NOT_FOUND;
                }
                return HmaCrossUserProbe.CallOutcome.NAME_NOT_FOUND;
            }
            @Override public HmaCrossUserProbe.CallOutcome queryApplicationInfoAnyUser(String pkg) {
                return HmaCrossUserProbe.CallOutcome.UNAVAILABLE;
            }
        });
        assertEquals(HmaCrossUserProbe.ProbeState.UNAVAILABLE,
                postCtrlFail.probe(Collections.singletonList(TARGET_PKG)).getState());
        assertFalse(postCtrlFail.probe(Collections.singletonList(TARGET_PKG)).isDetected());

        // Single non-repeated suppression (first=NNFE, second=SecurityException) -> 0 FP
        AtomicInteger targetCalls = new AtomicInteger();
        HmaCrossUserProbe transientHit = new HmaCrossUserProbe(new HmaCrossUserProbe.CrossUserAdapter() {
            @Override public String getCallerPackageName() { return CALLER_PKG; }
            @Override public HmaCrossUserProbe.CallOutcome queryPackageInfoAnyUser(String pkg) {
                if (CALLER_PKG.equals(pkg)) return HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
                return targetCalls.incrementAndGet() == 1
                        ? HmaCrossUserProbe.CallOutcome.NAME_NOT_FOUND
                        : HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
            }
            @Override public HmaCrossUserProbe.CallOutcome queryApplicationInfoAnyUser(String pkg) {
                return HmaCrossUserProbe.CallOutcome.UNAVAILABLE;
            }
        });
        assertFalse(transientHit.probe(Collections.singletonList(TARGET_PKG)).isDetected());
    }

    @Test
    public void orderedBroadcastInterleavedControlFailureAndBudgetPartialAreSafe() {
        // Between control fails -> target skipped, 0 FP
        AtomicInteger selfCalls = new AtomicInteger();
        HmaOrderedBroadcastProbe betweenFail = new HmaOrderedBroadcastProbe(
                new HmaOrderedBroadcastProbe.BroadcastTransport() {
                    @Override public String getCallerPackageName() { return CALLER_PKG; }
                    @Override public HmaOrderedBroadcastProbe.CallbackObservation sendAndAwait(String pkg) {
                        if (CALLER_PKG.equals(pkg)) {
                            int n = selfCalls.incrementAndGet();
                            // 1=initial, 2=before, 3=between (fails!)
                            return n == 3
                                    ? HmaOrderedBroadcastProbe.CallbackObservation.timedOut()
                                    : HmaOrderedBroadcastProbe.CallbackObservation.cleanConsistent();
                        }
                        return HmaOrderedBroadcastProbe.CallbackObservation.timedOut();
                    }
                    @Override public long elapsedRealtimeMs() { return 0L; }
                });
        HmaOrderedBroadcastProbe.ProbeOutcome outBetween =
                betweenFail.probe(Collections.singletonList(TARGET_PKG));
        assertEquals(HmaOrderedBroadcastProbe.ProbeState.UNAVAILABLE, outBetween.getState());
        assertFalse(outBetween.isDetected());

        // Budget expires after first target -> PARTIAL, 0 FP
        AtomicLong clock = new AtomicLong(0L);
        HmaOrderedBroadcastProbe budgetPartial = new HmaOrderedBroadcastProbe(
                new HmaOrderedBroadcastProbe.BroadcastTransport() {
                    @Override public String getCallerPackageName() { return CALLER_PKG; }
                    @Override public HmaOrderedBroadcastProbe.CallbackObservation sendAndAwait(String pkg) {
                        return HmaOrderedBroadcastProbe.CallbackObservation.cleanConsistent();
                    }
                    @Override public long elapsedRealtimeMs() {
                        return clock.getAndAdd(600L);
                    }
                },
                500L);
        HmaOrderedBroadcastProbe.ProbeOutcome outPartial =
                budgetPartial.probe(Arrays.asList(TARGET_PKG, "com.topjohnwu.magisk"));
        assertEquals(HmaOrderedBroadcastProbe.ProbeState.PARTIAL, outPartial.getState());
        assertTrue(outPartial.isTruncated());
        assertFalse(outPartial.isDetected());
    }

    @Test
    public void permissionServiceCleanVisibilityNonInstantControlFailureAndTransientRaceAreZeroFp() {
        Map<Integer, List<String>> cleanPerms = new HashMap<>();
        cleanPerms.put(10200, Collections.singletonList("android.permission.INTERNET"));
        cleanPerms.put(10210, Collections.singletonList("android.permission.ACCESS_WIFI_STATE"));
        Map<Integer, String[]> cleanPkgs = new HashMap<>();
        cleanPkgs.put(10200, new String[]{CALLER_PKG});
        cleanPkgs.put(10210, new String[]{"com.android.chrome"});

        // Full 10,000-UID clean scan -> CLEAN (0 FP)
        HmaPermissionServiceProbe cleanProbe = new HmaPermissionServiceProbe(
                new FakePermEnv(35, 10200, true, cleanPerms, cleanPkgs, new AtomicLong(0L), 0L));
        HmaPermissionServiceProbe.ProbeOutcome outClean = cleanProbe.probe();
        assertEquals(HmaPermissionServiceProbe.ProbeState.CLEAN, outClean.getState());
        assertEquals(HmaPermissionServiceProbe.UID_SPAN, outClean.getCheckedUids());
        assertFalse(outClean.isDetected());

        // Missing QUERY_ALL_PACKAGES -> UNAVAILABLE (0 FP)
        HmaPermissionServiceProbe noVis = new HmaPermissionServiceProbe(
                new FakePermEnv(35, 10200, false, cleanPerms, cleanPkgs, new AtomicLong(0L), 0L));
        assertEquals(HmaPermissionServiceProbe.ProbeState.UNAVAILABLE, noVis.probe().getState());

        // Instant permission definitions -> UNSUPPORTED (0 FP)
        HmaPermissionServiceProbe instantPerm = new HmaPermissionServiceProbe(
                new FakePermEnv(35, 10200, true, cleanPerms, cleanPkgs, new AtomicLong(0L), 0L,
                        true, false));
        assertEquals(HmaPermissionServiceProbe.ProbeState.UNSUPPORTED,
                instantPerm.probe().getState());

        // Post-scan self-control failure MUST discard previously collected hidden UIDs (0 FP)
        AtomicInteger selfPkgLookups = new AtomicInteger();
        HmaPermissionServiceProbe postCtrlFail = new HmaPermissionServiceProbe(
                new FakePermEnv(35, 10200, true, cleanPerms, cleanPkgs, new AtomicLong(0L), 0L) {
                    @Override public Boolean checkUidPermissionWire(int uid, String permission) {
                        if (uid == 10250 && "android.permission.ACCESS_WIFI_STATE".equals(permission)) {
                            return Boolean.TRUE;
                        }
                        return super.checkUidPermissionWire(uid, permission);
                    }
                    @Override public String[] getPackagesForUidWire(int uid) {
                        if (uid == 10200) {
                            // First call (pre-control) passes; second call (post-control) fails!
                            return selfPkgLookups.incrementAndGet() == 1
                                    ? new String[]{CALLER_PKG}
                                    : new String[0];
                        }
                        return super.getPackagesForUidWire(uid);
                    }
                });
        HmaPermissionServiceProbe.ProbeOutcome outPostFail = postCtrlFail.probe();
        assertEquals(HmaPermissionServiceProbe.ProbeState.UNAVAILABLE, outPostFail.getState());
        assertFalse(outPostFail.isDetected());

        // Transient uninstall race (permission disappears on recheck) -> CLEAN (0 FP)
        AtomicInteger raceCalls = new AtomicInteger();
        HmaPermissionServiceProbe transientRace = new HmaPermissionServiceProbe(
                new FakePermEnv(35, 10200, true, cleanPerms, cleanPkgs, new AtomicLong(0L), 0L) {
                    @Override public Boolean checkUidPermissionWire(int uid, String permission) {
                        if (uid == 10260 && "android.permission.ACCESS_WIFI_STATE".equals(permission)) {
                            return raceCalls.incrementAndGet() == 1;
                        }
                        return super.checkUidPermissionWire(uid, permission);
                    }
                });
        HmaPermissionServiceProbe.ProbeOutcome outRace = transientRace.probe();
        assertEquals(HmaPermissionServiceProbe.ProbeState.CLEAN, outRace.getState());
        assertFalse(outRace.isDetected());

        // Wire control helper strictly requires positive + negative contrast
        assertTrue(HmaPermissionServiceProbe.verifyWirePermissionControl(true, Boolean.TRUE, Boolean.FALSE));
        assertFalse(HmaPermissionServiceProbe.verifyWirePermissionControl(false, Boolean.FALSE, Boolean.FALSE));
        assertFalse(HmaPermissionServiceProbe.verifyWirePermissionControl(true, Boolean.FALSE, Boolean.FALSE));
        assertFalse(HmaPermissionServiceProbe.verifyWirePermissionControl(true, Boolean.TRUE, Boolean.TRUE));
        assertEquals(null, HmaPermissionServiceProbe.transactPermissionMgrCheckUidPermission(null, 1, 10200, "p", 0));
        assertEquals(null, HmaPermissionServiceProbe.transactPackageMgrCheckUidPermission(null, 1, "p", 10200));
        assertEquals(null, HmaPermissionServiceProbe.transactGetPackagesForUid(null, HmaPermissionServiceProbe.DESC_PACKAGE_MANAGER, 1, 10200));
    }

    private static class FakePermEnv implements HmaPermissionServiceProbe.Environment {
        private final int sdkInt;
        private final int myUid;
        private final boolean fullVisibility;
        private final Map<Integer, List<String>> grantedPerms;
        private final Map<Integer, String[]> packagesByUid;
        private final AtomicLong clock;
        private final long clockStep;
        private final boolean internetGranted;
        private final boolean nonInstant;

        FakePermEnv(int sdkInt,
                    int myUid,
                    boolean fullVisibility,
                    Map<Integer, List<String>> grantedPerms,
                    Map<Integer, String[]> packagesByUid,
                    AtomicLong clock,
                    long clockStep) {
            this(sdkInt, myUid, fullVisibility, grantedPerms, packagesByUid, clock, clockStep, true, true);
        }

        FakePermEnv(int sdkInt,
                    int myUid,
                    boolean fullVisibility,
                    Map<Integer, List<String>> grantedPerms,
                    Map<Integer, String[]> packagesByUid,
                    AtomicLong clock,
                    long clockStep,
                    boolean internetGranted,
                    boolean nonInstant) {
            this.sdkInt = sdkInt;
            this.myUid = myUid;
            this.fullVisibility = fullVisibility;
            this.grantedPerms = grantedPerms;
            this.packagesByUid = packagesByUid;
            this.clock = clock;
            this.clockStep = clockStep;
            this.internetGranted = internetGranted;
            this.nonInstant = nonInstant;
        }

        @Override public int getSdkInt() { return sdkInt; }
        @Override public int getMyUid() { return myUid; }
        @Override public String getMyPackageName() { return CALLER_PKG; }
        @Override public boolean hasFullPackageVisibility() { return fullVisibility; }
        @Override public boolean isCallerInternetGranted() { return internetGranted; }
        @Override public boolean areProbePermissionsNonInstant() { return nonInstant; }
        @Override public Boolean checkUidPermissionWire(int uid, String permission) {
            List<String> perms = grantedPerms.get(uid);
            return perms != null && perms.contains(permission);
        }
        @Override public String[] getPackagesForUidWire(int uid) {
            String[] pkgs = packagesByUid.get(uid);
            return pkgs == null ? new String[0] : pkgs;
        }
        @Override public long elapsedRealtimeMs() {
            return clock.getAndAdd(clockStep);
        }
    }
}
