package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.CorrelationEngine;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.EvidenceFamily;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.detector.BaseDetector;
import com.wsttxm.riskenginesdk.detector.DetectorRegistry;
import com.wsttxm.riskenginesdk.detector.ThreatAppDetector;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaCrossUserProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaOrderedBroadcastProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaPermissionServiceProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaUidVisibilityProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThanoxIpcProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThreatAppPackageProbe;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ThreatAppDetectorTest {

    private static final String KSU_OFFICIAL_SHA =
            "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6";
    private static final String CUSTOM_CERT_SHA =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    @Test
    public void registersAsSixteenthConvergedDomainStrictlyInPostponedTier() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();
        DetectorRegistry registry = new DetectorRegistry(null, config);
        assertEquals(16, registry.getDetectors().size());

        BaseDetector found = null;
        for (BaseDetector d : registry.getDetectors()) {
            if ("threat_apps".equals(d.getName())) {
                found = d;
                break;
            }
        }
        assertNotNull("threat_apps must be registered by default", found);
        assertEquals(ScanTier.POSTPONED, found.getScanTier());
    }

    @Test
    public void hmaBehavioralSideChannelScoresHigh7ActionableInAllScenesWithIndependentFamily() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();
        ThreatAppDetector detector = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv() {
            @Override
            public ThanoxIpcProbe.ProbeOutcome runThanoxIpcProbe() {
                return new ThanoxIpcProbe(() -> new ThanoxIpcProbe.TransactOutcome(
                        ThanoxIpcProbe.TransactOutcome.Kind.RETURNED_BINDER,
                        ThanoxIpcProbe.THANOX_DESCRIPTOR,
                        "matched")).probe();
            }
        });

        DetectionResult raw = detector.call();
        assertEquals("threat_apps", raw.getDetectorName());
        assertEquals(ScanTier.POSTPONED, raw.getScanTier());
        assertEquals(RiskLevel.HIGH, raw.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, raw.getStatus());
        assertEquals(7, raw.getScore());
        assertFalse(raw.isInformational());

        Set<String> families = EvidenceFamily.families(raw.getDetails(), raw.getEvidenceItems());
        assertTrue(families.contains("hma_hiding"));
        assertFalse(families.contains("root_fw"));

        for (CollectScene scene : CollectScene.values()) {
            DetectionResult applied = CorrelationEngine.applyScene(raw, scene);
            assertEquals(RiskLevel.HIGH, applied.getRiskLevel());
            assertEquals(7, applied.getScore());
            assertFalse("HMA side-channel must stay actionable in " + scene,
                    applied.isInformational());
        }
    }

    @Test
    public void signedThreatToolAndCustomPolicyScoreMedium5ActionableInAllScenes() {
        ThreatAppPolicy policy = new ThreatAppPolicy.Builder()
                .additionalPackages("com.cheat.memory")
                .additionalCertSha256s(CUSTOM_CERT_SHA)
                .enableHmaProbes(false)
                .build();
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .threatAppPolicy(policy)
                .build();

        ThreatAppDetector detector = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv() {
            @Override
            public ThreatAppPackageProbe.ProbeOutcome runPackageProbe(ThreatAppPolicy effective) {
                ThreatAppPackageProbe.InspectedApp cheatApp = new ThreatAppPackageProbe.InspectedApp(
                        "com.cheat.memory",
                        Collections.singletonList(CUSTOM_CERT_SHA),
                        null,
                        Collections.emptyList(),
                        null);
                return new ThreatAppPackageProbe(
                        (pkg, includePerms) -> "com.cheat.memory".equals(pkg) ? cheatApp : null,
                        (dir, payloads) -> ThreatAppPackageProbe.PayloadScanResult.observed(Collections.emptySet()),
                        app -> null).probe(effective);
            }
        });

        DetectionResult res = detector.call();
        assertEquals(RiskLevel.MEDIUM, res.getRiskLevel());
        assertEquals(DetectionStatus.WARNING, res.getStatus());
        assertEquals(5, res.getScore());
        assertFalse(res.isInformational());

        for (CollectScene scene : CollectScene.values()) {
            DetectionResult applied = CorrelationEngine.applyScene(res, scene);
            assertEquals(RiskLevel.MEDIUM, applied.getRiskLevel());
            assertEquals(5, applied.getScore());
            assertFalse(applied.isInformational());
        }
    }

    @Test
    public void rootManagerHitDeduplicatesWithRootDetectorOnRootFwWhileHmaHidingStaysIndependent() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();

        // 1. Root manager detected by ThreatAppDetector shares root_fw with RootDetector
        ThreatAppDetector rootMgrDetector = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv() {
            @Override
            public ThreatAppPackageProbe.ProbeOutcome runPackageProbe(ThreatAppPolicy effective) {
                ThreatAppPackageProbe.InspectedApp ksu = new ThreatAppPackageProbe.InspectedApp(
                        "me.weishu.kernelsu",
                        Collections.singletonList(KSU_OFFICIAL_SHA),
                        "/data/app/ksu/lib/arm64",
                        Collections.emptyList(),
                        null);
                return new ThreatAppPackageProbe(
                        (pkg, includePerms) -> "me.weishu.kernelsu".equals(pkg) ? ksu : null,
                        (dir, payloads) -> ThreatAppPackageProbe.PayloadScanResult.observed(
                                Collections.singleton("libksud.so")),
                        app -> null).probe(effective);
            }
        });

        DetectionResult threatRootRes = rootMgrDetector.call();
        Set<String> threatRootFamilies =
                EvidenceFamily.families(threatRootRes.getDetails(), threatRootRes.getEvidenceItems());
        assertEquals(Collections.singleton("root_fw"), threatRootFamilies);

        DetectionResult rootRes = new DetectionResult(
                "root",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8,
                10,
                false,
                Collections.singletonList("su_found:/system/bin/su"),
                "su_found:/system/bin/su")
                .withEvidenceItems(Collections.singletonList(new EvidenceItem(
                        "su_found",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/system/bin/su",
                        "exists",
                        "root_fw",
                        EvidenceItem.Rank.STRONG)));

        DataAggregator aggregator = new DataAggregator();
        RiskReport dedupedReport = aggregator.aggregate(
                Collections.emptyList(),
                Arrays.asList(rootRes, threatRootRes),
                CollectScene.STANDARD);

        // Deduped: threat_apps's root_fw MUST NOT double-score on top of root's root_fw
        // (family-max 72 + bounded corroboration lift 6 = 78).
        assertEquals(78, dedupedReport.getRiskScore());

        // 2. Now add an independent hma_hiding finding -> MUST stay independent and score!
        ThreatAppDetector hmaDetector = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv() {
            @Override
            public HmaCrossUserProbe.ProbeOutcome runCrossUserProbe(Collection<String> targetPackages) {
                return new HmaCrossUserProbe(new HmaCrossUserProbe.CrossUserAdapter() {
                    @Override public String getCallerPackageName() { return "com.host.app"; }
                    @Override public HmaCrossUserProbe.CallOutcome queryPackageInfoAnyUser(String pkg) {
                        return "com.host.app".equals(pkg)
                                ? HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION
                                : HmaCrossUserProbe.CallOutcome.NAME_NOT_FOUND;
                    }
                    @Override public HmaCrossUserProbe.CallOutcome queryApplicationInfoAnyUser(String pkg) {
                        return HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
                    }
                }).probe(Collections.singletonList("me.weishu.kernelsu"));
            }
        });

        DetectionResult hmaRes = hmaDetector.call();
        Set<String> hmaFamilies = EvidenceFamily.families(hmaRes.getDetails(), hmaRes.getEvidenceItems());
        assertEquals(Collections.singleton("hma_hiding"), hmaFamilies);

        RiskReport combinedReport = aggregator.aggregate(
                Collections.emptyList(),
                Arrays.asList(rootRes, hmaRes),
                CollectScene.STANDARD);
        assertTrue("Independent hma_hiding must not be deduped by root_fw",
                combinedReport.getRiskScore() > dedupedReport.getRiskScore());
    }

    @Test
    public void partialTruncationPropagatesWhileStockCleanStaysSafeWithZeroFp() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();

        // Stock clean device -> SAFE / SAFE
        ThreatAppDetector clean = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv());
        DetectionResult cleanRes = clean.call();
        assertEquals(RiskLevel.SAFE, cleanRes.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, cleanRes.getStatus());
        assertEquals(DetectionExecutionStatus.SAFE, cleanRes.getExecutionStatus());
        assertEquals(0, cleanRes.getScore());

        // Truncated PermissionService probe -> SAFE with PARTIAL execution status (0 FP)
        ThreatAppDetector partial = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv() {
            @Override
            public HmaPermissionServiceProbe.ProbeOutcome runPermissionServiceProbe() {
                Map<Integer, List<String>> perms = new HashMap<>();
                perms.put(10200, Collections.singletonList("android.permission.INTERNET"));
                Map<Integer, String[]> pkgs = new HashMap<>();
                pkgs.put(10200, new String[]{"com.host.app"});
                AtomicLong clock = new AtomicLong(0L);
                return new HmaPermissionServiceProbe(new HmaPermissionServiceProbe.Environment() {
                    @Override public int getSdkInt() { return 35; }
                    @Override public int getMyUid() { return 10200; }
                    @Override public String getMyPackageName() { return "com.host.app"; }
                    @Override public boolean hasFullPackageVisibility() { return true; }
                    @Override public boolean isCallerInternetGranted() { return true; }
                    @Override public boolean areProbePermissionsNonInstant() { return true; }
                    @Override public Boolean checkUidPermissionWire(int uid, String p) {
                        List<String> list = perms.get(uid);
                        return list != null && list.contains(p);
                    }
                    @Override public String[] getPackagesForUidWire(int uid) {
                        String[] arr = pkgs.get(uid);
                        return arr == null ? new String[0] : arr;
                    }
                    @Override public long elapsedRealtimeMs() { return clock.getAndAdd(600L); }
                }, 1000L).probe();
            }
        });
        DetectionResult partialRes = partial.call();
        assertEquals(RiskLevel.SAFE, partialRes.getRiskLevel());
        assertEquals(DetectionStatus.NORMAL, partialRes.getStatus());
        assertEquals(DetectionExecutionStatus.PARTIAL, partialRes.getExecutionStatus());
        assertEquals(0, partialRes.getScore());
    }

    @Test
    public void detectedWithTruncationPreservesPartialWhileUnavailableAndPolicyTogglesStayZeroFp() {
        RiskEngineConfig config = new RiskEngineConfig.Builder().build();

        // 1. DETECTED + truncated -> HIGH / DANGER / PARTIAL
        ThreatAppDetector detectedTruncated = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv() {
            @Override
            public HmaPermissionServiceProbe.ProbeOutcome runPermissionServiceProbe() {
                Map<Integer, List<String>> perms = new HashMap<>();
                perms.put(10200, Collections.singletonList("android.permission.INTERNET"));
                perms.put(10000, Collections.singletonList("android.permission.ACCESS_WIFI_STATE"));
                Map<Integer, String[]> pkgs = new HashMap<>();
                pkgs.put(10200, new String[]{"com.host.app"});
                AtomicLong clock = new AtomicLong(0L);
                return new HmaPermissionServiceProbe(new HmaPermissionServiceProbe.Environment() {
                    @Override public int getSdkInt() { return 35; }
                    @Override public int getMyUid() { return 10200; }
                    @Override public String getMyPackageName() { return "com.host.app"; }
                    @Override public boolean hasFullPackageVisibility() { return true; }
                    @Override public boolean isCallerInternetGranted() { return true; }
                    @Override public boolean areProbePermissionsNonInstant() { return true; }
                    @Override public Boolean checkUidPermissionWire(int uid, String p) {
                        List<String> list = perms.get(uid);
                        return list != null && list.contains(p);
                    }
                    @Override public String[] getPackagesForUidWire(int uid) {
                        String[] arr = pkgs.get(uid);
                        return arr == null ? new String[0] : arr;
                    }
                    @Override public long elapsedRealtimeMs() {
                        // First check (offset 0, uid 10000) succeeds; second check exceeds 1000ms budget
                        return clock.getAndAdd(600L);
                    }
                }, 1000L).probe();
            }
        });
        DetectionResult dtRes = detectedTruncated.call();
        assertEquals(RiskLevel.HIGH, dtRes.getRiskLevel());
        assertEquals(DetectionStatus.DANGER, dtRes.getStatus());
        assertEquals(7, dtRes.getScore());
        assertEquals(DetectionExecutionStatus.PARTIAL, dtRes.getExecutionStatus());
        assertTrue(dtRes.getFailureReasons().contains("hma_permission_service_truncated"));

        // 2. All behavioral probes UNAVAILABLE/UNSUPPORTED (incl. invalidated UNAVAILABLE+truncated) -> SAFE/SAFE
        java.util.concurrent.atomic.AtomicInteger postCtrlSelfLookups =
                new java.util.concurrent.atomic.AtomicInteger();
        ThreatAppDetector allUnavailable = ThreatAppDetector.createForTest(null, config, new CleanThreatEnv() {
            @Override
            public HmaUidVisibilityProbe.ProbeOutcome runUidVisibilityProbe() {
                return new HmaUidVisibilityProbe((HmaUidVisibilityProbe.Environment) null).probe();
            }
            @Override
            public HmaCrossUserProbe.ProbeOutcome runCrossUserProbe(Collection<String> targets) {
                return new HmaCrossUserProbe((HmaCrossUserProbe.CrossUserAdapter) null).probe(targets);
            }
            @Override
            public HmaOrderedBroadcastProbe.ProbeOutcome runOrderedBroadcastProbe(Collection<String> targets) {
                return new HmaOrderedBroadcastProbe((HmaOrderedBroadcastProbe.BroadcastTransport) null).probe(targets);
            }
            @Override
            public HmaPermissionServiceProbe.ProbeOutcome runPermissionServiceProbe() {
                AtomicLong clock = new AtomicLong(0L);
                return new HmaPermissionServiceProbe(new HmaPermissionServiceProbe.Environment() {
                    @Override public int getSdkInt() { return 35; }
                    @Override public int getMyUid() { return 10200; }
                    @Override public String getMyPackageName() { return "com.host.app"; }
                    @Override public boolean hasFullPackageVisibility() { return true; }
                    @Override public boolean isCallerInternetGranted() { return true; }
                    @Override public boolean areProbePermissionsNonInstant() { return true; }
                    @Override public Boolean checkUidPermissionWire(int uid, String p) {
                        return uid == 10200 && "android.permission.INTERNET".equals(p);
                    }
                    @Override public String[] getPackagesForUidWire(int uid) {
                        // Pre-control passes, post-control fails -> UNAVAILABLE with truncated=true
                        if (uid == 10200) {
                            return postCtrlSelfLookups.incrementAndGet() == 1
                                    ? new String[]{"com.host.app"}
                                    : new String[0];
                        }
                        return new String[0];
                    }
                    @Override public long elapsedRealtimeMs() { return clock.getAndAdd(1500L); }
                }, 1000L).probe();
            }
            @Override
            public ThanoxIpcProbe.ProbeOutcome runThanoxIpcProbe() {
                return new ThanoxIpcProbe((ThanoxIpcProbe.DropBoxTransactAdapter) null).probe();
            }
        });
        DetectionResult unavailRes = allUnavailable.call();
        assertEquals(RiskLevel.SAFE, unavailRes.getRiskLevel());
        assertEquals(DetectionExecutionStatus.SAFE, unavailRes.getExecutionStatus());
        assertEquals(0, unavailRes.getScore());

        // 3. ThreatAppPolicy disabling HMA probes MUST NOT invoke them
        java.util.concurrent.atomic.AtomicInteger hmaCalls =
                new java.util.concurrent.atomic.AtomicInteger();
        RiskEngineConfig hmaDisabledCfg = new RiskEngineConfig.Builder()
                .threatAppPolicy(new ThreatAppPolicy.Builder().enableHmaProbes(false).build())
                .build();
        ThreatAppDetector disabledHma = ThreatAppDetector.createForTest(null, hmaDisabledCfg, new CleanThreatEnv() {
            @Override public HmaUidVisibilityProbe.ProbeOutcome runUidVisibilityProbe() {
                hmaCalls.incrementAndGet(); return super.runUidVisibilityProbe();
            }
            @Override public HmaCrossUserProbe.ProbeOutcome runCrossUserProbe(Collection<String> t) {
                hmaCalls.incrementAndGet(); return super.runCrossUserProbe(t);
            }
            @Override public HmaOrderedBroadcastProbe.ProbeOutcome runOrderedBroadcastProbe(Collection<String> t) {
                hmaCalls.incrementAndGet(); return super.runOrderedBroadcastProbe(t);
            }
            @Override public HmaPermissionServiceProbe.ProbeOutcome runPermissionServiceProbe() {
                hmaCalls.incrementAndGet(); return super.runPermissionServiceProbe();
            }
            @Override public ThanoxIpcProbe.ProbeOutcome runThanoxIpcProbe() {
                hmaCalls.incrementAndGet(); return super.runThanoxIpcProbe();
            }
        });
        assertEquals(RiskLevel.SAFE, disabledHma.call().getRiskLevel());
        assertEquals(0, hmaCalls.get());
    }

    private static class CleanThreatEnv implements ThreatAppDetector.ThreatEnvironment {
        @Override
        public ThreatAppPackageProbe.ProbeOutcome runPackageProbe(ThreatAppPolicy policy) {
            return new ThreatAppPackageProbe(
                    (pkg, includePerms) -> null,
                    (dir, payloads) -> ThreatAppPackageProbe.PayloadScanResult.observed(Collections.emptySet()),
                    app -> null).probe(policy);
        }

        @Override
        public HmaUidVisibilityProbe.ProbeOutcome runUidVisibilityProbe() {
            return new HmaUidVisibilityProbe(new HmaUidVisibilityProbe.Environment() {
                @Override public int getMyUid() { return 10200; }
                @Override public String getMyPackageName() { return "com.host.app"; }
                @Override public boolean hasFullPackageVisibility() { return false; }
                @Override public SignalResult<String> scanActiveAppUids(int f, int l) {
                    return SignalResult.unavailable("skipped");
                }
                @Override public SignalResult<String> probeSeccompUidFilter(int f, int l) {
                    return SignalResult.success("status=OK\terrno=0\n"
                            + "kind=seccomp_uid\tinstall_status=installed\tinstall_error=0\t"
                            + "queried=10000\tnotified=10000\tfirst_suppressed=-1\t"
                            + "last_suppressed=-1\tquery_outcome=complete\tquery_error=0\tself_notified=1");
                }
                @Override public String[] getPackagesForUid(int uid) { return new String[0]; }
                @Override public long elapsedRealtimeMs() { return 0L; }
            }).probe();
        }

        @Override
        public HmaCrossUserProbe.ProbeOutcome runCrossUserProbe(Collection<String> targetPackages) {
            return new HmaCrossUserProbe(new HmaCrossUserProbe.CrossUserAdapter() {
                @Override public String getCallerPackageName() { return "com.host.app"; }
                @Override public HmaCrossUserProbe.CallOutcome queryPackageInfoAnyUser(String p) {
                    return HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
                }
                @Override public HmaCrossUserProbe.CallOutcome queryApplicationInfoAnyUser(String p) {
                    return HmaCrossUserProbe.CallOutcome.SECURITY_EXCEPTION;
                }
            }).probe(targetPackages);
        }

        @Override
        public HmaOrderedBroadcastProbe.ProbeOutcome runOrderedBroadcastProbe(
                Collection<String> targetPackages) {
            return new HmaOrderedBroadcastProbe(new HmaOrderedBroadcastProbe.BroadcastTransport() {
                @Override public String getCallerPackageName() { return "com.host.app"; }
                @Override public HmaOrderedBroadcastProbe.CallbackObservation sendAndAwait(String p) {
                    return HmaOrderedBroadcastProbe.CallbackObservation.cleanConsistent();
                }
                @Override public long elapsedRealtimeMs() { return 0L; }
            }).probe(targetPackages);
        }

        @Override
        public HmaPermissionServiceProbe.ProbeOutcome runPermissionServiceProbe() {
            return new HmaPermissionServiceProbe(new HmaPermissionServiceProbe.Environment() {
                @Override public int getSdkInt() { return 34; }
                @Override public int getMyUid() { return 10200; }
                @Override public String getMyPackageName() { return "com.host.app"; }
                @Override public boolean hasFullPackageVisibility() { return false; }
                @Override public boolean isCallerInternetGranted() { return true; }
                @Override public boolean areProbePermissionsNonInstant() { return true; }
                @Override public Boolean checkUidPermissionWire(int uid, String p) { return false; }
                @Override public String[] getPackagesForUidWire(int uid) { return new String[0]; }
                @Override public long elapsedRealtimeMs() { return 0L; }
            }).probe();
        }

        @Override
        public ThanoxIpcProbe.ProbeOutcome runThanoxIpcProbe() {
            return new ThanoxIpcProbe(() -> new ThanoxIpcProbe.TransactOutcome(
                    ThanoxIpcProbe.TransactOutcome.Kind.NOT_HANDLED, null, "not_handled")).probe();
        }
    }
}
