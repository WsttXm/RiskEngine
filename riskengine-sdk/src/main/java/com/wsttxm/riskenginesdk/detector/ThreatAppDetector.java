package com.wsttxm.riskenginesdk.detector;

import android.content.Context;

import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.ScanTier;
import com.wsttxm.riskenginesdk.ThreatAppPolicy;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaCrossUserProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaOrderedBroadcastProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaPermissionServiceProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.HmaUidVisibilityProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThanoxIpcProbe;
import com.wsttxm.riskenginesdk.detector.probe.threat.ThreatAppPackageProbe;
import com.wsttxm.riskenginesdk.generated.DetectionLists;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskLevel;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 16th converged top-level detector: Threat Apps, Signing-Immune Root Managers &amp; HMA
 * Behavioral Side-Channels ({@code threat_apps}, strictly {@link ScanTier#POSTPONED}).
 *
 * <p>Orchestrates:
 * <ol>
 *   <li>{@link ThreatAppPackageProbe}: official release cert SHA-256 lineage (v2/v3/v3.1),
 *       {@code nativeLibraryDir} payloads, {@code android:zygotePreloadName}, and custom
 *       {@link ThreatAppPolicy} rules. Root manager matches map to {@code root_fw} (deduping
 *       automatically with {@code root} and {@code mount_analysis} in {@link DataAggregator}).</li>
 *   <li>{@link HmaUidVisibilityProbe}: disposable-child {@code getpriority(PRIO_USER)} +
 *       Linux >= 5.0 {@code SECCOMP_FILTER_FLAG_NEW_LISTENER} user-notif side-channel.</li>
 *   <li>{@link HmaCrossUserProbe}: cross-user {@code MATCH_ANY_USER} exception suppression.</li>
 *   <li>{@link HmaOrderedBroadcastProbe}: HMA-OSS #164 missing {@code resultTo} &amp; #173
 *       {@code isOrderedBroadcast() == true} asymmetry with interleaved self-controls.</li>
 *   <li>{@link HmaPermissionServiceProbe}: API 35–37 {@code PermissionService} vs
 *       {@code getPackagesForUid} diff under strict 1s wall-clock budget.</li>
 *   <li>{@link ThanoxIpcProbe}: exact {@code github.tornaco.android.thanos.core.IThanos}
 *       {@code dropbox} Binder verification (zero OriginOS FP).</li>
 * </ol></p>
 *
 * <p>Scoring contract:
 * <ul>
 *   <li>HMA / Thanox behavioral side-channel hit &rarr; {@code HIGH/7} ({@code DANGER},
 *       actionable in all 4 {@code CollectScene}s, {@code hma_hiding} family).</li>
 *   <li>Signed threat tool / root manager / custom policy hit &rarr; {@code MEDIUM/5}
 *       ({@code WARNING}, actionable in all 4 {@code CollectScene}s).</li>
 *   <li>Visibility loss, permission limits, or {@code UNSUPPORTED} kernels NEVER produce
 *       false positives or degrade a clean device from {@code SAFE} to {@code UNKNOWN}.</li>
 * </ul></p>
 */
public class ThreatAppDetector extends BaseDetector {

    public static final String DETECTOR_NAME = "threat_apps";
    public static final String FAMILY_ROOT_FW = ThreatAppPackageProbe.FAMILY_ROOT_FW;
    public static final String FAMILY_HMA_HIDING = ThreatAppPackageProbe.FAMILY_HMA_HIDING;
    public static final String FAMILY_THREAT_APP = ThreatAppPackageProbe.FAMILY_THREAT_APP;

    private static final long DETECTOR_TIMEOUT_MS = 5_000L;
    private static final long PKG_PROBE_TIMEOUT_MS = 1_200L;
    private static final long UID_VIS_PROBE_TIMEOUT_MS = 2_800L;
    private static final long CROSS_USER_PROBE_TIMEOUT_MS = 1_000L;
    private static final long BROADCAST_PROBE_TIMEOUT_MS = 2_400L;
    private static final long PERM_SVC_PROBE_TIMEOUT_MS = 1_300L;
    private static final long THANOX_PROBE_TIMEOUT_MS = 600L;

    /** Injectable seam for deterministic pure-JVM unit tests. */
    public interface ThreatEnvironment {
        ThreatAppPackageProbe.ProbeOutcome runPackageProbe(ThreatAppPolicy policy);

        HmaUidVisibilityProbe.ProbeOutcome runUidVisibilityProbe();

        HmaCrossUserProbe.ProbeOutcome runCrossUserProbe(Collection<String> targetPackages);

        HmaOrderedBroadcastProbe.ProbeOutcome runOrderedBroadcastProbe(
                Collection<String> targetPackages);

        HmaPermissionServiceProbe.ProbeOutcome runPermissionServiceProbe();

        ThanoxIpcProbe.ProbeOutcome runThanoxIpcProbe();
    }

    private final RiskEngineConfig config;
    private final ThreatEnvironment env;

    public ThreatAppDetector(Context context, RiskEngineConfig config) {
        this(context, config, null);
    }

    public static ThreatAppDetector createForTest(Context context,
                                                  RiskEngineConfig config,
                                                  ThreatEnvironment env) {
        return new ThreatAppDetector(context, config, env);
    }

    private ThreatAppDetector(Context context, RiskEngineConfig config, ThreatEnvironment env) {
        super(context);
        this.config = config != null ? config : new RiskEngineConfig.Builder().build();
        this.env = env != null ? env : new DefaultThreatEnvironment(this.context);
    }

    @Override
    public String getName() {
        return DETECTOR_NAME;
    }

    @Override
    public ScanTier getScanTier() {
        return ScanTier.POSTPONED;
    }

    @Override
    public long getTimeoutMs() {
        return DETECTOR_TIMEOUT_MS;
    }

    @Override
    protected DetectionResult detect() {
        ThreatAppPolicy policy = config.getEffectiveThreatAppPolicy();
        Set<String> targetPackages = buildBehavioralTargetPackages(policy);

        List<EvidenceItem> evidenceItems = new ArrayList<>();
        Set<String> details = new LinkedHashSet<>();
        CheckCoverage coverage = new CheckCoverage();

        boolean anyProbeRan = false;
        boolean hmaBehavioralDetected = false;
        boolean toolOrPolicyDetected = false;

        // 1. Targeted package / cert lineage / nativeLibraryDir / zygotePreloadName / policy probe
        ThreatAppPackageProbe.ProbeOutcome pkgOutcome = SafeExecutor.safeWithTimeoutOrInline(
                PKG_PROBE_TIMEOUT_MS,
                () -> env.runPackageProbe(policy)).getOrNull();
        if (pkgOutcome != null) {
            anyProbeRan = true;
            coverage.success();
            if (pkgOutcome.hasFindings()) {
                toolOrPolicyDetected = true;
                evidenceItems.addAll(pkgOutcome.getEvidenceItems());
                details.addAll(pkgOutcome.getDetails());
            }
        }

        // 2. Native HMA UID visibility + Linux >= 5.0 seccomp-notif side-channel
        if (policy.isEnableHmaUidVisibilityProbe()) {
            HmaUidVisibilityProbe.ProbeOutcome uidOut = SafeExecutor.safeWithTimeoutOrInline(
                    UID_VIS_PROBE_TIMEOUT_MS,
                    env::runUidVisibilityProbe).getOrNull();
            if (uidOut != null) {
                if (uidOut.isDetected()) {
                    anyProbeRan = true;
                    coverage.success();
                    if (uidOut.isTruncated()) {
                        coverage.failure("hma_uid_visibility_truncated");
                    }
                    hmaBehavioralDetected = true;
                    evidenceItems.addAll(uidOut.getEvidenceItems());
                    details.addAll(uidOut.getDetails());
                } else if (uidOut.getState() == HmaUidVisibilityProbe.ProbeState.CLEAN) {
                    anyProbeRan = true;
                    coverage.success();
                } else if (uidOut.getState() == HmaUidVisibilityProbe.ProbeState.PARTIAL) {
                    anyProbeRan = true;
                    coverage.success();
                    coverage.failure("hma_uid_visibility_truncated");
                }
            }
        }

        // 3. Cross-user MATCH_ANY_USER exception suppression
        if (policy.isEnableHmaCrossUserProbe()) {
            HmaCrossUserProbe.ProbeOutcome crossOut = SafeExecutor.safeWithTimeoutOrInline(
                    CROSS_USER_PROBE_TIMEOUT_MS,
                    () -> env.runCrossUserProbe(targetPackages)).getOrNull();
            if (crossOut != null) {
                if (crossOut.isDetected()) {
                    anyProbeRan = true;
                    coverage.success();
                    hmaBehavioralDetected = true;
                    evidenceItems.addAll(crossOut.getEvidenceItems());
                    details.addAll(crossOut.getDetails());
                } else if (crossOut.getState() == HmaCrossUserProbe.ProbeState.CLEAN) {
                    anyProbeRan = true;
                    coverage.success();
                }
            }
        }

        // 4. Ordered Broadcast resultTo asymmetry (HMA-OSS #164 & #173)
        if (policy.isEnableHmaOrderedBroadcastProbe()) {
            HmaOrderedBroadcastProbe.ProbeOutcome bcastOut = SafeExecutor.safeWithTimeoutOrInline(
                    BROADCAST_PROBE_TIMEOUT_MS,
                    () -> env.runOrderedBroadcastProbe(targetPackages)).getOrNull();
            if (bcastOut != null) {
                if (bcastOut.isDetected()) {
                    anyProbeRan = true;
                    coverage.success();
                    if (bcastOut.isTruncated()) {
                        coverage.failure("hma_ordered_broadcast_truncated");
                    }
                    hmaBehavioralDetected = true;
                    evidenceItems.addAll(bcastOut.getEvidenceItems());
                    details.addAll(bcastOut.getDetails());
                } else if (bcastOut.getState() == HmaOrderedBroadcastProbe.ProbeState.CLEAN) {
                    anyProbeRan = true;
                    coverage.success();
                } else if (bcastOut.getState() == HmaOrderedBroadcastProbe.ProbeState.PARTIAL) {
                    anyProbeRan = true;
                    coverage.success();
                    coverage.failure("hma_ordered_broadcast_truncated");
                }
            }
        }

        // 5. Android 15-17 PermissionService.checkUidPermission vs getPackagesForUid diff
        if (policy.isEnableHmaPermissionServiceProbe()) {
            HmaPermissionServiceProbe.ProbeOutcome permOut = SafeExecutor.safeWithTimeoutOrInline(
                    PERM_SVC_PROBE_TIMEOUT_MS,
                    env::runPermissionServiceProbe).getOrNull();
            if (permOut != null) {
                if (permOut.isDetected()) {
                    anyProbeRan = true;
                    coverage.success();
                    if (permOut.isTruncated()) {
                        coverage.failure("hma_permission_service_truncated");
                    }
                    hmaBehavioralDetected = true;
                    evidenceItems.addAll(permOut.getEvidenceItems());
                    details.addAll(permOut.getDetails());
                } else if (permOut.getState() == HmaPermissionServiceProbe.ProbeState.CLEAN) {
                    anyProbeRan = true;
                    coverage.success();
                } else if (permOut.getState() == HmaPermissionServiceProbe.ProbeState.PARTIAL) {
                    anyProbeRan = true;
                    coverage.success();
                    coverage.failure("hma_permission_service_truncated");
                }
            }
        }

        // 6. Thanox exact dropbox IPC descriptor verification
        if (policy.isEnableThanoxIpcProbe()) {
            ThanoxIpcProbe.ProbeOutcome thanoxOut = SafeExecutor.safeWithTimeoutOrInline(
                    THANOX_PROBE_TIMEOUT_MS,
                    env::runThanoxIpcProbe).getOrNull();
            if (thanoxOut != null) {
                if (thanoxOut.isDetected()) {
                    anyProbeRan = true;
                    coverage.success();
                    hmaBehavioralDetected = true;
                    evidenceItems.addAll(thanoxOut.getEvidenceItems());
                    details.addAll(thanoxOut.getDetails());
                } else if (thanoxOut.getState() == ThanoxIpcProbe.ProbeState.CLEAN) {
                    anyProbeRan = true;
                    coverage.success();
                }
            }
        }

        // Visibility loss / unsupported platform must NEVER degrade a clean device to UNKNOWN.
        if (!anyProbeRan) {
            coverage.success();
        }

        List<EvidenceItem> mergedEvidence = DataAggregator.mergeEvidenceItems(evidenceItems);
        List<String> detailList = new ArrayList<>(details);

        if (hmaBehavioralDetected) {
            String summary = String.join("; ", detailList);
            return result(
                    RiskLevel.HIGH,
                    DetectionStatus.DANGER,
                    7,
                    10,
                    false,
                    detailList,
                    summary,
                    coverage).withEvidenceItems(mergedEvidence);
        }

        if (toolOrPolicyDetected) {
            String summary = String.join("; ", detailList);
            return result(
                    RiskLevel.MEDIUM,
                    DetectionStatus.WARNING,
                    5,
                    10,
                    false,
                    detailList,
                    summary,
                    coverage).withEvidenceItems(mergedEvidence);
        }

        return result(
                RiskLevel.SAFE,
                DetectionStatus.NORMAL,
                0,
                10,
                false,
                detailList,
                "no risk detected",
                coverage).withEvidenceItems(mergedEvidence);
    }

    private static Set<String> buildBehavioralTargetPackages(ThreatAppPolicy policy) {
        Set<String> targets = new LinkedHashSet<>();
        if (policy.isEnableBuiltInCatalog()) {
            Collections.addAll(targets, DetectionLists.THREAT_APP_PACKAGES);
        }
        targets.addAll(policy.getAdditionalPackages());
        return targets;
    }

    private static final class DefaultThreatEnvironment implements ThreatEnvironment {
        private final Context context;

        DefaultThreatEnvironment(Context context) {
            this.context = context;
        }

        @Override
        public ThreatAppPackageProbe.ProbeOutcome runPackageProbe(ThreatAppPolicy policy) {
            return new ThreatAppPackageProbe(context).probe(policy);
        }

        @Override
        public HmaUidVisibilityProbe.ProbeOutcome runUidVisibilityProbe() {
            return new HmaUidVisibilityProbe(context).probe();
        }

        @Override
        public HmaCrossUserProbe.ProbeOutcome runCrossUserProbe(Collection<String> targetPackages) {
            return new HmaCrossUserProbe(context).probe(targetPackages);
        }

        @Override
        public HmaOrderedBroadcastProbe.ProbeOutcome runOrderedBroadcastProbe(
                Collection<String> targetPackages) {
            return new HmaOrderedBroadcastProbe(context).probe(targetPackages);
        }

        @Override
        public HmaPermissionServiceProbe.ProbeOutcome runPermissionServiceProbe() {
            return new HmaPermissionServiceProbe(context).probe();
        }

        @Override
        public ThanoxIpcProbe.ProbeOutcome runThanoxIpcProbe() {
            return new ThanoxIpcProbe().probe();
        }
    }
}
