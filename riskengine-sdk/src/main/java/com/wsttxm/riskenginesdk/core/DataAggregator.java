package com.wsttxm.riskenginesdk.core;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.FingerprintHasher;
import com.wsttxm.riskenginesdk.FingerprintStability;
import com.wsttxm.riskenginesdk.FingerprintVersion;
import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.RiskPolicy;
import com.wsttxm.riskenginesdk.collector.java_layer.SecurityPostureCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class DataAggregator {

    public RiskReport aggregate(List<CollectorResult> collectorResults,
                                List<DetectionResult> detectionResults) {
        return aggregate(collectorResults, detectionResults, defaultRiskPolicy);
    }

    private final FingerprintStore fingerprintStore;
    private final String ephemeralSalt;
    private final FingerprintVersion fingerprintVersion;
    private final FingerprintStability fingerprintStability;
    private final FingerprintHasher fingerprintHasher;
    private final RiskPolicy defaultRiskPolicy;

    public DataAggregator() {
        this(null, null);
    }

    /**
     * @param fingerprintStore local salt and continuity store. When null the
     *                         fingerprint ID is still computed using an
     *                         ephemeral per-instance salt without continuity.
     */
    public DataAggregator(FingerprintStore fingerprintStore) {
        this(fingerprintStore, null);
    }

    public DataAggregator(FingerprintStore fingerprintStore, RiskEngineConfig config) {
        this.fingerprintStore = fingerprintStore;
        this.ephemeralSalt = fingerprintStore == null
                ? FingerprintStore.generateRandomHex(16)
                : null;
        this.fingerprintVersion = config == null
                ? FingerprintVersion.V2
                : config.getFingerprintVersion();
        this.fingerprintStability = config == null
                ? FingerprintStability.OPTIMAL
                : config.getFingerprintStability();
        this.fingerprintHasher = config == null
                ? FingerprintHasher.SHA256
                : config.getFingerprintHasher();
        this.defaultRiskPolicy = config == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : config.getRiskPolicy();
    }

    public RiskReport aggregate(List<CollectorResult> collectorResults,
                                List<DetectionResult> detectionResults,
                                CollectScene scene) {
        CollectScene effectiveScene = scene == null ? CollectScene.STANDARD : scene;
        return aggregate(collectorResults, detectionResults, RiskPolicy.forScene(effectiveScene));
    }

    public RiskReport aggregate(List<CollectorResult> collectorResults,
                                List<DetectionResult> detectionResults,
                                RiskPolicy policy) {
        Objects.requireNonNull(collectorResults, "collectorResults must not be null");
        Objects.requireNonNull(detectionResults, "detectionResults must not be null");
        RiskPolicy effectivePolicy = policy == null
                ? RiskPolicy.forScene(CollectScene.STANDARD)
                : policy;
        CollectScene scene = effectivePolicy.getBaseScene();
        DeviceFingerprint fingerprint = new DeviceFingerprint();

        for (CollectorResult cr : collectorResults) {
            fingerprint.addResult(cr);
        }

        List<DetectionResult> allDetections = CorrelationEngine.dedupeFamilies(
                CorrelationEngine.applyPolicy(detectionResults, effectivePolicy));
        List<DetectionResult> correlationInput = CorrelationEngine.filterForCorrelation(
                allDetections, effectivePolicy);
        DetectionResult correlated = CorrelationEngine.correlate(correlationInput, scene);
        if (correlated != null) {
            correlated = CorrelationEngine.applyPolicy(correlated, effectivePolicy);
            if (!correlated.getDetails().isEmpty()) {
                allDetections.add(correlated);
            }
        }
        addCollectionCoverageSignal(collectorResults, allDetections);
        RiskPolicy.FamilyMode hwSpoofMode = effectivePolicy.getFamilyMode("hw_spoof");
        if (fingerprint.hasInconsistency() && hwSpoofMode != RiskPolicy.FamilyMode.ALLOWLIST) {
            List<String> inconsistent = fingerprint.getInconsistentFields();
            List<String> details = List.of("inconsistent_fields:" + String.join(",", inconsistent));
            String evidence = details.get(0);
            allDetections.add(new DetectionResult(
                    "multi_source_validation",
                    RiskLevel.MEDIUM,
                    DetectionStatus.WARNING,
                    4,
                    10,
                    hwSpoofMode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY,
                    details,
                    evidence
            ));
            CLog.w("Multi-source validation detected inconsistency: " + evidence);
        }

        StoreTelemetry storeTelemetry = new StoreTelemetry();
        FingerprintId fingerprintId = buildFingerprintId(
                fingerprint, allDetections, storeTelemetry,
                effectivePolicy.getFamilyMode("device_binding"));
        allDetections = mergeMultiSourceEvidence(allDetections);
        addSyntheticFingerprintSignals(fingerprint, allDetections);
        DevicePosture devicePosture = mergePostureSignals(
                SecurityPostureCollector.fromFingerprint(fingerprint), allDetections, storeTelemetry);
        return new RiskReport(fingerprint, allDetections, effectivePolicy, fingerprintId,
                devicePosture, storeTelemetry.anchorDriftCount);
    }

    /**
     * Merges {@link EvidenceItem} entries sharing the same {@code (code, location)} into
     * a single entry carrying the union of {@code mergedSources} and the highest {@link EvidenceItem.Rank}.
     */
    public static List<EvidenceItem> mergeEvidenceItems(List<EvidenceItem> items) {
        if (items == null || items.isEmpty()) {
            return Collections.emptyList();
        }
        Map<String, EvidenceItem> merged = new LinkedHashMap<>();
        for (EvidenceItem item : items) {
            if (item == null) continue;
            String key = evidenceMergeKey(item);
            EvidenceItem existing = merged.get(key);
            merged.put(key, existing == null ? item : existing.mergeWith(item));
        }
        return new ArrayList<>(merged.values());
    }

    private static List<DetectionResult> mergeMultiSourceEvidence(List<DetectionResult> detections) {
        if (detections == null || detections.isEmpty()) {
            return detections;
        }
        Map<String, EvidenceItem> globalByKey = new LinkedHashMap<>();
        boolean anyItems = false;
        for (DetectionResult detection : detections) {
            for (EvidenceItem item : detection.getEvidenceItems()) {
                anyItems = true;
                String key = evidenceMergeKey(item);
                EvidenceItem existing = globalByKey.get(key);
                globalByKey.put(key, existing == null ? item : existing.mergeWith(item));
            }
        }
        if (!anyItems) {
            return detections;
        }

        List<DetectionResult> updated = new ArrayList<>(detections.size());
        for (DetectionResult detection : detections) {
            List<EvidenceItem> original = detection.getEvidenceItems();
            if (original.isEmpty()) {
                updated.add(detection);
                continue;
            }
            Map<String, EvidenceItem> localMerged = new LinkedHashMap<>();
            for (EvidenceItem item : original) {
                String key = evidenceMergeKey(item);
                localMerged.putIfAbsent(key, globalByKey.get(key));
            }
            List<EvidenceItem> resolved = new ArrayList<>(localMerged.values());
            updated.add(resolved.equals(original) ? detection : detection.withEvidenceItems(resolved));
        }
        return updated;
    }

    private static String evidenceMergeKey(EvidenceItem item) {
        return item.getCode() + "\0" + item.getLocation();
    }

    /**
     * Composes the layered fingerprint ID and records continuity.
     *
     * Runs before synthetic runtime_integrity_score_inputs so any
     * fingerprint_continuity finding is reflected in the score summary.
     */
    private FingerprintId buildFingerprintId(DeviceFingerprint fingerprint,
                                             List<DetectionResult> detections,
                                             StoreTelemetry storeTelemetry,
                                             RiskPolicy.FamilyMode deviceBindingMode) {
        try {
            String salt = fingerprintStore == null
                    ? ephemeralSalt : fingerprintStore.getOrCreateSalt();
            FingerprintId id = FingerprintIdBuilder.build(
                    fingerprint, salt, fingerprintVersion, fingerprintStability, fingerprintHasher);

            CollectorResult idResult = new CollectorResult("fingerprint_id");
            idResult.addValue("version", id.getVersion().name());
            idResult.addValue("stability", id.getStability().name());
            if (!id.getCompositeId().isEmpty()) {
                idResult.addValue("composite", id.getCompositeId());
            }
            if (!id.getHardwareId().isEmpty()) {
                idResult.addValue("hardware", id.getHardwareId());
            }
            if (!id.getSystemId().isEmpty()) {
                idResult.addValue("system", id.getSystemId());
            }
            if (!id.getVolatileId().isEmpty()) {
                idResult.addValue("volatile", id.getVolatileId());
            }
            idResult.addValue("hardware_coverage",
                    id.getHardwareFieldsPresent() + "/" + id.getHardwareFieldsTotal());
            idResult.addValue("system_coverage",
                    id.getSystemFieldsPresent() + "/" + id.getSystemFieldsTotal());
            idResult.addValue("hardware_layer_reliable",
                    String.valueOf(id.isHardwareLayerReliable()));

            if (fingerprintStore != null) {
                FingerprintStore.Continuity continuity =
                        fingerprintStore.recordAndCompare(id);
                storeTelemetry.anchorDriftCount = continuity.getDriftCount();
                storeTelemetry.lockscreenOrBiometricReset =
                        continuity.isLockscreenOrBiometricReset();
                storeTelemetry.keystoreSecurityLevel = continuity.getKeystoreSecurityLevel();

                idResult.addValue("continuity", continuity.getState().name());
                idResult.addValue("observation_count",
                        String.valueOf(continuity.getObservationCount()));
                idResult.addValue("anchor_drift_count",
                        String.valueOf(continuity.getDriftCount()));
                idResult.addValue("device_binding_broken",
                        String.valueOf(continuity.isDeviceBindingBroken()));
                if (!continuity.getDeviceBindingReason().isEmpty()) {
                    idResult.addValue("device_binding_reason",
                            continuity.getDeviceBindingReason());
                }
                if (continuity.getKeystoreSecurityLevel()
                        != DevicePosture.KeystoreSecurityLevel.UNKNOWN) {
                    idResult.addValue("keystore_security_level",
                            continuity.getKeystoreSecurityLevel().name());
                }
                if (continuity.isLockscreenOrBiometricReset()) {
                    idResult.addValue("lockscreen_or_biometric_reset", "true");
                }
                if (!continuity.getChangedBuckets().isEmpty()) {
                    idResult.addValue("changed_buckets",
                            String.join(",", continuity.getChangedBuckets()));
                }

                if (continuity.isDeviceBindingBroken()
                        && deviceBindingMode != RiskPolicy.FamilyMode.ALLOWLIST) {
                    List<String> details = new ArrayList<>();
                    details.add("device_binding_broken");
                    String reason = continuity.getDeviceBindingReason();
                    if (!reason.isEmpty()) {
                        details.add("device_binding_reason:" + reason);
                    }
                    List<EvidenceItem> evidenceItems = Collections.singletonList(
                            new EvidenceItem(
                                    "device_binding_broken",
                                    EvidenceItem.SourceLayer.HARDWARE,
                                    "AndroidKeyStore",
                                    reason,
                                    "device_binding",
                                    EvidenceItem.Rank.STRONG));
                    detections.add(new DetectionResult(
                            "fingerprint_continuity",
                            RiskLevel.HIGH,
                            DetectionStatus.DANGER,
                            8, 10,
                            deviceBindingMode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY,
                            DetectionExecutionStatus.RISK,
                            1, 1, 0,
                            Collections.emptyList(),
                            details,
                            evidenceItems,
                            String.join("; ", details)));
                    CLog.w("Fingerprint device binding broken: " + reason);
                } else if (continuity.getState() == FingerprintStore.State.HARDWARE_CHANGED
                        && deviceBindingMode != RiskPolicy.FamilyMode.ALLOWLIST) {
                    List<String> details = new ArrayList<>();
                    details.add("hardware_layer_changed_between_observations");
                    String changed = String.join(",", continuity.getChangedBuckets());
                    if (!changed.isEmpty()) {
                        details.add("changed_buckets:" + changed);
                    }
                    List<EvidenceItem> evidenceItems = Collections.singletonList(
                            new EvidenceItem(
                                    "hardware_layer_changed",
                                    EvidenceItem.SourceLayer.JAVA,
                                    "FingerprintStore",
                                    changed,
                                    "device_binding",
                                    EvidenceItem.Rank.MEDIUM));
                    detections.add(new DetectionResult(
                            "fingerprint_continuity",
                            RiskLevel.MEDIUM,
                            DetectionStatus.WARNING,
                            4, 10,
                            deviceBindingMode == RiskPolicy.FamilyMode.INFORMATIONAL_ONLY,
                            DetectionExecutionStatus.RISK,
                            1, 1, 0,
                            Collections.emptyList(),
                            details,
                            evidenceItems,
                            String.join("; ", details)));
                    CLog.w("Fingerprint hardware layer changed between observations: " + changed);
                }
            }
            fingerprint.addResult(idResult);
            return id;
        } catch (Exception e) {
            CLog.e("Fingerprint ID composition failed", e);
            return null;
        }
    }

    private static DevicePosture mergePostureSignals(DevicePosture basePosture,
                                                     List<DetectionResult> detections,
                                                     StoreTelemetry telemetry) {
        DevicePosture base = basePosture == null ? DevicePosture.empty() : basePosture;
        Boolean systemVpn = base.getSystemVpn();
        Boolean unofficialStore = base.getUnofficialStore();

        if (detections != null) {
            for (DetectionResult d : detections) {
                if (d == null) continue;
                DetectionExecutionStatus exec = d.getExecutionStatus();
                boolean usable = exec != DetectionExecutionStatus.UNAVAILABLE
                        && exec != DetectionExecutionStatus.ERROR
                        && exec != DetectionExecutionStatus.TIMEOUT;
                if (!usable) continue;

                if ("network_risk".equals(d.getDetectorName())) {
                    boolean vpnHit = hasTokenOrCode(d, "vpn_active:", "vpn_active");
                    if (vpnHit) {
                        systemVpn = Boolean.TRUE;
                    } else if (d.getChecksSucceeded() >= 4 && !hasFailurePrefix(d, "vpn_check_")) {
                        systemVpn = Boolean.FALSE;
                    }
                } else if ("app_integrity".equals(d.getDetectorName())) {
                    boolean storeHit = hasTokenOrCode(d, "unofficial_installer:", "unofficial_installer");
                    unofficialStore = storeHit ? Boolean.TRUE : Boolean.FALSE;
                } else if ("tee_integrity".equals(d.getDetectorName())
                        && d.getRiskLevel() == RiskLevel.SAFE) {
                    String ev = d.getEvidence();
                    if (ev != null && ev.startsWith("hardware_attested_locked_verified:")) {
                        String tier = ev.substring("hardware_attested_locked_verified:".length());
                        if ("STRONGBOX".equals(tier)) {
                            if (telemetry != null) {
                                telemetry.keystoreSecurityLevel =
                                        DevicePosture.KeystoreSecurityLevel.STRONGBOX;
                            }
                        } else if ("TRUSTED_ENVIRONMENT".equals(tier)
                                && telemetry != null
                                && telemetry.keystoreSecurityLevel
                                        != DevicePosture.KeystoreSecurityLevel.STRONGBOX) {
                            telemetry.keystoreSecurityLevel =
                                    DevicePosture.KeystoreSecurityLevel.TEE;
                        }
                    }
                }
            }
        }

        boolean updateReset = telemetry != null
                && telemetry.lockscreenOrBiometricReset
                && !base.isLockscreenOrBiometricReset();
        boolean hasMeasuredKeyInfoLevel = telemetry != null
                && telemetry.keystoreSecurityLevel != null
                && telemetry.keystoreSecurityLevel != DevicePosture.KeystoreSecurityLevel.UNKNOWN
                && telemetry.keystoreSecurityLevel != DevicePosture.KeystoreSecurityLevel.UNAVAILABLE;
        boolean updateKsLevel = hasMeasuredKeyInfoLevel
                && telemetry.keystoreSecurityLevel != base.getKeystoreSecurityLevel();
        boolean updateVpn = !java.util.Objects.equals(systemVpn, base.getSystemVpn());
        boolean updateStore = !java.util.Objects.equals(unofficialStore, base.getUnofficialStore());

        if (!updateReset && !updateKsLevel && !updateVpn && !updateStore) {
            return base;
        }
        return new DevicePosture.Builder()
                .setDeviceSecure(base.getDeviceSecure())
                .setStorageEncryptionStatus(base.getStorageEncryptionStatus())
                .setKeystoreSecurityLevel(updateKsLevel
                        ? telemetry.keystoreSecurityLevel
                        : base.getKeystoreSecurityLevel())
                .setBiometricStatus(base.getBiometricStatus())
                .setDeveloperOptionsEnabled(base.getDeveloperOptionsEnabled())
                .setAdbEnabled(base.getAdbEnabled())
                .setSystemVpn(systemVpn)
                .setUnofficialStore(unofficialStore)
                .setLockscreenOrBiometricReset(
                        base.isLockscreenOrBiometricReset()
                                || (telemetry != null && telemetry.lockscreenOrBiometricReset))
                .setEvaluatedAtMs(base.getEvaluatedAtMs())
                .build();
    }

    private static boolean hasFailurePrefix(DetectionResult detection, String prefix) {
        for (String reason : detection.getFailureReasons()) {
            if (reason != null && reason.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasTokenOrCode(DetectionResult detection, String prefix, String code) {
        for (String detail : detection.getDetails()) {
            if (detail != null && (detail.equals(code) || detail.startsWith(prefix))) {
                return true;
            }
        }
        for (EvidenceItem item : detection.getEvidenceItems()) {
            if (item != null && code.equals(item.getCode())) {
                return true;
            }
        }
        return false;
    }

    private static final class StoreTelemetry {
        int anchorDriftCount;
        boolean lockscreenOrBiometricReset;
        DevicePosture.KeystoreSecurityLevel keystoreSecurityLevel =
                DevicePosture.KeystoreSecurityLevel.UNKNOWN;
    }

    private void addCollectionCoverageSignal(List<CollectorResult> collectorResults,
                                             List<DetectionResult> detections) {
        for (CollectorResult result : collectorResults) {
            if (result.getStatus() == CollectorResult.Status.ERROR) {
                String reason = result.getStatus() + (result.getError() == null
                        ? "" : ":" + result.getError());
                if ("timeout".equalsIgnoreCase(result.getError())) {
                    detections.add(DetectionResult.timeout(
                            "collector:" + result.getFieldName(), reason));
                } else {
                    detections.add(DetectionResult.error(
                            "collector:" + result.getFieldName(), reason));
                }
            }
        }
    }

    private void addSyntheticFingerprintSignals(DeviceFingerprint fingerprint,
                                                List<DetectionResult> detections) {
        CollectorResult hookSignals = buildHookMemorySignals(detections);
        if (hookSignals != null) {
            fingerprint.addResult(hookSignals);
        }

        CollectorResult runtimeInputs = buildRuntimeIntegrityInputs(detections);
        if (runtimeInputs != null) {
            fingerprint.addResult(runtimeInputs);
        }
    }

    private CollectorResult buildHookMemorySignals(List<DetectionResult> detections) {
        for (DetectionResult detection : detections) {
            if (!"hook_framework".equals(detection.getDetectorName())) {
                continue;
            }
            List<String> details = detection.getDetails().stream()
                    .filter(detail -> detail.startsWith("anon_exec:")
                            || detail.startsWith("maps:")
                            || detail.startsWith("frida_pid_port:"))
                    .collect(Collectors.toList());
            if (details.isEmpty()) {
                return null;
            }

            CollectorResult result = new CollectorResult("hook_memory_signals");
            result.addValue("summary", "present");
            result.addValue("signals", String.join(",", details));
            result.addValue("count", String.valueOf(details.size()));
            return result;
        }
        return null;
    }

    private CollectorResult buildRuntimeIntegrityInputs(List<DetectionResult> detections) {
        if (detections.isEmpty()) {
            return null;
        }

        CollectorResult result = new CollectorResult("runtime_integrity_score_inputs");
        int dangerCount = 0;
        int warningCount = 0;
        long score = 0;
        List<String> statusMap = new ArrayList<>();
        for (DetectionResult detection : detections) {
            if (detection.getStatus() == DetectionStatus.DANGER) {
                dangerCount++;
            } else if (detection.getStatus() == DetectionStatus.WARNING) {
                warningCount++;
            }
            if (!detection.isInformational()) {
                score += detection.getScore();
            }
            statusMap.add(detection.getDetectorName() + ":" + detection.getStatus());
        }

        result.addValue("summary", "score=" + score + ",danger=" + dangerCount + ",warning=" + warningCount);
        result.addValue("detectors", String.join(",", statusMap));
        return result;
    }
}
