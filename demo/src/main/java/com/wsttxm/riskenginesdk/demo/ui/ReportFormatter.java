package com.wsttxm.riskenginesdk.demo.ui;

import android.content.Context;

import androidx.annotation.ColorRes;

import com.wsttxm.riskenginesdk.demo.R;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Presentation formatter and localizer for RiskReport models.
 */
public final class ReportFormatter {

    public static final class EvidenceDetail {
        public final String title;
        public final String sourceTag;
        public final String location;
        public final String content;
        public final String risk;
        public final String inlineSummary;
        public final boolean diagnosticOnly;
        final String mergeKey;

        EvidenceDetail(String title,
                       String sourceTag,
                       String location,
                       String content,
                       String risk,
                       String inlineSummary,
                       boolean diagnosticOnly,
                       String mergeKey) {
            this.title = title;
            this.sourceTag = sourceTag;
            this.location = location;
            this.content = content;
            this.risk = risk;
            this.inlineSummary = inlineSummary;
            this.diagnosticOnly = diagnosticOnly;
            this.mergeKey = mergeKey;
        }

        EvidenceDetail withSourceTag(String mergedTag) {
            return new EvidenceDetail(
                    title, mergedTag, location, content, risk, inlineSummary, diagnosticOnly, mergeKey);
        }
    }

    public static final class FailureDetail {
        public final String target;
        public final String reason;

        FailureDetail(String target, String reason) {
            this.target = target;
            this.reason = reason;
        }
    }

    private final Context ctx;

    public ReportFormatter(Context context) {
        this.ctx = context;
    }

    public List<DetectionResult> environmentDetections(RiskReport report) {
        List<DetectionResult> list = new ArrayList<>();
        for (DetectionResult d : report.getDetections()) {
            if (!d.getDetectorName().startsWith("collector:")) {
                list.add(d);
            }
        }
        list.sort((a, b) -> Integer.compare(detectionPriority(a), detectionPriority(b)));
        return list;
    }

    public int countCollectorCoverageGaps(RiskReport report) {
        int count = 0;
        for (DetectionResult d : report.getDetections()) {
            if (d.getDetectorName().startsWith("collector:")) {
                count++;
            }
        }
        return count;
    }

    public int countActionableAttention(List<DetectionResult> detections) {
        int count = 0;
        for (DetectionResult d : detections) {
            if (isActionableRisk(d)) {
                count++;
            }
        }
        return count;
    }

    public boolean isActionableRisk(DetectionResult d) {
        return !d.isInformational()
                && (d.getStatus() == DetectionStatus.DANGER || d.getStatus() == DetectionStatus.WARNING);
    }

    public boolean isInformationalItem(DetectionResult d) {
        return d.isInformational()
                && (d.getStatus() == DetectionStatus.DANGER || d.getStatus() == DetectionStatus.WARNING);
    }

    public boolean isIncompleteItem(DetectionResult d) {
        switch (d.getExecutionStatus()) {
            case PARTIAL:
            case UNAVAILABLE:
            case TIMEOUT:
            case ERROR:
                return d.getStatus() == DetectionStatus.UNKNOWN || d.getStatus() == DetectionStatus.NORMAL;
            default:
                return false;
        }
    }

    public boolean isCleanNormal(DetectionResult d) {
        return d.getStatus() == DetectionStatus.NORMAL
                && d.getExecutionStatus() == DetectionExecutionStatus.SAFE;
    }

    public int detectionPriority(DetectionResult detection) {
        switch (detection.getStatus()) {
            case DANGER:
                return detection.isInformational() ? 2 : 0;
            case WARNING:
                return detection.isInformational() ? 3 : 1;
            case UNKNOWN:
                return 4;
            case NORMAL:
            default:
                return detection.getExecutionStatus() == DetectionExecutionStatus.PARTIAL ? 5 : 6;
        }
    }

    public boolean isSyntheticCollector(String name) {
        return "fingerprint_id".equals(name)
                || "hook_memory_signals".equals(name)
                || "runtime_integrity_score_inputs".equals(name);
    }

    public String formatElapsed(long elapsedMs) {
        if (elapsedMs < 1000L) {
            return elapsedMs + " ms";
        }
        return String.format(Locale.getDefault(), "%.2f s", elapsedMs / 1000f);
    }

    public String heroSubtitle(RiskReport report) {
        DetectionResult primary = primaryDetection(report);
        if (primary != null && !primary.isInformational()) {
            return detectorTitle(primary.getDetectorName()) + " · " + primaryReadableEvidence(primary);
        }
        return riskDescription(report.getOverallRiskLevel());
    }

    public DetectionResult primaryDetection(RiskReport report) {
        List<DetectionResult> candidates = environmentDetections(report);
        DetectionResult informational = null;
        for (DetectionResult d : candidates) {
            if (d.getStatus() == DetectionStatus.NORMAL
                    || d.getStatus() == DetectionStatus.UNKNOWN
                    || d.getDetails().isEmpty()) {
                continue;
            }
            if (!d.isInformational()) {
                return d;
            }
            if (informational == null) {
                informational = d;
            }
        }
        return informational;
    }

    public String detectionSummary(DetectionResult detection) {
        if (detection.getStatus() == DetectionStatus.UNKNOWN) {
            String reason = firstReadableFailure(detection);
            if (reason != null) {
                return ctx.getString(R.string.detection_unavailable_reason_summary, reason);
            }
            return ctx.getString(R.string.detection_unavailable_summary,
                    executionStatusLabel(detection));
        }
        if (detection.getStatus() == DetectionStatus.NORMAL) {
            return detection.getExecutionStatus() == DetectionExecutionStatus.PARTIAL
                    ? ctx.getString(R.string.detection_partial_safe_summary,
                            detection.getChecksSucceeded(), detection.getChecksAttempted())
                    : ctx.getString(R.string.detection_normal_summary);
        }
        String reason = primaryReadableEvidence(detection);
        if (detection.isInformational()) {
            if (detection.getDetails().contains("deduped:corroborating_evidence")) {
                return ctx.getString(R.string.detection_duplicate_summary, reason);
            }
            return ctx.getString(R.string.detection_informational_summary, reason);
        }
        if (detection.getStatus() == DetectionStatus.DANGER) {
            return ctx.getString(R.string.detection_danger_summary, reason);
        }
        return ctx.getString(R.string.detection_warning_summary, reason);
    }

    public List<EvidenceDetail> detectionRiskFindings(DetectionResult detection) {
        return collectEvidenceDetails(detection, false);
    }

    public List<EvidenceDetail> detectionDiagnosticItems(DetectionResult detection) {
        return collectEvidenceDetails(detection, true);
    }

    private List<EvidenceDetail> collectEvidenceDetails(DetectionResult detection, boolean diagnosticOnly) {
        Map<String, EvidenceDetail> merged = new LinkedHashMap<>();
        for (String rawDetail : detection.getDetails()) {
            if (rawDetail == null || rawDetail.isBlank()) continue;
            if (isInternalExecutionToken(rawDetail)) continue;
            EvidenceDetail item = parseEvidenceDetail(rawDetail);
            if (item == null || item.diagnosticOnly != diagnosticOnly) continue;
            String key = item.mergeKey != null ? item.mergeKey : (item.location + "|" + item.content);
            EvidenceDetail existing = merged.get(key);
            if (existing == null) {
                merged.put(key, item);
            } else if (!existing.sourceTag.equals(item.sourceTag)
                    && !existing.sourceTag.contains(item.sourceTag)) {
                String combinedTag = combineSourceTags(existing.sourceTag, item.sourceTag);
                merged.put(key, existing.withSourceTag(combinedTag));
            }
        }
        return new ArrayList<>(merged.values());
    }

    private static String combineSourceTags(String first, String second) {
        if (("Java 层".equals(first) && "Native 层".equals(second))
                || ("Native 层".equals(first) && "Java 层".equals(second))) {
            return "Java + Native";
        }
        return first + " · " + second;
    }

    public List<FailureDetail> detectionFailureDetails(DetectionResult detection) {
        List<FailureDetail> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String reason : detection.getFailureReasons()) {
            if (reason == null || reason.isBlank()) continue;
            FailureDetail fd = parseFailureDetail(reason);
            String key = fd.target + "|" + fd.reason;
            if (seen.add(key)) {
                out.add(fd);
            }
        }
        for (String detail : detection.getDetails()) {
            if (detail != null && isInternalExecutionToken(detail)) {
                int sep = detail.indexOf(':');
                String payload = sep >= 0 ? detail.substring(sep + 1) : detail;
                FailureDetail fd = parseFailureDetail(payload);
                String key = fd.target + "|" + fd.reason;
                if (seen.add(key)) {
                    out.add(fd);
                }
            }
        }
        return out;
    }

    public String formatFindingsForCopy(DetectionResult detection) {
        List<EvidenceDetail> findings = detectionRiskFindings(detection);
        List<FailureDetail> failures = detectionFailureDetails(detection);
        if (findings.isEmpty() && failures.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("【").append(detectorTitle(detection.getDetectorName()))
                .append(" · ").append(detectionStatusLabel(detection)).append("】");
        int idx = 1;
        for (EvidenceDetail item : findings) {
            sb.append("\n\n").append(idx++).append(". ").append(item.title);
            if (!item.sourceTag.isEmpty()) {
                sb.append(" [").append(item.sourceTag).append("]");
            }
            sb.append("\n   检出位置：").append(item.location);
            sb.append("\n   检出内容：").append(item.content);
            sb.append("\n   风险说明：").append(item.risk);
        }
        if (!failures.isEmpty()) {
            sb.append("\n\n未完成子项：");
            for (FailureDetail f : failures) {
                sb.append("\n- ").append(f.target).append("：").append(f.reason);
            }
        }
        return sb.toString();
    }

    public String primaryReadableEvidence(DetectionResult detection) {
        List<EvidenceDetail> findings = detectionRiskFindings(detection);
        if (!findings.isEmpty()) {
            return findings.get(0).inlineSummary;
        }
        List<EvidenceDetail> diagnostics = detectionDiagnosticItems(detection);
        if (!diagnostics.isEmpty()) {
            return diagnostics.get(0).inlineSummary;
        }
        return ctx.getString(R.string.no_specific_evidence);
    }

    private String primaryRedactedEvidence(DetectionResult detection) {
        List<EvidenceDetail> findings = detectionRiskFindings(detection);
        if (!findings.isEmpty()) {
            return findings.get(0).title;
        }
        List<EvidenceDetail> diagnostics = detectionDiagnosticItems(detection);
        if (!diagnostics.isEmpty()) {
            return diagnostics.get(0).title;
        }
        return ctx.getString(R.string.no_specific_evidence);
    }

    private String firstReadableFailure(DetectionResult detection) {
        List<FailureDetail> failures = detectionFailureDetails(detection);
        if (!failures.isEmpty()) {
            FailureDetail f = failures.get(0);
            return f.target.isEmpty() ? f.reason : f.target + "（" + f.reason + "）";
        }
        return null;
    }

    public String detectionStatusLabel(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE: return ctx.getString(R.string.execution_unavailable);
            case DISABLED: return ctx.getString(R.string.execution_disabled);
            case TIMEOUT: return ctx.getString(R.string.execution_timeout);
            case ERROR: return ctx.getString(R.string.execution_error);
            case PARTIAL:
                if (detection.getStatus() == DetectionStatus.NORMAL) {
                    return ctx.getString(R.string.execution_partial);
                }
                return ctx.getString(R.string.risk_partial, riskLabel(detection.getRiskLevel()));
            default:
                break;
        }
        if (detection.getStatus() == DetectionStatus.NORMAL) {
            return ctx.getString(R.string.status_normal);
        }
        if (detection.isInformational()) {
            return ctx.getString(R.string.status_information);
        }
        return riskLabel(detection.getRiskLevel());
    }

    public String executionStatusLabel(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case SAFE:
            case RISK: return ctx.getString(R.string.execution_complete);
            case PARTIAL: return ctx.getString(R.string.execution_partial);
            case UNAVAILABLE: return ctx.getString(R.string.execution_unavailable);
            case DISABLED: return ctx.getString(R.string.execution_disabled);
            case TIMEOUT: return ctx.getString(R.string.execution_timeout);
            case ERROR:
            default: return ctx.getString(R.string.execution_error);
        }
    }

    @ColorRes
    public int detectionStatusColorRes(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE:
            case DISABLED:
            case TIMEOUT:
            case ERROR:
                return R.color.risk_unknown;
            case PARTIAL:
                return detection.getStatus() == DetectionStatus.NORMAL
                        ? R.color.risk_unknown
                        : riskColorRes(detection.getRiskLevel());
            default:
                return riskColorRes(detection.getRiskLevel());
        }
    }

    @ColorRes
    public int detectionStatusBgRes(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE:
            case DISABLED:
            case TIMEOUT:
            case ERROR:
                return R.color.risk_unknown_bg;
            case PARTIAL:
                return detection.getStatus() == DetectionStatus.NORMAL
                        ? R.color.risk_unknown_bg
                        : riskBgRes(detection.getRiskLevel());
            default:
                return riskBgRes(detection.getRiskLevel());
        }
    }

    public String riskLabel(RiskLevel level) {
        switch (level) {
            case SAFE: return ctx.getString(R.string.risk_safe);
            case LOW: return ctx.getString(R.string.risk_low);
            case MEDIUM: return ctx.getString(R.string.risk_medium);
            case HIGH: return ctx.getString(R.string.risk_high);
            case DEADLY: return ctx.getString(R.string.risk_deadly);
            case UNKNOWN:
            default: return ctx.getString(R.string.risk_unknown);
        }
    }

    public String riskDescription(RiskLevel level) {
        switch (level) {
            case SAFE: return ctx.getString(R.string.risk_description_safe);
            case LOW: return ctx.getString(R.string.risk_description_low);
            case MEDIUM: return ctx.getString(R.string.risk_description_medium);
            case HIGH: return ctx.getString(R.string.risk_description_high);
            case DEADLY: return ctx.getString(R.string.risk_description_deadly);
            case UNKNOWN:
            default: return ctx.getString(R.string.risk_description_unknown);
        }
    }

    @ColorRes
    public int riskColorRes(RiskLevel level) {
        switch (level) {
            case SAFE: return R.color.risk_safe;
            case LOW: return R.color.risk_low;
            case MEDIUM: return R.color.risk_medium;
            case HIGH: return R.color.risk_high;
            case DEADLY: return R.color.risk_deadly;
            case UNKNOWN:
            default: return R.color.risk_unknown;
        }
    }

    @ColorRes
    public int riskBgRes(RiskLevel level) {
        switch (level) {
            case SAFE: return R.color.risk_safe_bg;
            case LOW: return R.color.risk_low_bg;
            case MEDIUM: return R.color.risk_medium_bg;
            case HIGH: return R.color.risk_high_bg;
            case DEADLY: return R.color.risk_deadly_bg;
            case UNKNOWN:
            default: return R.color.risk_unknown_bg;
        }
    }

    public String detectorTitle(String name) {
        switch (name) {
            case "root": return ctx.getString(R.string.detector_root);
            case "mount_analysis": return ctx.getString(R.string.detector_mount);
            case "hook_framework": return ctx.getString(R.string.detector_hook);
            case "adb": return ctx.getString(R.string.detector_adb);
            case "emulator": return ctx.getString(R.string.detector_emulator);
            case "debug": return ctx.getString(R.string.detector_debug);
            case "cloud_phone": return ctx.getString(R.string.detector_cloud_phone);
            case "custom_rom": return ctx.getString(R.string.detector_custom_rom);
            case "multi_source_validation": return ctx.getString(R.string.detector_multi_source);
            case "signal_correlation": return ctx.getString(R.string.detector_correlation);
            case "consistency": return ctx.getString(R.string.detector_consistency);
            case "fingerprint_continuity": return ctx.getString(R.string.detector_fingerprint_continuity);
            default:
                if (name.startsWith("collector:")) {
                    return ctx.getString(R.string.detector_collector_coverage,
                            collectorTitle(name.substring("collector:".length())));
                }
                return ctx.getString(R.string.detector_other);
        }
    }

    public String collectorTitle(String name) {
        switch (name) {
            case "android_id": return ctx.getString(R.string.collector_android_id);
            case "build_props": return ctx.getString(R.string.collector_build_props);
            case "screen_info": return ctx.getString(R.string.collector_screen);
            case "apk_signature": return ctx.getString(R.string.collector_signature);
            case "bluetooth_info": return ctx.getString(R.string.collector_bluetooth);
            case "wifi_info": return ctx.getString(R.string.collector_wifi);
            case "telephony": return ctx.getString(R.string.collector_telephony);
            case "settings": return ctx.getString(R.string.collector_settings);
            case "adb_state": return ctx.getString(R.string.collector_adb);
            case "container_signals": return ctx.getString(R.string.collector_container);
            case "gpu_info": return ctx.getString(R.string.collector_gpu);
            case "sensor_fingerprint": return ctx.getString(R.string.collector_sensor);
            case "cpu_topology": return ctx.getString(R.string.collector_cpu_topology);
            case "hardware_profile": return ctx.getString(R.string.collector_hardware_profile);
            case "partition_fingerprints": return ctx.getString(R.string.collector_partition_fingerprints);
            case "drm_id": return ctx.getString(R.string.collector_drm);
            case "boot_id": return ctx.getString(R.string.collector_boot);
            case "system_properties_native": return ctx.getString(R.string.collector_properties);
            case "cpu_info": return ctx.getString(R.string.collector_cpu);
            case "disk_size": return ctx.getString(R.string.collector_disk);
            case "kernel_info": return ctx.getString(R.string.collector_kernel);
            case "fingerprint_id": return ctx.getString(R.string.collector_fingerprint_id);
            case "hook_memory_signals": return ctx.getString(R.string.collector_hook_memory);
            case "runtime_integrity_score_inputs": return ctx.getString(R.string.collector_score_inputs);
            default: return ctx.getString(R.string.collector_other);
        }
    }

    public String collectorSensitivityLabel(String name) {
        if ("android_id".equals(name) || "drm_id".equals(name)
                || "boot_id".equals(name) || "apk_signature".equals(name)) {
            return ctx.getString(R.string.sensitivity_pseudonymous);
        }
        if (isSyntheticCollector(name) || "system_properties_native".equals(name)
                || "cpu_info".equals(name) || "kernel_info".equals(name)) {
            return ctx.getString(R.string.sensitivity_technical);
        }
        return ctx.getString(R.string.sensitivity_non_sensitive);
    }

    public String collectorStatusLabel(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return ctx.getString(R.string.collector_status_success);
            case EMPTY: return ctx.getString(R.string.collector_status_empty);
            case ERROR: return ctx.getString(R.string.collector_status_error);
            case UNSUPPORTED: return ctx.getString(R.string.collector_status_unsupported);
            default: return ctx.getString(R.string.status_unknown);
        }
    }

    @ColorRes
    public int collectorStatusColorRes(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return R.color.risk_safe;
            case ERROR: return R.color.risk_deadly;
            case EMPTY:
            case UNSUPPORTED:
            default: return R.color.risk_unknown;
        }
    }

    @ColorRes
    public int collectorStatusBgRes(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return R.color.risk_safe_bg;
            case ERROR: return R.color.risk_deadly_bg;
            case EMPTY:
            case UNSUPPORTED:
            default: return R.color.risk_unknown_bg;
        }
    }

    public String collectorSummary(CollectorResult result) {
        switch (result.getStatus()) {
            case EMPTY:
                return ctx.getString(R.string.collector_empty);
            case ERROR:
                return ctx.getString(R.string.collector_failed,
                        humanizeFailureReason(result.getError()));
            case UNSUPPORTED:
                return ctx.getString(R.string.collector_unsupported);
            case SUCCESS:
            default:
                if (result.isCompareSources() && result.getValues().size() > 1) {
                    return result.isConsistent()
                            ? ctx.getString(R.string.collector_sources_consistent,
                                    result.getValues().size())
                            : ctx.getString(R.string.collector_sources_inconsistent,
                                    result.getValues().size());
                }
                if (result.getValues().isEmpty()) {
                    return ctx.getString(R.string.collector_no_display_data);
                }
                StringBuilder summary = new StringBuilder();
                int count = 0;
                for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
                    if (count > 0) summary.append(" · ");
                    summary.append(collectorValueLabel(result.getFieldName(), entry.getKey()))
                            .append(" ")
                            .append(formatCollectorValue(result.getFieldName(),
                                    entry.getKey(), entry.getValue(), true));
                    if (++count == 2) break;
                }
                return summary.toString();
        }
    }

    public Map<String, String> collectorFormattedEntries(CollectorResult result) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
            out.put(
                    collectorValueLabel(result.getFieldName(), entry.getKey()),
                    formatCollectorValue(result.getFieldName(), entry.getKey(), entry.getValue(), false)
            );
        }
        return out;
    }

    public String shortenHash(String value) {
        if (value == null || value.isBlank()) {
            return ctx.getString(R.string.value_none);
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 18) {
            return trimmed;
        }
        return trimmed.substring(0, 10) + "…" + trimmed.substring(trimmed.length() - 6);
    }

    public String shortenValue(String value) {
        if (value == null || value.isBlank()) {
            return ctx.getString(R.string.value_none);
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 44) {
            return trimmed;
        }
        return trimmed.substring(0, 24) + "…" + trimmed.substring(trimmed.length() - 10);
    }

    public String collectorValueLabel(String field, String key) {
        switch (key) {
            case "summary": return ctx.getString(R.string.value_summary);
            case "status": return ctx.getString(R.string.value_status);
            case "supported": return ctx.getString(R.string.value_supported);
            case "low_energy_supported": return ctx.getString(R.string.value_bluetooth_le);
            case "wifi_direct_supported": return ctx.getString(R.string.value_wifi_direct);
            case "development_settings_enabled": return ctx.getString(R.string.value_developer_options);
            case "checks_completed": return ctx.getString(R.string.value_checks_completed);
            case "check_failures": return ctx.getString(R.string.value_check_failures);
            case "phone_type": return ctx.getString(R.string.value_phone_type);
            case "sim_state": return ctx.getString(R.string.value_sim_state);
            case "signing_cert_sha256": return ctx.getString(R.string.value_signing_cert);
            case "native": return ctx.getString(R.string.value_native_source);
            case "tcp_port": return ctx.getString(R.string.value_tcp_port);
            case "signals": return ctx.getString(R.string.value_signals);
            case "count": return ctx.getString(R.string.value_count);
            case "width":
            case "width_px": return ctx.getString(R.string.value_width);
            case "height":
            case "height_px": return ctx.getString(R.string.value_height);
            case "density":
            case "density_dpi": return ctx.getString(R.string.value_density);
            case "xdpi": return ctx.getString(R.string.value_xdpi);
            case "ydpi": return ctx.getString(R.string.value_ydpi);
            case "native_data": return ctx.getString(R.string.value_data_capacity);
            case "native_storage": return ctx.getString(R.string.value_storage_capacity);
            case "settings_api": return ctx.getString(R.string.value_settings_api);
            case "content_resolver": return ctx.getString(R.string.value_content_resolver);
            case "content_query": return ctx.getString(R.string.value_content_query);
            case "egl_version": return ctx.getString(R.string.value_egl_version);
            case "vendor": return ctx.getString(R.string.value_gpu_vendor);
            case "renderer": return ctx.getString(R.string.value_gpu_renderer);
            case "extensions_hash": return ctx.getString(R.string.value_gpu_extensions);
            case "tuple_hash": return ctx.getString(R.string.value_sensor_tuple_hash);
            case "runtime_processors": return ctx.getString(R.string.value_runtime_processors);
            case "sysfs_cores": return ctx.getString(R.string.value_sysfs_cores);
            case "clusters": return ctx.getString(R.string.value_cpu_clusters);
            case "ram_total_mb_bucket": return ctx.getString(R.string.value_ram_bucket);
            case "low_ram_device": return ctx.getString(R.string.value_low_ram);
            case "supported_abis": return ctx.getString(R.string.value_abis);
            case "composite_id": return ctx.getString(R.string.value_composite_id);
            case "hardware_id": return ctx.getString(R.string.value_hardware_id);
            case "system_id": return ctx.getString(R.string.value_system_id);
            case "volatile_id": return ctx.getString(R.string.value_volatile_id);
            case "brand": return ctx.getString(R.string.value_brand);
            case "model": return ctx.getString(R.string.value_model);
            case "device": return ctx.getString(R.string.value_device);
            case "manufacturer": return ctx.getString(R.string.value_manufacturer);
            case "hardware": return ctx.getString(R.string.value_hardware);
            case "board": return ctx.getString(R.string.value_board);
            case "fingerprint": return ctx.getString(R.string.value_fingerprint);
            default:
                if (key.startsWith("ro.")) return ctx.getString(R.string.value_system_property, key);
                return key.replace('_', ' ');
        }
    }

    public String formatCollectorValue(String field, String key, String value, boolean summary) {
        if (value == null || value.isBlank()) return ctx.getString(R.string.value_none);
        if ("disk_size".equals(field) && ("native_data".equals(key) || "native_storage".equals(key))) {
            try {
                double gib = Long.parseLong(value) / (1024d * 1024d * 1024d);
                return String.format(Locale.getDefault(), "%.1f GB", gib);
            } catch (NumberFormatException ignored) {}
        }
        if ("ram_total_mb_bucket".equals(key)) {
            try {
                long mb = Long.parseLong(value);
                if (mb >= 1024) {
                    return String.format(Locale.getDefault(), "%.1f GB", mb / 1024d);
                }
                return mb + " MB";
            } catch (NumberFormatException ignored) {}
        }
        if ("phone_type".equals(key)) return phoneTypeLabel(value);
        if ("sim_state".equals(key)) return simStateLabel(value);
        if ("mount_overlay".equals(value)) return ctx.getString(R.string.value_mount_overlay);
        if ("summary".equals(key)) {
            if ("present".equalsIgnoreCase(value)) return ctx.getString(R.string.value_present);
            if ("none".equalsIgnoreCase(value)) return ctx.getString(R.string.value_none);
            if ("enabled_wifi".equals(value)) return ctx.getString(R.string.value_adb_wifi_on);
            if ("enabled".equals(value)) return ctx.getString(R.string.value_adb_on);
        }
        if ("true".equalsIgnoreCase(value)) return ctx.getString(R.string.yes);
        if ("false".equalsIgnoreCase(value)) return ctx.getString(R.string.no);
        if (summary && (field.endsWith("_id") || key.contains("hash") || key.endsWith("_id")) && value.length() > 16) {
            return value.substring(0, 8) + "…" + value.substring(value.length() - 4);
        }
        return summary ? shortenValue(value) : value;
    }

    private String phoneTypeLabel(String value) {
        switch (value) {
            case "0": return ctx.getString(R.string.phone_type_none);
            case "1": return ctx.getString(R.string.phone_type_gsm);
            case "2": return ctx.getString(R.string.phone_type_cdma);
            case "3": return ctx.getString(R.string.phone_type_sip);
            default: return value;
        }
    }

    private String simStateLabel(String value) {
        switch (value) {
            case "0": return ctx.getString(R.string.sim_state_unknown);
            case "1": return ctx.getString(R.string.sim_state_absent);
            case "2": return ctx.getString(R.string.sim_state_pin);
            case "3": return ctx.getString(R.string.sim_state_puk);
            case "4": return ctx.getString(R.string.sim_state_network_locked);
            case "5": return ctx.getString(R.string.sim_state_ready);
            case "6": return ctx.getString(R.string.sim_state_not_ready);
            case "7": return ctx.getString(R.string.sim_state_perm_disabled);
            case "8": return ctx.getString(R.string.sim_state_card_io_error);
            case "9": return ctx.getString(R.string.sim_state_card_restricted);
            case "10": return ctx.getString(R.string.sim_state_loaded);
            default: return value;
        }
    }

    public String buildRedactedSummary(RiskReport report) {
        StringBuilder summary = new StringBuilder();
        summary.append(ctx.getString(R.string.redacted_report_header,
                report.getSdkVersion(), riskLabel(report.getOverallRiskLevel()),
                report.getRiskScore(), report.getDisplayThresholdMaximum(),
                report.getCompletedCheckCount(), report.getCheckCount(),
                report.getDangerCount(), report.getWarningCount(),
                report.getIncompleteCheckCount()));
        for (DetectionResult detection : report.getDetections()) {
            if (detection.getDetectorName().startsWith("collector:")) continue;
            summary.append(ctx.getString(R.string.redacted_report_item,
                    detectorTitle(detection.getDetectorName()), detectionStatusLabel(detection)));
            if (!detectionRiskFindings(detection).isEmpty()) {
                summary.append(ctx.getString(R.string.redacted_report_reason,
                        primaryRedactedEvidence(detection)));
            }
        }
        summary.append(ctx.getString(R.string.redacted_report_footer));
        return summary.toString();
    }

    // ---- Structured Evidence Parsing (Location + Content + Risk) ----

    private EvidenceDetail parseEvidenceDetail(String raw) {
        String detail = raw.trim();
        boolean fromNative = detail.startsWith("native:");
        String normalized = fromNative ? detail.substring("native:".length()) : detail;
        String layerTag = fromNative ? "Native 层" : "Java 层";

        // ---- Diagnostic / context-only tokens ----
        if (detail.startsWith("loader_depth:")) {
            String depth = detail.substring("loader_depth:".length());
            return diag("类加载器链深度", "环境诊断",
                    "应用 ClassLoader 继承链",
                    "当前类加载器共 " + depth + " 层（处于正常范围）",
                    "类加载器层级：" + depth + " 层");
        }
        if (detail.startsWith("passes:")) {
            String passes = detail.substring("passes:".length());
            return diag("后台完整性巡检", "后台守护",
                    "Native 周期性内存与进程监控线程",
                    "自 SDK 初始化以来已完成 " + passes + " 轮后台巡检",
                    "后台巡检已完成 " + passes + " 轮");
        }
        if (detail.equals("art_native_flag:invoke")) {
            return diag("系统原生反射方法", "环境诊断",
                    "java.lang.reflect.Method.invoke",
                    "当前系统 libcore 使用原生实现 Method.invoke（属正常系统特征，不计分）",
                    "Method.invoke 为系统原生实现");
        }
        if (detail.equals("deduped:corroborating_evidence")) {
            return diag("同源证据已去重", "评分策略",
                    "风险聚合与证据去重引擎",
                    "本项检出的风险证据与前置检测项同源，仅保留用于交叉佐证，不重复叠加总分",
                    "与前置检测项同源，已去重");
        }

        // ---- Root Detection ----
        if (detail.startsWith("su_found:") || normalized.startsWith("su:")) {
            String path = detail.startsWith("su_found:")
                    ? detail.substring("su_found:".length())
                    : normalized.substring("su:".length());
            return risk("su 提权可执行文件", layerTag, path,
                    "在系统路径中检出 su 二进制提权文件",
                    "设备存在 su 提权入口，可获取超级用户权限并突破应用沙箱隔离，可能导致私有数据泄露或应用逻辑被篡改。",
                    "检出 su 文件：" + path,
                    "root:su:" + path);
        }
        if (normalized.startsWith("path_su:")) {
            String path = normalized.substring("path_su:".length());
            return risk("PATH 环境变量中的 Root 工具", "Native 层",
                    "/proc/self/environ (PATH) → " + path,
                    "在进程默认 PATH 可执行搜索目录中检出 Root 相关二进制文件",
                    "系统全局可执行路径已暴露 Root 工具，任意进程均可直接调用提权能力，运行环境不可信。",
                    "PATH 检出 Root 文件：" + path,
                    "root:su:" + path);
        }
        if (detail.startsWith("magisk_found:") || normalized.startsWith("magisk:")) {
            String path = detail.startsWith("magisk_found:")
                    ? detail.substring("magisk_found:".length())
                    : normalized.substring("magisk:".length());
            return risk("Magisk 框架残留路径", layerTag, path,
                    "在文件系统中检出 Magisk Root 框架核心目录或数据库文件",
                    "设备已部署 Magisk Root 框架，支持系统级模块注入、属性动态伪造及 Root 隐藏，存在高危环境被控风险。",
                    "检出 Magisk 路径：" + path,
                    "root:magisk:" + path);
        }
        if (detail.startsWith("ksu_found:") || normalized.startsWith("ksu:")) {
            String path = detail.startsWith("ksu_found:")
                    ? detail.substring("ksu_found:".length())
                    : normalized.substring("ksu:".length());
            return risk("KernelSU 框架残留路径", layerTag, path,
                    "在文件系统中检出 KernelSU 管理工具或模块目录",
                    "设备已部署内核级 Root 方案 KernelSU，可在内核层隐蔽授权并拦截系统调用，极易绕过常规应用层防护。",
                    "检出 KernelSU 路径：" + path,
                    "root:ksu:" + path);
        }
        if (detail.startsWith("apatch_found:") || normalized.startsWith("apatch:")) {
            String path = detail.startsWith("apatch_found:")
                    ? detail.substring("apatch_found:".length())
                    : normalized.substring("apatch:".length());
            return risk("APatch 内核补丁路径", layerTag, path,
                    "在文件系统中检出 APatch / KPatch 内核补丁组件",
                    "设备已安装内核级动态补丁框架 APatch，可修补内核权限校验并授予 Root，系统底层可信度丧失。",
                    "检出 APatch 路径：" + path,
                    "root:apatch:" + path);
        }
        if (detail.startsWith("modules_found:") || normalized.startsWith("modules:")) {
            String path = detail.startsWith("modules_found:")
                    ? detail.substring("modules_found:".length())
                    : normalized.substring("modules:".length());
            return risk("Root 模块扩展目录", layerTag, path,
                    "检出 Root 框架扩展模块存储目录",
                    "设备存在 Root 模块加载目录，可能已启用 Hook 注入、抓包证书、设备改机或反检测隐藏模块。",
                    "检出 Root 模块目录：" + path,
                    "root:modules:" + path);
        }
        if (normalized.startsWith("tamper_tool:")) {
            String path = normalized.substring("tamper_tool:".length());
            return risk("逆向或改机工具文件", "Native 层", path,
                    "在本地存储路径检出已知逆向分析或改机工具残留",
                    "设备存在 Frida Server、改机配置等高危工具文件，应用面临被动态注入调试或伪造设备身份的风险。",
                    "检出工具路径：" + path,
                    "root:tool:" + path);
        }
        if (normalized.startsWith("syscall_mismatch:")) {
            String path = normalized.substring("syscall_mismatch:".length());
            return risk("系统调用访问结果矛盾", "Native 层",
                    path + "（faccessat / fstatat / openat）",
                    "同一路径通过不同底层系统调用探测时，存在性与打开结果自相矛盾",
                    "表明存在 Root 隐藏框架（如 Shamiko / Zygisk）在部分拦截或伪装文件访问，设备处于对抗隐藏状态。",
                    "路径访问矛盾：" + path,
                    "root:syscall_mismatch:" + path);
        }
        if (normalized.startsWith("listing_mismatch:")) {
            String path = normalized.substring("listing_mismatch:".length());
            return risk("目录枚举与访问结果不一致", "Native 层",
                    path + "（getdents64 vs faccessat）",
                    "父目录底层条目遍历结果与直接访问该路径的结果不一致",
                    "存在针对特定敏感路径的隐蔽隐藏机制，试图对安全检测屏蔽 Root 文件痕迹。",
                    "目录遍历隐藏痕迹：" + path,
                    "root:listing_mismatch:" + path);
        }
        if (normalized.startsWith("ksu_prctl:")) {
            String ver = normalized.substring("ksu_prctl:".length());
            return risk("内核级 Root 接口响应", "内核探测",
                    "内核 prctl 系统调用（0xDEADBEEF）",
                    "内核响应了 KernelSU / APatch 私有控制指令（返回：" + ver + "）",
                    "即使隐藏了所有用户态文件，内核中仍驻留提权模块，具备系统最高控制权，属于高置信度 Root 证据。",
                    "内核响应 KernelSU/APatch 指令（" + ver + "）",
                    "root:ksu_prctl");
        }
        if (normalized.startsWith("selinux_context:")) {
            String seCtx = normalized.substring("selinux_context:".length());
            return risk("异常 SELinux 特权上下文", "内核探测",
                    "/proc/self/attr/current",
                    "当前进程运行在包含特权标识的 SELinux 上下文中：" + seCtx,
                    "正常应用应运行在受限应用安全域，当前特权域说明进程环境被提权或 SELinux 策略遭到篡改。",
                    "SELinux 上下文异常：" + seCtx,
                    "root:selinux_ctx");
        }
        if (detail.equals("selinux_permissive")) {
            return risk("SELinux 处于宽松模式", "系统状态",
                    "/sys/fs/selinux/enforce",
                    "读取到 SELinux 强制访问控制状态值为 0（Permissive 模式）",
                    "系统安全策略已降级为仅告警不拦截，恶意进程可越权读写应用私有数据或操纵系统服务。",
                    "SELinux 处于 Permissive 宽松模式",
                    "root:selinux");
        }
        if (detail.equals("test_keys")) {
            return risk("系统使用测试密钥签名", "系统构建",
                    "android.os.Build.TAGS",
                    "系统构建标签包含 test-keys（非厂商正式量产签名）",
                    "设备运行着测试签名或自行编译的系统镜像，通常意味着刷机、自编译 ROM 或缺少官方签名校验保障。",
                    "Build.TAGS 包含 test-keys",
                    "root:test_keys");
        }
        if (normalized.equals("root_check_positive")) {
            return risk("Native 层检出 Root 特征", "Native 层",
                    "Native 层底层 Root 综合探测",
                    "底层系统调用探测返回 Root 阳性结论",
                    "设备底层环境存在 Root 痕迹，应用运行环境完整性无法保证。",
                    "Native 层检出 Root 特征",
                    "root:native_positive");
        }

        // ---- Mount Analysis & Native Mount Tokens ----
        if (detail.startsWith("system_tmpfs_mount:") || normalized.startsWith("mount:system_tmpfs:")) {
            String mp = detail.startsWith("system_tmpfs_mount:")
                    ? detail.substring("system_tmpfs_mount:".length())
                    : normalized.substring("mount:system_tmpfs:".length());
            return risk("只读系统分区异常 tmpfs 挂载", fromNative ? "Native 层" : "挂载表",
                    "/proc/self/mountinfo → " + mp,
                    "只读系统分区子路径 " + mp + " 被挂载为可写 tmpfs 内存文件系统",
                    "攻击者常借此绕过系统只读分区保护（如向 /system/etc/security/cacerts 注入自定义根证书实现 HTTPS 抓包，或无痕替换系统文件）。",
                    "只读分区异常 tmpfs 挂载：" + mp,
                    "mount:system_tmpfs:" + mp);
        }
        if (normalized.equals("mount:ksu") || detail.equals("mountinfo:ksu") || detail.equals("kernelsu_mount")) {
            String loc = detail.equals("kernelsu_mount") ? "/proc/mounts" : "/proc/self/mountinfo";
            return risk("KernelSU 文件系统挂载", fromNative ? "Native 层" : "挂载表",
                    loc,
                    "挂载表中检出 KernelSU 关键字（kernelsu / /data/adb/ksu）",
                    "KernelSU 正通过自定义挂载接管或覆盖系统路径，设备具备内核级 Root 篡改能力。",
                    loc + " 检出 KernelSU 挂载",
                    "mount:ksu:" + loc);
        }
        if (normalized.equals("mount:magisk") || detail.equals("mountinfo:magisk") || detail.equals("magisk_mount")) {
            String loc = detail.equals("magisk_mount") ? "/proc/mounts" : "/proc/self/mountinfo";
            return risk("Magisk 文件系统挂载", fromNative ? "Native 层" : "挂载表",
                    loc,
                    "挂载表中检出 Magisk 挂载标识（magisk / core/mirror）",
                    "Magisk 挂载机制正在重定向系统目录，可能已加载恶意插件或修改系统库与证书。",
                    loc + " 检出 Magisk 挂载",
                    "mount:magisk:" + loc);
        }
        if (normalized.equals("mount:module") || detail.equals("module_mount")) {
            String loc = detail.equals("module_mount") ? "/proc/mounts" : "/proc/self/mountinfo";
            return risk("Root 模块绑定挂载", fromNative ? "Native 层" : "挂载表",
                    loc + "（/data/adb/modules）",
                    "挂载表中检出 /data/adb/modules 路径的模块绑定挂载",
                    "外部 Root 模块正在覆盖系统目录内容，可能已植入改机、Hook 或抓包模块。",
                    "检出 /data/adb/modules 模块挂载",
                    "mount:module:" + loc);
        }
        if (normalized.equals("mount:debug_ramdisk") || detail.equals("debug_ramdisk_mount")) {
            String loc = detail.equals("debug_ramdisk_mount") ? "/proc/mounts" : "/proc/self/mountinfo";
            return risk("Root 调试 ramdisk 挂载", fromNative ? "Native 层" : "挂载表",
                    loc + "（/debug_ramdisk）",
                    "挂载表中检出 debug_ramdisk 挂载项",
                    "debug_ramdisk 常用于 Root 框架注入临时守护进程与工具文件，提示设备启动环境已被修改。",
                    "检出 debug_ramdisk 挂载",
                    "mount:debug_ramdisk:" + loc);
        }
        if (detail.equals("docker_mount")) {
            return risk("容器化 Overlay 挂载", "挂载表",
                    "/proc/mounts",
                    "挂载表中检出 Docker 容器路径（/docker/）与 overlay 文件系统",
                    "设备运行在容器化虚拟实例中，常见于云手机、自动化测试集群或黑灰产群控环境。",
                    "/proc/mounts 检出 Docker 容器挂载",
                    "mount:docker");
        }

        // ---- Hook & Injection Detection ----
        if (detail.startsWith("inline_hook:")) {
            String sym = detail.substring("inline_hook:".length());
            String lib = ("dlopen".equals(sym) || "dlsym".equals(sym)) ? "libdl.so" : "libc.so";
            return risk("系统函数被 Inline Hook", "Native 层",
                    lib + " 导出函数 " + sym + "（内存代码段 vs 磁盘 ELF）",
                    "内存中函数 " + sym + " 入口指令与磁盘原始 ELF 不一致或存在跳转蹦床（Trampoline）",
                    "关键底层系统函数被劫持，攻击者可拦截并篡改文件访问、系统属性读取或网络通信返回值。",
                    lib + " 函数 " + sym + " 被 Inline Hook",
                    "hook:inline:" + sym);
        }
        if (detail.startsWith("got_hook:")) {
            String sym = detail.substring("got_hook:".length());
            return risk("动态链接表（PLT/GOT）被篡改", "Native 层",
                    "libriskengine.so PLT/GOT 表项 → " + sym,
                    "导入符号 " + sym + " 的 GOT 跳转目标指向非系统可信模块",
                    "存在 GOT/PLT Hook（如 ShadowHook / ByteHook / xHook），正在拦截并伪造 SDK 的底层函数调用。",
                    "GOT 表符号 " + sym + " 被劫持",
                    "hook:got:" + sym);
        }
        if (detail.startsWith("jni_table_hook:") || detail.startsWith("jni_slot_hook:")) {
            String fn = detail.substring(detail.indexOf(':') + 1);
            return risk("JNI 函数表入口被劫持", "Native 层",
                    "JNIEnv->functions." + fn + "（对比 libart.so 地址范围）",
                    "JNI 核心函数指针 " + fn + " 指向 libart.so 可执行代码段之外的未知地址",
                    "ART 运行时的 JNI 接口表遭到篡改，攻击者可监控或伪造 Java 与 Native 层之间的交互数据。",
                    "JNI 函数表入口 " + fn + " 被替换",
                    "hook:jni:" + fn);
        }
        if (detail.startsWith("art_native_flag:")) {
            String method = detail.substring("art_native_flag:".length());
            return risk("Java 方法被异常标记为 Native", "ART 运行时",
                    "ART Method 元数据 → " + method,
                    "原本为纯 Java 实现的方法 " + method + " 在运行时出现 ACC_NATIVE 修饰标志",
                    "常见于 ART Hook 框架（如 LSPosed / SandHook / Pine）将 Java 方法入口替换为原生跳板函数以劫持执行流。",
                    "方法 " + method + " 出现异常 Native 标记",
                    "hook:art_flag:" + method);
        }
        if (detail.startsWith("art_native_cleared:")) {
            String method = detail.substring("art_native_cleared:".length());
            return risk("SDK 原生桥接方法被劫持", "ART 运行时",
                    "NativeCollectorBridge." + method,
                    "SDK 原生 JNI 方法 " + method + " 的 ACC_NATIVE 标志被清除",
                    "Java 层 Hook（如 Frida Java.use）已将 SDK 原生方法替换为伪造 Java 代理，试图绕过或屏蔽安全检测。",
                    "桥接方法 " + method + " 的 Native 标记被篡改",
                    "hook:art_cleared:" + method);
        }
        if (detail.startsWith("memfd_private_elf:")) {
            String label = detail.substring("memfd_private_elf:".length());
            return risk("无文件 memfd 私有可执行 ELF 注入", "Native 层",
                    "/proc/self/maps → /memfd:" + label + "（私有 r-xp 段）",
                    "检出伪装为匿名内存文件（memfd）的私有可执行 ELF 动态库镜像",
                    "攻击者常通过 memfd_create + dlopen 进行无文件内存注入，以隐蔽加载 Hook/恶意模块并逃避路径扫描。",
                    "检出 memfd 私有 ELF 注入：/memfd:" + label,
                    "hook:memfd:" + label);
        }
        if (detail.equals("late_memfd_elf")) {
            return risk("运行期延迟 memfd 内存注入", "后台巡检",
                    "/proc/self/maps（/memfd:* 私有可执行段）",
                    "后台持续巡检期间检出延迟加载的私有 memfd 可执行 ELF 镜像",
                    "攻击者采用延迟注入策略规避启动期检测，当前进程已出现无文件内存载荷。",
                    "后台巡检发现延迟 memfd ELF 注入",
                    "hook:late_memfd");
        }
        if (detail.startsWith("wx_segment:")) {
            String target = detail.substring("wx_segment:".length());
            String displayTarget = "self".equals(target) ? "libriskengine.so" : target;
            return risk("关键代码段存在可写可执行权限", "Native 层",
                    "/proc/self/maps → " + displayTarget + "（rwxp）",
                    "模块 " + displayTarget + " 的内存代码段同时拥有写入与执行权限（W+X）",
                    "正常代码段应为只读可执行（r-xp），出现 rwxp 通常是动态代码补丁、Inline Hook 或 Shellcode 注入的直接迹象。",
                    displayTarget + " 出现 rwx 可写可执行段",
                    "hook:wx:" + target);
        }
        if (detail.equals("late_wx_self") || detail.equals("late_wx_art")) {
            String target = detail.equals("late_wx_self") ? "libriskengine.so" : "libart.so";
            return risk("运行期关键库出现可写可执行段", "后台巡检",
                    "/proc/self/maps → " + target + "（rwxp）",
                    "后台巡检发现 " + target + " 内存段被修改为可写可执行（rwx）权限",
                    "存在运行期延迟触发的代码段热修改或动态 Hook 注入行为。",
                    "后台巡检发现 " + target + " 出现 rwx 内存段",
                    "hook:" + detail);
        }
        if (detail.equals("late_tracer_attached")) {
            return risk("运行期延迟附加调试器", "后台巡检",
                    "/proc/self/status（TracerPid）",
                    "应用运行期间后台巡检发现 TracerPid 变为非零值",
                    "攻击者在绕过应用启动检测后，于运行中动态附加 ptrace 调试器分析或篡改进程内存。",
                    "后台巡检发现进程被调试器延迟附加",
                    "hook:late_tracer");
        }
        if (detail.startsWith("late_module:")) {
            String mod = detail.substring("late_module:".length());
            return risk("运行期延迟注入框架模块", "后台巡检",
                    "/proc/self/maps（" + mod + "）",
                    "后台巡检期间发现进程地址空间新加载了 " + mod + " 注入模块",
                    "攻击者采用延迟注入方式绕过启动阶段校验，进程现已处于动态 Hook 控制下。",
                    "后台巡检发现延迟注入模块：" + mod,
                    "hook:late_mod:" + mod);
        }
        if (detail.equals("xposed_class_found")) {
            return risk("检出 Xposed 桥接类", "Java 层",
                    "JVM ClassLoader（de.robv.android.xposed.XposedBridge）",
                    "在应用类加载环境中成功定位到 Xposed 核心桥接类",
                    "当前进程已被注入 Xposed / LSPosed 框架，攻击者可拦截任意 Java 方法调用与敏感参数。",
                    "类加载器中检出 XposedBridge",
                    "hook:xposed_class");
        }
        if (detail.startsWith("xposed_hooks_active:")) {
            String count = detail.substring("xposed_hooks_active:".length());
            return risk("存在活跃的 Xposed 方法 Hook", "Java 层",
                    "XposedBridge.sHookedMethodCallbacks",
                    "检出 " + count + " 个正在生效的 Java 方法 Hook 回调项",
                    "应用或系统关键方法正被主动劫持，业务风控逻辑、加密算法及敏感数据面临被篡改和窃取风险。",
                    "检出 " + count + " 个活跃 Xposed Hook 回调",
                    "hook:xposed_active");
        }
        if (detail.startsWith("xposed_stack:")) {
            String cls = detail.substring("xposed_stack:".length());
            return risk("调用栈检出 Hook 框架帧", "Java 层",
                    "Thread.getStackTrace() → " + cls,
                    "当前线程执行调用栈中包含 Xposed / LSPosed 框架类：" + cls,
                    "应用执行流程正经过 Hook 代理层中转，函数输入与输出可被实时篡改。",
                    "调用栈检出框架类：" + cls,
                    "hook:xposed_stack:" + cls);
        }
        if (detail.equals("frida_maps") || detail.startsWith("frida_maps:")
                || detail.equals("maps:frida") || detail.startsWith("maps:frida:")) {
            String path = extractMapsDetailPath(detail, "frida_maps", "maps:frida");
            String loc = path.isEmpty() ? "/proc/self/maps" : "/proc/self/maps → " + path;
            String tag = detail.startsWith("maps:") ? "Native 层" : "Java 层";
            return risk("内存映射检出 Frida 模块", tag, loc,
                    path.isEmpty()
                            ? "进程内存映射表中检出 Frida 注入动态库"
                            : "进程内存映射中加载了 Frida 注入库：" + path,
                    "Frida 动态插桩引擎已注入当前进程，攻击者可实时 Hook 任意 Java/Native 函数并转储内存明文。",
                    path.isEmpty() ? "/proc/self/maps 检出 Frida 模块" : "内存映射检出 Frida：" + path,
                    "hook:maps_frida:" + path);
        }
        if (detail.equals("maps:gadget") || detail.startsWith("maps:gadget:")) {
            String path = extractMapsDetailPath(detail, "maps:gadget", "maps:gadget");
            String loc = path.isEmpty() ? "/proc/self/maps" : "/proc/self/maps → " + path;
            return risk("内存映射检出 Frida Gadget", "Native 层", loc,
                    path.isEmpty()
                            ? "进程内存映射中检出 libgadget.so / frida-gadget 模块"
                            : "进程内存映射中加载了 Frida Gadget 嵌入库：" + path,
                    "应用可能被二次打包植入了 Frida Gadget，无需 Root 即可直接运行动态 Hook 脚本篡改业务逻辑。",
                    path.isEmpty() ? "检出 Frida Gadget 内存映射" : "内存映射检出 Gadget：" + path,
                    "hook:maps_gadget:" + path);
        }
        if (detail.equals("maps:xposed") || detail.startsWith("maps:xposed:")
                || detail.equals("maps:lsposed") || detail.startsWith("maps:lsposed:")
                || detail.equals("maps:substrate") || detail.startsWith("maps:substrate:")) {
            String fw = detail.contains("lsposed") ? "LSPosed"
                    : (detail.contains("substrate") ? "Cydia Substrate" : "Xposed");
            String prefix = detail.contains("lsposed") ? "maps:lsposed"
                    : (detail.contains("substrate") ? "maps:substrate" : "maps:xposed");
            String path = extractMapsDetailPath(detail, prefix, prefix);
            String loc = path.isEmpty() ? "/proc/self/maps" : "/proc/self/maps → " + path;
            return risk("内存映射检出 " + fw + " 模块", "Native 层", loc,
                    path.isEmpty()
                            ? "进程内存映射中检出 " + fw + " Hook 框架动态库"
                            : "进程内存映射中加载了 " + fw + " 模块：" + path,
                    "注入框架已加载至当前进程内存，可在用户无感知情况下劫持应用方法与系统接口。",
                    path.isEmpty() ? "内存映射检出 " + fw + " 模块" : "内存映射检出 " + fw + "：" + path,
                    "hook:maps_fw:" + fw + ":" + path);
        }
        if (detail.startsWith("frida_dbus_port:")) {
            String port = detail.substring("frida_dbus_port:".length());
            return risk("检测到 Frida D-Bus 控制端口", "网络探测",
                    "127.0.0.1:" + port + "（D-Bus AUTH 握手）",
                    "向本地回环端口 " + port + " 发送 D-Bus 握手后收到 Frida 特征 REJECT 响应",
                    "确认设备本地正运行着 Frida 注入服务（即使服务进程已改名），可随时对当前应用发起动态 Hook 攻击。",
                    "端口 127.0.0.1:" + port + " 响应 Frida D-Bus 握手",
                    "hook:frida_dbus:" + port);
        }
        if (detail.startsWith("frida_port_open:")) {
            String port = detail.substring("frida_port_open:".length());
            return risk("Frida 默认通信端口处于监听状态", "网络探测",
                    "/proc/net/tcp（127.0.0.1:" + port + "）",
                    "本地回环端口 " + port + " 处于 TCP LISTEN 监听状态",
                    "27042 为 frida-server 默认监听端口，提示设备可能正在运行远程注入服务。",
                    "本地端口 " + port + " 处于监听状态",
                    "hook:frida_port:" + port);
        }
        if (detail.startsWith("frida_thread:") || detail.startsWith("thread:")) {
            String threadName = detail.substring(detail.indexOf(':') + 1);
            String tag = detail.startsWith("thread:") ? "Native 层" : "Java 层";
            return risk("检出 Frida 特征工作线程", tag,
                    "/proc/self/task/*/comm → " + threadName,
                    "在当前进程线程列表中检出 Frida 运行时线程：" + threadName,
                    "Frida 注入引擎已在当前进程内创建后台脚本/事件循环线程，进程正处于动态插桩监控中。",
                    "检出 Frida 特征线程：" + threadName,
                    "hook:thread:" + threadName);
        }
        if (detail.startsWith("frida_pid:")) {
            String pid = detail.substring("frida_pid:".length());
            return risk("后台存在活跃 Frida 进程", "进程检查",
                    "/proc/" + pid + "（frida-server / frida_helper）",
                    "检出正在运行的 Frida 守护进程（PID " + pid + "）",
                    "系统后台存在活跃的 Frida 服务端，可随时向当前进程注入脚本并窃取敏感数据。",
                    "发现 Frida 进程（PID " + pid + "）",
                    "hook:frida_pid:" + pid);
        }
        if (detail.startsWith("frida_pid_port:")) {
            String port = detail.substring("frida_pid_port:".length());
            return risk("Frida 进程已开放监听端口", "进程与端口",
                    "Frida 守护进程本地监听端口 127.0.0.1:" + port,
                    "已关联确认 Frida 进程正在监听本地 TCP 端口 " + port,
                    "Frida 远程控制通道已就绪，攻击者可通过该端口执行动态 Hook、内存读取及逻辑绕过。",
                    "Frida 进程监听端口 " + port,
                    "hook:frida_pid_port:" + port);
        }
        if (detail.startsWith("unix_socket:")) {
            String marker = detail.substring("unix_socket:".length());
            return risk("检出 Frida Unix 域通信套接字", "Native 层",
                    "/proc/net/unix（" + marker + "）",
                    "在系统 Unix 域套接字表中检出 Frida / Gum 进程间通信管道标识",
                    "表明设备中存在活跃的 Frida 通信通道，进程存在被动态注入与劫持的风险。",
                    "/proc/net/unix 检出 " + marker + " 套接字",
                    "hook:unix:" + marker);
        }
        if (detail.startsWith("loader_chain_deep:")) {
            String depth = detail.substring("loader_chain_deep:".length());
            return risk("类加载器继承链异常偏深", "ART 运行时",
                    "应用 ClassLoader 继承链",
                    "类加载器链达到 " + depth + " 层（正常应用通常不超过 3 层）",
                    "外层额外嵌套的自定义类加载器常用于插件框架、双开容器或代码注入环境，可能拦截类加载过程。",
                    "类加载器链异常偏深（" + depth + " 层）",
                    "hook:loader_deep");
        }
        if (detail.startsWith("loader_unexpected:")) {
            String cls = detail.substring("loader_unexpected:".length());
            return risk("检出非标准类加载器", "ART 运行时",
                    "应用 ClassLoader 继承链 → " + cls,
                    "检出非 Android 标准系统实现的自定义类加载器：" + cls,
                    "非预期类加载器可能来自 Hook 框架或第三方代理容器，存在替换应用字节码或监控调用的风险。",
                    "检出非预期类加载器：" + cls,
                    "hook:loader_unexpected:" + cls);
        }
        if (detail.startsWith("anon_exec:")) {
            String perms = detail.substring("anon_exec:".length());
            return risk("匿名可执行内存区域", "Native 层",
                    "/proc/self/maps（无文件路径匿名段，权限 " + perms + "）",
                    "检出未关联磁盘文件的匿名可执行内存页（" + perms + "）",
                    "可能存在动态释放的原生载荷或内存注入代码（部分加壳/JIT 场景亦可能产生，属上下文参考信号）。",
                    "检出匿名可执行内存（" + perms + "）",
                    "hook:anon_exec:" + perms);
        }

        // ---- ADB Detection ----
        if (detail.equals("settings_adb_enabled")) {
            return risk("USB 调试开关已开启", "系统设置",
                    "Settings.Global.adb_enabled",
                    "读取到系统设置 adb_enabled = 1",
                    "设备已开启 USB 调试模式，连接外部主机后可通过 ADB 执行 Shell 命令、拉取日志或附加调试。",
                    "USB 调试已开启（adb_enabled=1）",
                    "adb:usb");
        }
        if (detail.equals("settings_adb_wifi_enabled")) {
            return risk("无线 ADB 调试已开启", "系统设置",
                    "Settings.Global.adb_wifi_enabled",
                    "读取到系统设置 adb_wifi_enabled = 1",
                    "设备已开启无线调试，同一局域网下的主机可能远程建立 ADB 连接，执行自动化脚本或控制设备。",
                    "无线 ADB 调试已开启",
                    "adb:wifi");
        }
        if (detail.startsWith("adb_tcp_port:")) {
            String port = detail.substring("adb_tcp_port:".length());
            return risk("ADB 网络调试端口已开启", "系统属性",
                    "service.adb.tcp.port / persist.adb.tcp.port",
                    "ADB TCP 网络调试端口被配置为 " + port,
                    "adbd 守护进程可通过网络 TCP 端口接受远程接入，存在被群控或远程静默调试的高风险。",
                    "ADB TCP 端口已配置为 " + port,
                    "adb:tcp:" + port);
        }
        if (detail.startsWith("adbd_process:")) {
            String pid = detail.substring("adbd_process:".length());
            return risk("adbd 调试守护进程运行中", "进程状态",
                    "/proc/" + pid + "（adbd）",
                    "检出系统 ADB 调试守护进程 adbd 正在运行（PID " + pid + "）",
                    "ADB 后台服务处于活跃状态，设备当前具备接受外部 ADB 调试会话的条件。",
                    "adbd 进程运行中（PID " + pid + "）",
                    "adb:adbd_pid");
        }
        if (detail.startsWith("adbd_pid_port:")) {
            String port = detail.substring("adbd_pid_port:".length());
            return risk("adbd 进程监听本地 TCP 端口", "网络端口",
                    "/proc/<adbd>/net/tcp（端口 " + port + "）",
                    "确认 adbd 守护进程正在监听本地 TCP 端口 " + port,
                    "ADB 守护进程已开放网络端口监听，容易被外部主机或群控工具远程连接操控。",
                    "adbd 正在监听 TCP 端口 " + port,
                    "adb:adbd_port:" + port);
        }
        if (detail.equals("usb_function:adb")) {
            return risk("USB 驱动已启用 ADB 功能", "内核节点",
                    "/sys/class/android_usb/android0/functions",
                    "USB 复合设备功能列表中包含 adb 接口",
                    "底层 USB 驱动已开启 ADB 调试通道，设备接入电脑时可直接建立调试控制连接。",
                    "USB 功能节点已启用 adb 接口",
                    "adb:usb_func");
        }
        if (detail.startsWith("usb_state:")) {
            String state = detail.substring("usb_state:".length());
            return risk("ADB USB 接口处于连接/配置状态", "内核节点",
                    "/sys/class/usb_composite/adb/state",
                    "ADB USB 接口状态为 " + state,
                    "设备当前可能正通过 USB 数据线与外部调试主机保持物理连接。",
                    "ADB USB 接口状态：" + state,
                    "adb:usb_state");
        }

        // ---- Debug Mode Detection ----
        if (detail.startsWith("tracer_pid:")) {
            String pid = detail.substring("tracer_pid:".length());
            return risk("进程正在被调试器跟踪", "进程状态",
                    "/proc/self/status（TracerPid 字段）",
                    "读取到 TracerPid = " + pid + "（当前进程正被 PID " + pid + " 通过 ptrace 跟踪）",
                    "外部调试器（如 gdb / lldb / IDA / Frida）已附加到当前进程，攻击者可暂停执行、读取内存明文并修改寄存器或逻辑分支。",
                    "进程正被跟踪（TracerPid: " + pid + "）",
                    "debug:tracer:" + pid);
        }
        if (detail.equals("debuggable_flag")) {
            return risk("应用可调试模式已开启", "应用配置",
                    "ApplicationInfo.flags（FLAG_DEBUGGABLE）",
                    "当前应用清单标记为可调试（android:debuggable=\"true\"）",
                    "允许外部通过 JDWP 附加 Java 调试器或使用 run-as 访问私有数据目录；若正式生产包开启此标记将大幅降低逆向分析成本。",
                    "应用已开启 android:debuggable 标记",
                    "debug:debuggable");
        }
        if (detail.equals("debugger_connected")) {
            return risk("检测到 JDWP 调试器连接", "调试状态",
                    "android.os.Debug（isDebuggerConnected / waitingForDebugger）",
                    "运行时返回调试器已连接或进程正处于等待调试器接入状态",
                    "应用当前正处于主动调试会话中，代码执行逻辑与内存敏感信息可被实时单步查看与篡改。",
                    "检测到 JDWP 调试器已连接",
                    "debug:jdwp");
        }
        if (detail.startsWith("ida_port_open:")) {
            String port = detail.substring("ida_port_open:".length());
            return risk("IDA 远程调试默认端口开启", "网络端口",
                    "/proc/net/tcp（127.0.0.1:" + port + "）",
                    "检出 IDA Pro 远程调试服务默认端口 " + port + " 处于监听状态",
                    "设备本地可能正在运行 IDA android_server 调试服务端，应用存在被逆向分析与动态调试的风险。",
                    "IDA 调试端口 " + port + " 处于监听状态",
                    "debug:ida_port:" + port);
        }
        if (detail.startsWith("maps_exec_path:")) {
            String rest = detail.substring("maps_exec_path:".length());
            int sep = rest.indexOf(':');
            String tool = sep > 0 ? rest.substring(0, sep) : rest;
            String path = sep > 0 ? rest.substring(sep + 1) : "";
            String loc = path.isEmpty() ? "/proc/self/maps" : "/proc/self/maps → " + path;
            return risk("内存映射检出调试工具模块", "内存映射", loc,
                    path.isEmpty()
                            ? "进程可执行内存映射中检出调试工具特征：" + tool
                            : "进程可执行映射加载了调试工具模块（" + tool + "）：" + path,
                    "逆向调试代理组件已出现在进程地址空间中，应用运行逻辑面临被动态分析与篡改风险。",
                    "内存映射检出调试工具：" + tool,
                    "debug:maps_exec:" + tool + ":" + path);
        }

        // ---- Emulator Detection ----
        if (detail.startsWith("qemu_pipe:")) {
            String path = detail.substring("qemu_pipe:".length());
            return risk("检出 QEMU 宿主机通信管道", "Native 层", path,
                    "在设备节点中检出 QEMU / Goldfish 宿主机通信管道文件",
                    "该虚拟通道仅存在于 Android 模拟器与宿主机之间，属于高置信度的模拟器硬件虚拟化证据。",
                    "检出 QEMU 管道：" + path,
                    "emu:pipe:" + path);
        }
        if (detail.startsWith("emu_file:")) {
            String path = detail.substring("emu_file:".length());
            return risk("检出模拟器专属特征文件", "Native 层", path,
                    "在文件系统中检出已知模拟器专属配置文件、驱动或组件",
                    "设备运行在 PC 模拟器（如雷电 / 夜神 / MuMu / 蓝叠 / Redroid 等）中，常见于自动化脚本与批量黑灰产环境。",
                    "检出模拟器文件：" + path,
                    "emu:file:" + path);
        }
        if (detail.startsWith("emu_pkg:")) {
            String pkg = detail.substring("emu_pkg:".length());
            return risk("检出模拟器专属应用包", "应用列表",
                    "PackageManager → " + pkg,
                    "设备已安装模拟器内置桌面、框架或辅助服务包：" + pkg,
                    "表明当前设备高度疑似 PC 模拟器实例，非正常真实移动终端。",
                    "检出模拟器应用：" + pkg,
                    "emu:pkg:" + pkg);
        }
        if (detail.startsWith("qemu_prop:")) {
            String prop = detail.substring("qemu_prop:".length());
            return risk("系统属性暴露 QEMU 虚拟化标记", "系统属性",
                    "系统属性 " + prop,
                    "读取到虚拟化/模拟器系统属性生效（" + prop + "）",
                    "系统底层属性明确声明当前运行在 QEMU 或虚拟化镜像上，属于高置信度模拟器信号。",
                    "模拟器系统属性生效：" + prop,
                    "emu:qemu_prop:" + prop);
        }
        if (detail.startsWith("virtual_gpu:")) {
            String rest = detail.substring("virtual_gpu:".length());
            int sep = rest.indexOf(':');
            String marker = sep > 0 ? rest.substring(0, sep) : rest;
            String renderer = sep > 0 ? rest.substring(sep + 1) : "";
            return risk("GPU 为虚拟化/软件渲染器", "图形硬件",
                    "OpenGL ES / EGL GPU 渲染器信息",
                    renderer.isEmpty()
                            ? "GPU 厂商或渲染器命中虚拟化特征：" + marker
                            : "GPU 渲染器为 " + renderer + "（命中虚拟化特征：" + marker + "）",
                    "真实量产手机均使用硬件移动 GPU（如 Adreno / Mali），软件或虚拟化 GPU 是模拟器与云手机的强特征。",
                    "GPU 命中虚拟化特征：" + marker,
                    "emu:vgpu:" + marker);
        }
        if (detail.equals("cpu:hypervisor")) {
            return risk("CPU 信息包含虚拟化特征", "硬件信息",
                    "/proc/cpuinfo",
                    "CPU 硬件描述中检出 hypervisor / qemu / ranchu / goldfish 关键字",
                    "处理器运行在宿主机虚拟化管理程序之上，非真实移动芯片硬件。",
                    "/proc/cpuinfo 检出虚拟化特征",
                    "emu:cpu_hv");
        }
        if (detail.startsWith("runtime_arch:")) {
            String arch = detail.substring("runtime_arch:".length());
            return risk("运行架构为桌面级 x86 指令集", "Native 层",
                    "进程运行时 CPU 架构 / uname",
                    "检出当前运行架构为 " + arch + "（非主流移动 ARM 架构）",
                    "x86 / x86_64 指令集常见于运行在 PC 主机上的 Android 模拟器环境。",
                    "运行架构为 " + arch,
                    "emu:arch:" + arch);
        }
        if (detail.startsWith("fingerprint:") || detail.startsWith("generic_fingerprint:")) {
            String val = detail.substring(detail.indexOf(':') + 1);
            boolean generic = detail.startsWith("generic_fingerprint:");
            return risk(generic ? "构建指纹为通用/模拟器格式" : "构建指纹命中模拟器特征", "系统构建",
                    "android.os.Build.FINGERPRINT",
                    "构建指纹为：" + val,
                    "量产真机使用厂商定制构建指纹，通用或包含 vbox/emulator 的指纹常见于模拟器与虚拟镜像。",
                    "Build.FINGERPRINT 含模拟器特征",
                    "emu:fp:" + val);
        }
        if (detail.startsWith("model:") || detail.startsWith("manufacturer:")
                || detail.startsWith("product:") || detail.startsWith("hardware:")
                || detail.startsWith("board:")) {
            int sep = detail.indexOf(':');
            String fieldKey = detail.substring(0, sep).toUpperCase(Locale.ROOT);
            String val = detail.substring(sep + 1);
            return risk("系统构建参数命中模拟器标识", "系统构建",
                    "android.os.Build." + fieldKey,
                    "Build." + fieldKey + " = " + val,
                    "设备构建标识包含已知模拟器平台关键字（如 ranchu / goldfish / sdk / Genymotion / Nox），属于虚拟模拟环境。",
                    "Build." + fieldKey + " 命中模拟器特征：" + val,
                    "emu:build:" + fieldKey);
        }
        if (detail.equals("disk_small")) {
            return risk("用户数据分区容量异常偏小", "存储硬件",
                    "/data 分区（statfs 容量探测）",
                    "/data 分区总容量小于 4 GB",
                    "现代实体手机存储容量远高于 4 GB，极小分区容量常见于精简模拟器或轻量虚拟容器。",
                    "/data 分区容量小于 4 GB",
                    "emu:disk_small");
        }
        if (detail.equals("screen_stock")) {
            return risk("屏幕参数匹配默认模拟器预设", "显示参数",
                    "WindowManager / DisplayMetrics",
                    "屏幕分辨率与像素密度组合命中常见模拟器默认配置（如 720p/1080p + 160/240dpi）",
                    "标准虚拟分辨率与等比 DPI 是模拟器的典型辅助特征。",
                    "屏幕参数接近默认模拟器预设",
                    "emu:screen_stock");
        }
        if (detail.equals("no_thermal_zones")) {
            return risk("缺失硬件温度传感器节点", "内核节点",
                    "/sys/class/thermal/thermal_zone*",
                    "未检出任何芯片/电池温度监控节点（数量为 0）",
                    "实体物理手机均配备多个硬件温控传感器，完全缺失是模拟器及虚拟化环境的常见特征。",
                    "未检出硬件温度传感器节点",
                    "emu:no_thermal");
        }
        if (detail.startsWith("low_sensor_count:") || detail.startsWith("very_low_sensor_count:")) {
            String count = detail.substring(detail.indexOf(':') + 1);
            return risk("硬件传感器数量异常偏少", "传感器硬件",
                    "SensorManager.getSensorList(TYPE_ALL)",
                    "设备仅检出 " + count + " 个可用硬件传感器",
                    "实体手机通常配备十余种物理传感器，传感器严重缺失高度疑似模拟器或云端虚拟手机。",
                    "可用硬件传感器仅 " + count + " 个",
                    "emu:low_sensor:" + count);
        }
        if (detail.startsWith("aosp_sensor_vendor:")) {
            String sensorName = detail.substring("aosp_sensor_vendor:".length());
            return risk("传感器由 AOSP 虚拟驱动提供", "传感器硬件",
                    "SensorManager → " + sensorName,
                    "传感器「" + sensorName + "」的厂商标识为 AOSP 默认模拟实现",
                    "真机传感器由实体芯片厂商提供驱动，AOSP 虚拟厂商常见于 Android 模拟器镜像。",
                    "检出 AOSP 模拟传感器：" + sensorName,
                    "emu:aosp_sensor:" + sensorName);
        }
        if (detail.startsWith("missing_feature:")) {
            String feat = detail.substring("missing_feature:".length());
            return risk("硬件特性与基带描述矛盾", "硬件能力",
                    "PackageManager 特性声明 vs Build.getRadioVersion()",
                    "系统存在基带版本号但未声明 " + feat + " 硬件能力",
                    "硬件能力声明与底层基带信息不一致，常见于配置不完整的模拟器或改机系统。",
                    "缺失硬件特性声明：" + feat,
                    "emu:missing_feat:" + feat);
        }
        if (detail.startsWith("emulator_ip:")) {
            String ip = detail.substring("emulator_ip:".length());
            return risk("网卡分配模拟器默认 NAT 地址", "网络接口",
                    "NetworkInterface IPv4 地址 → " + ip,
                    "本机网卡分配了 Android QEMU 模拟器默认私有网段地址 " + ip,
                    "10.0.2.15/16 为 Android 官方模拟器默认虚拟网卡 IP，提示处于模拟器网络环境。",
                    "检出模拟器默认 IP：" + ip,
                    "emu:ip:" + ip);
        }
        if (detail.startsWith("cgroup:")) {
            String kw = detail.substring("cgroup:".length());
            return risk("控制组路径检出容器化标识", "进程环境",
                    "/proc/1/cgroup / /proc/self/cgroup",
                    "进程 cgroup 控制组信息中检出容器特征关键字：" + kw,
                    "进程运行在 Docker / LXC / Kubernetes 等容器环境中，属于云端托管或虚拟化设备。",
                    "cgroup 检出容器特征：" + kw,
                    "emu:cgroup:" + kw);
        }
        if (detail.equals("cmdline_mismatch")) {
            return risk("进程命令行与应用包名不匹配", "进程环境",
                    "/proc/self/cmdline",
                    "读取到的进程命令行名称不包含当前应用包名",
                    "应用进程可能由第三方虚拟容器或宿主机代理启动，运行隔离边界存在异常。",
                    "/proc/self/cmdline 与包名不一致",
                    "emu:cmdline_mismatch");
        }

        // ---- Cloud Phone Detection ----
        if (detail.startsWith("cloud_pkg:")) {
            String pkg = detail.substring("cloud_pkg:".length());
            return risk("检出云手机平台应用", "应用列表",
                    "PackageManager → " + pkg,
                    "设备已安装云手机服务商客户端或托管代理组件：" + pkg,
                    "设备属于云手机或托管虚拟真机平台，常被用于自动化脚本、群控养号及黑产作弊场景。",
                    "检出云手机应用：" + pkg,
                    "cloud:pkg:" + pkg);
        }
        if (detail.startsWith("cloud_prop:")) {
            String kv = detail.substring("cloud_prop:".length());
            int eq = kv.indexOf('=');
            String prop = eq > 0 ? kv.substring(0, eq) : kv;
            String val = eq > 0 ? kv.substring(eq + 1) : "";
            return risk("检出云手机厂商系统属性", "系统属性",
                    "系统属性 " + prop,
                    val.isEmpty() ? "系统属性 " + prop + " 存在取值" : prop + " = " + val,
                    "该专属系统属性由云手机服务商镜像注入，确认当前运行环境为云端托管手机实例。",
                    "检出云手机属性：" + prop,
                    "cloud:prop:" + prop);
        }
        if (detail.startsWith("wired_interface:")) {
            String iface = detail.substring("wired_interface:".length());
            return risk("检出有线以太网网卡", "网络接口",
                    "/sys/class/net/" + iface,
                    "设备存在有线以太网网络接口：" + iface,
                    "机房托管云手机通常通过虚拟以太网 ethN 联网（实体机外接 USB-C 扩展坞亦可出现，属弱参考信号）。",
                    "检出有线网卡接口：" + iface,
                    "cloud:eth:" + iface);
        }
        if (detail.startsWith("battery_zero:")) {
            String kv = detail.substring("battery_zero:".length());
            return risk("电池硬件传感器读数为零", "电源硬件",
                    "系统电池广播（ACTION_BATTERY_CHANGED）",
                    "电池电压或温度返回 0（" + kv + "）",
                    "云手机或去除电池直供电的机房群控主板常缺失真实电池管理芯片，导致电池读数恒为零。",
                    "电池电压或温度读数为零（" + kv + "）",
                    "cloud:battery_zero");
        }
        if (detail.startsWith("battery_anomaly:")) {
            String val = detail.substring("battery_anomaly:".length());
            return risk("电池充电状态自相矛盾", "电源硬件",
                    "系统电池广播（ACTION_BATTERY_CHANGED）",
                    "电量显示 100% 且处于充电中，但未接入任何电源适配器（" + val + "）",
                    "典型的云真机或直供电改造设备电池模拟异常特征。",
                    "电池状态异常（满电充电但未接电源）",
                    "cloud:battery_anomaly");
        }
        if (detail.startsWith("low_camera_count:")) {
            String count = detail.substring("low_camera_count:".length());
            return risk("缺失物理摄像头硬件", "相机硬件",
                    "CameraManager / PackageManager",
                    "设备可用摄像头数量为 " + count,
                    "实体手机普遍配备前后摄像头，无摄像头硬件是云手机与机房托管实例的典型特征。",
                    "设备可用摄像头数量为 " + count,
                    "cloud:camera:" + count);
        }

        // ---- Custom ROM Detection ----
        if (detail.startsWith("community_rom:")) {
            String kv = detail.substring("community_rom:".length());
            int eq = kv.indexOf('=');
            String romName = eq > 0 ? kv.substring(0, eq) : kv;
            String ver = eq > 0 ? kv.substring(eq + 1) : "";
            return risk("检出第三方社区 ROM", "系统属性",
                    "社区 ROM 版本系统属性（" + romName + "）",
                    ver.isEmpty() ? "命中第三方社区 ROM：" + romName : "命中 " + romName + " 系统，版本：" + ver,
                    "设备刷入了非原厂官方系统镜像，社区 ROM 常默认开放高权限接口或放宽安全限制（仅作环境提示）。",
                    "检出社区 ROM：" + romName,
                    "rom:community:" + romName);
        }
        if (detail.equals("prop_mismatch:fingerprint")) {
            return risk("系统指纹内存值与磁盘文件不一致", "系统属性",
                    "/system/build.prop vs 系统属性 ro.build.fingerprint",
                    "磁盘 /system/build.prop 中的构建指纹与运行时系统属性值不一致",
                    "运行时系统指纹可能被 resetprop 等改机工具动态覆写，用于伪造设备型号或逃避风控识别。",
                    "ro.build.fingerprint 与 /system/build.prop 不一致",
                    "rom:prop_mismatch_fp");
        }

        // ---- Consistency (系统信息防篡改) ----
        if (detail.equals("partition_fingerprint_mismatch:build_vs_system")) {
            return risk("主构建指纹与 system 分区指纹不一致", "属性校验",
                    "ro.build.fingerprint vs ro.system.build.fingerprint",
                    "主构建指纹与 system 分区构建指纹取值不相同",
                    "两项属性在正常系统中应当一致，出现偏差高度疑似使用 resetprop 局部篡改了设备系统指纹。",
                    "ro.build.fingerprint 与 system 分区指纹冲突",
                    "cons:part_fp_sys");
        }
        if (detail.startsWith("partition_fingerprint_mismatch:brand_conflict=")) {
            String brands = detail.substring("partition_fingerprint_mismatch:brand_conflict=".length());
            return risk("系统各分区品牌标识冲突", "属性校验",
                    "各分区指纹（ro.*.build.fingerprint）",
                    "不同系统分区声明的品牌前缀不一致：" + brands,
                    "跨品牌冲突是改机工具仅修改部分分区指纹导致的典型破绽，设备身份极可能已被伪造。",
                    "系统分区品牌前缀冲突：" + brands,
                    "cons:part_brand");
        }
        if (detail.equals("partition_keytype_mismatch")) {
            return risk("系统分区混用测试与量产签名", "属性校验",
                    "各分区指纹（ro.*.build.fingerprint）",
                    "不同系统分区同时出现 release-keys 与 test-keys/dev-keys 标签",
                    "系统部分分区可能被非官方镜像替换或重签名，系统镜像完整性存在异常。",
                    "不同系统分区签名密钥类型不一致",
                    "cons:part_keytype");
        }
        if (detail.startsWith("build_prop_mismatch:")) {
            String prop = detail.substring("build_prop_mismatch:".length());
            return risk("Java Build 字段与原生属性不一致", "跨层校验",
                    "android.os.Build vs 原生属性 " + prop,
                    "Java 层 Build 常量值与 Native 层读取的 " + prop + " 不一致",
                    "Java 层设备信息疑似被 Hook 框架或改机模块劫持伪造，试图绕过设备指纹与机型识别。",
                    "Build 字段与原生属性 " + prop + " 冲突",
                    "cons:build_prop:" + prop);
        }
        if (detail.startsWith("core_count_mismatch:")) {
            String kv = detail.substring("core_count_mismatch:".length());
            return risk("CPU 核心数多源读数矛盾", "硬件校验",
                    "Runtime / /proc/cpuinfo / /sys/devices/system/cpu/possible",
                    "不同途径读取的 CPU 核心数出现物理矛盾（" + kv + "）",
                    "逻辑核心数超过硬件物理上限，表明 CPU 硬件参数被改机或虚拟化层伪造篡改。",
                    "CPU 核心数多源读数矛盾（" + kv + "）",
                    "cons:core_count");
        }
        if (detail.startsWith("abi_arch_mismatch:")) {
            String kv = detail.substring("abi_arch_mismatch:".length());
            return risk("CPU ABI 与运行架构不匹配", "架构校验",
                    "Build.SUPPORTED_ABIS vs JVM os.arch",
                    "系统声明的 CPU ABI 与实际运行指令集架构矛盾（" + kv + "）",
                    "设备架构属性可能被人为伪造（例如 x86 模拟器伪装 ARM 架构），运行环境不可信。",
                    "ABI 与实际架构不匹配（" + kv + "）",
                    "cons:abi_arch");
        }
        if (detail.startsWith("abi_64bit_mismatch:")) {
            String kv = detail.substring("abi_64bit_mismatch:".length());
            return risk("64 位 ABI 声明自相矛盾", "架构校验",
                    "Build.SUPPORTED_ABIS vs SUPPORTED_64_BIT_ABIS",
                    "主 ABI 声明为 64 位架构，但 64 位 ABI 列表为空（" + kv + "）",
                    "设备架构配置存在明显矛盾，疑似被改机工具不完整地改写了 Build 字段。",
                    "64 位 ABI 声明不一致（" + kv + "）",
                    "cons:abi_64");
        }
        if (detail.startsWith("api_release_mismatch:")) {
            String kv = detail.substring("api_release_mismatch:".length());
            return risk("Android 版本号与 API 等级不匹配", "版本校验",
                    "Build.VERSION.SDK_INT vs Build.VERSION.RELEASE",
                    "系统 API 等级与 Android 大版本号对应关系异常（" + kv + "）",
                    "系统版本参数存在人为伪造痕迹，可能用于规避基于系统版本的风控策略。",
                    "API 等级与系统版本不匹配（" + kv + "）",
                    "cons:api_release");
        }
        if (detail.startsWith("fingerprint_malformed:")) {
            String val = detail.substring("fingerprint_malformed:".length());
            return risk("构建指纹格式不合规", "属性校验",
                    "android.os.Build.FINGERPRINT",
                    "构建指纹不符合标准 brand/product/device:version/id:type/tags 格式：" + val,
                    "正规量产系统指纹严格遵循 AOSP 格式规范，异常格式常由改机脚本错误覆写导致。",
                    "Build.FINGERPRINT 格式异常",
                    "cons:fp_malformed");
        }
        if (detail.startsWith("fingerprint_brand_mismatch:")) {
            String val = detail.substring("fingerprint_brand_mismatch:".length());
            return risk("构建指纹品牌与 Build.BRAND 冲突", "属性校验",
                    "Build.FINGERPRINT vs Build.BRAND",
                    "构建指纹品牌前缀与 Build.BRAND 不一致（" + val + "）",
                    "设备品牌信息存在局部篡改，疑似改机工具仅修改了部分设备字段。",
                    "构建指纹品牌前缀与 Build.BRAND 不一致",
                    "cons:fp_brand");
        }
        if (detail.startsWith("verified_boot_state:")) {
            String state = detail.substring("verified_boot_state:".length());
            return risk("Verified Boot 启动校验异常", "启动链校验",
                    "ro.boot.verifiedbootstate / /proc/cmdline",
                    "Verified Boot 启动验证状态为 " + state + "（正常量产锁定设备应为 green）",
                    "系统启动链未通过完整官方签名验证，说明 Bootloader 已解锁或引导/系统分区被刷入非官方镜像。",
                    "Verified Boot 状态异常：" + state,
                    "cons:vb_state:" + state);
        }
        if (detail.equals("bootloader_unlocked")) {
            return risk("Bootloader 已解锁", "启动链校验",
                    "ro.boot.flash.locked / /proc/cmdline",
                    "Bootloader 锁定状态值为 0（已处于解锁状态）",
                    "设备允许刷入未签名内核、Recovery 或 Root 镜像，硬件级信任根（Root of Trust）保护已失效。",
                    "设备 Bootloader 已解锁",
                    "cons:bl_unlocked");
        }
        if (detail.startsWith("cmdline_prop_mismatch:")) {
            String field = detail.substring("cmdline_prop_mismatch:".length());
            return risk("内核启动参数与系统属性矛盾", "启动链校验",
                    "/proc/cmdline vs 系统属性 ro.boot." + field,
                    "内核启动命令行参数 androidboot." + field + " 与运行时属性取值不一致",
                    "高度疑似使用 resetprop 伪造 Verified Boot / Bootloader 锁定状态，以向风控隐藏解锁或篡改事实。",
                    "/proc/cmdline 与 ro.boot." + field + " 不一致",
                    "cons:cmdline:" + field);
        }
        if (detail.equals("kernel_dirty_on_release")) {
            return risk("量产系统运行自编译 -dirty 内核", "内核校验",
                    "uname.release vs Build.TAGS",
                    "系统签名标签为 release-keys，但内核版本号包含 -dirty 后缀",
                    "厂商量产系统不会分发带 -dirty 标记的内核，说明设备可能刷入了包含 KernelSU 或修改后的自定义内核。",
                    "量产签名系统运行了 -dirty 自定义内核",
                    "cons:kernel_dirty");
        }

        // ---- Multi-source, Correlation & Continuity ----
        if (detail.startsWith("inconsistent_fields:")) {
            String fields = detail.substring("inconsistent_fields:".length());
            return risk("多来源采集数据不一致", "交叉校验",
                    "冲突字段：" + fields,
                    "同一设备属性通过不同采集通道读取时返回了不一致的取值",
                    "部分采集 API 可能被 Hook 劫持返回了伪造数据，设备真实标识存在篡改风险。",
                    "多源字段冲突：" + fields,
                    "multi:inconsistent:" + fields);
        }
        if (detail.startsWith("C1:")) {
            return risk("模拟器弱特征与虚拟化交叉印证", "交叉规则",
                    "规则 C1（模拟器检测多信号联动）",
                    "弱模拟器特征与虚拟化 CPU / QEMU / x86 特征同时命中",
                    "多维度虚拟化信号相互印证，显著提高当前设备为模拟器的置信度。",
                    "弱模拟器信号与虚拟化特征同时出现",
                    "corr:c1");
        }
        if (detail.startsWith("C2:")) {
            return risk("模拟器强特征与虚拟化双重确认", "交叉规则",
                    "规则 C2（模拟器检测多信号联动）",
                    "模拟器强特征与底层虚拟化特征形成双重确认",
                    "高置信度确认为模拟器虚拟环境，建议限制高风险业务操作。",
                    "模拟器强信号与虚拟化特征交叉印证",
                    "corr:c2");
        }
        if (detail.startsWith("C3:")) {
            return risk("活跃 Frida 函数劫持攻击", "交叉规则",
                    "规则 C3（注入与 Hook 信号联动）",
                    "系统底层函数被 Inline/GOT Hook 且同时检出 Frida 运行痕迹",
                    "确认当前进程正遭受活跃的 Frida 动态函数劫持，存在极高的敏感数据泄露与风控绕过风险。",
                    "函数被 Hook 且存在 Frida 痕迹",
                    "corr:c3");
        }
        if (detail.startsWith("C4:")) {
            return risk("高危隐蔽型 Root 对抗环境", "交叉规则",
                    "规则 C4（ROOT检测 + 挂载完整性联动）",
                    "同时检出系统调用访问矛盾（syscall_mismatch）与 Root 模块挂载",
                    "设备不仅具备 Root 权限，还启用了针对性的反检测隐藏措施，属于高危对抗环境。",
                    "Root 路径访问存在交叉隐藏",
                    "corr:c4");
        }
        if (detail.startsWith("C5:")) {
            return risk("疑似 resetprop 动态改写系统指纹", "交叉规则",
                    "规则 C5（第三方 ROM + 属性比对联动）",
                    "非社区 ROM 且非模拟器设备上出现构建指纹磁盘与内存不一致",
                    "设备极可能通过 resetprop 运行时改写了系统指纹以伪装设备身份。",
                    "系统指纹疑似被运行时改写",
                    "corr:c5");
        }
        if (detail.startsWith("C7:")) {
            return risk("敏感场景云手机弱信号聚集", "交叉规则",
                    "规则 C7（云手机特征多维聚合）",
                    "在登录/支付等敏感场景下同时命中多项云手机硬件异常信号",
                    "多项硬件缺失与异常特征叠加，高度疑似云手机或机房群控设备。",
                    "多项云真机弱特征同时出现",
                    "corr:c7");
        }
        if (detail.equals("hardware_layer_changed_between_observations")) {
            return risk("设备硬件层指纹发生突变", "指纹连续性",
                    "本地设备指纹连续性存储",
                    "本次采集与历史记录相比，设备硬件层指纹摘要发生改变",
                    "真实物理设备的硬件层属性通常保持稳定，突变高度疑似使用了改机工具重置设备身份。",
                    "设备硬件层指纹在两次采集间发生突变",
                    "cont:hw_changed");
        }
        if (detail.startsWith("changed_buckets:")) {
            String buckets = detail.substring("changed_buckets:".length());
            return risk("设备指纹变化维度", "指纹连续性",
                    "本地设备指纹连续性比对",
                    "发生变化的硬件指纹分组：" + buckets,
                    "上述硬件特征分组较历史观测值发生变更，需关注是否存在动态改机伪造行为。",
                    "发生变化的指纹维度：" + buckets,
                    "cont:buckets:" + buckets);
        }

        // ---- Fallback ----
        int sep = detail.indexOf(':');
        if (sep > 0 && sep < detail.length() - 1) {
            String key = detail.substring(0, sep).replace('_', ' ');
            String val = detail.substring(sep + 1);
            return risk("检出异常环境信号", layerTag, key,
                    "检出特征值：" + val,
                    "该信号与正常真机运行环境存在偏差，建议结合其他安全检测项综合评估风险。",
                    key + "：" + val,
                    null);
        }
        String clean = detail.replace('_', ' ');
        return risk("检出异常环境信号", layerTag, "运行环境检测项",
                "检出特征：" + clean,
                "该信号与正常真机运行环境存在偏差，建议结合其他安全检测项综合评估风险。",
                clean,
                null);
    }

    private static EvidenceDetail risk(String title, String sourceTag, String location,
                                       String content, String risk, String inlineSummary,
                                       String mergeKey) {
        return new EvidenceDetail(title, sourceTag, location, content, risk, inlineSummary, false, mergeKey);
    }

    private static EvidenceDetail diag(String title, String sourceTag, String location,
                                       String content, String inlineSummary) {
        return new EvidenceDetail(title, sourceTag, location, content, "", inlineSummary, true,
                "diag:" + title);
    }

    private static String extractMapsDetailPath(String detail, String prefixA, String prefixB) {
        if (detail.startsWith(prefixA + ":")) {
            return detail.substring(prefixA.length() + 1).trim();
        }
        if (detail.startsWith(prefixB + ":")) {
            return detail.substring(prefixB.length() + 1).trim();
        }
        return "";
    }

    private FailureDetail parseFailureDetail(String raw) {
        String normalized = raw.trim();
        if (normalized.startsWith("unavailable:")) {
            normalized = normalized.substring("unavailable:".length());
        }
        if (normalized.startsWith("detection_unavailable:")) {
            normalized = normalized.substring("detection_unavailable:".length());
        }
        int sep = normalized.indexOf(':');
        if (sep > 0 && sep < normalized.length() - 1) {
            String prefix = normalized.substring(0, sep);
            String reason = normalized.substring(sep + 1);
            return new FailureDetail(humanizeFailureTarget(prefix), humanizeFailureReason(reason));
        }
        return new FailureDetail("子检查执行受限", humanizeFailureReason(normalized));
    }

    private String humanizeFailureTarget(String prefix) {
        switch (prefix) {
            case "selinux": return "SELinux 状态读取（/sys/fs/selinux/enforce）";
            case "native_root": return "Native 层 Root 探测";
            case "su_paths": return "su 文件路径扫描";
            case "magisk_paths": return "Magisk 路径扫描";
            case "ksu_paths": return "KernelSU 路径扫描";
            case "apatch_paths": return "APatch 路径扫描";
            case "module_paths": return "Root 模块目录扫描";
            case "build_tags": return "Build.TAGS 读取";
            case "proc_mounts_unavailable": return "/proc/mounts 读取";
            case "proc_mountinfo_unavailable": return "/proc/self/mountinfo 读取";
            case "xposed_class": return "Xposed 类加载检查";
            case "xposed_stack": return "线程调用栈检查";
            case "frida_maps": return "/proc/self/maps 扫描";
            case "frida_ports": return "本地回环监听端口检查";
            case "frida_threads": return "/proc/self/task 线程列表扫描";
            case "frida_processes": return "进程列表关联检查";
            case "native_hook": return "Native 层 Hook 检测";
            case "monitor": return "后台完整性巡检";
            case "settings_adb": return "Settings.Global.adb_enabled 读取";
            case "settings_adb_wifi": return "Settings.Global.adb_wifi_enabled 读取";
            case "adb_properties": return "ADB TCP 端口系统属性读取";
            case "tracer_pid": return "/proc/self/status TracerPid 读取";
            case "debuggable": return "ApplicationInfo.flags 检查";
            case "ida_port": return "IDA 默认调试端口检查";
            case "debugger_connection": return "JDWP 调试器状态检查";
            case "maps_exec_path": return "/proc/self/maps 可执行段检查";
            case "qemu_props": return "QEMU 系统属性检查";
            case "hardware_features": return "硬件能力与基带检查";
            case "emulator_files": return "模拟器特征文件探测";
            case "thermal_zones": return "温度传感器节点探测";
            case "runtime_arch": return "运行架构探测";
            case "cpu_info": return "/proc/cpuinfo 读取";
            case "disk_size": return "/data 存储容量探测";
            case "kernel_info": return "内核版本信息读取";
            case "screen": return "屏幕显示参数读取";
            case "sensors": return "系统传感器列表读取";
            case "network_interfaces": return "本机网络接口检查";
            case "emulator_packages": return "模拟器应用包检查";
            case "container_signals": return "容器环境信号检查";
            case "gpu_identity": return "EGL GPU 渲染器探测";
            case "build_characteristics": return "ro.build.characteristics 读取";
            case "net_iface": return "有线网络接口检查";
            case "partition_fingerprints": return "各系统分区指纹比对";
            case "build_props": return "Build 与原生属性比对";
            case "core_count": return "CPU 核心数一致性校验";
            case "abi_arch": return "ABI 与架构一致性校验";
            case "api_release": return "API 等级与版本一致性校验";
            case "fingerprint_shape": return "构建指纹格式校验";
            case "verified_boot": return "Verified Boot 启动链校验";
            case "kernel_release": return "内核版本标签校验";
            default: return prefix.replace('_', ' ');
        }
    }

    private boolean isInternalExecutionToken(String detail) {
        return detail.startsWith("unavailable:")
                || detail.startsWith("timeout:")
                || detail.startsWith("error:")
                || detail.startsWith("disabled:")
                || detail.startsWith("detection_unavailable:");
    }

    public String humanizeFailureReason(String reason) {
        if (reason == null || reason.isBlank()) return ctx.getString(R.string.unknown_error);
        String normalized = reason;
        if (normalized.startsWith("unavailable:")) {
            normalized = normalized.substring("unavailable:".length());
        }
        String lower = normalized.toLowerCase(Locale.ROOT);
        if (lower.contains("timeout") || lower.contains("deadline")) return ctx.getString(R.string.failure_timeout);
        if (lower.contains("securityexception")) return ctx.getString(R.string.failure_access_denied);
        if (lower.contains("native_library_unavailable") || lower.contains("native_unavailable")) {
            return ctx.getString(R.string.failure_native_unavailable);
        }
        if (lower.contains("unsupported")) return ctx.getString(R.string.failure_unsupported);
        if (lower.contains("disabled")) return ctx.getString(R.string.failure_disabled);
        if (lower.contains("file_unreadable") || lower.contains("procfs_unavailable")) {
            return ctx.getString(R.string.failure_file_unreadable);
        }
        if (lower.contains("service_unavailable")) {
            return ctx.getString(R.string.failure_service_unavailable);
        }
        return normalized.replace('_', ' ');
    }
}
