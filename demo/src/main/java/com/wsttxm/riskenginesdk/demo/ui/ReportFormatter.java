package com.wsttxm.riskenginesdk.demo.ui;

import android.content.Context;
import android.text.TextUtils;

import androidx.annotation.ColorRes;

import com.wsttxm.riskenginesdk.demo.R;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import java.util.ArrayList;
import java.util.HashSet;
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

    public List<String> detectionEvidenceBullets(DetectionResult detection) {
        List<String> bullets = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String reason : detection.getFailureReasons()) {
            String human = humanizeFailureReason(reason);
            if (seen.add(human)) {
                bullets.add(human);
            }
        }
        for (String detail : detection.getDetails()) {
            String human = humanizeEvidence(detail);
            if (seen.add(human)) {
                bullets.add(human);
            }
        }
        return bullets;
    }

    public String detectionRawDetails(DetectionResult detection) {
        Set<String> raw = new LinkedHashSet<>();
        for (String reason : detection.getFailureReasons()) {
            if (reason != null && !reason.isBlank()) {
                raw.add("failure:" + reason);
            }
        }
        for (String detail : detection.getDetails()) {
            if (detail != null && !detail.isBlank()) {
                raw.add(detail);
            }
        }
        return TextUtils.join("\n", raw);
    }

    public String primaryReadableEvidence(DetectionResult detection) {
        for (String detail : detection.getDetails()) {
            if (!isContextOnlyEvidence(detail)) {
                return humanizeEvidence(detail);
            }
        }
        if (!detection.getDetails().isEmpty()) {
            return humanizeEvidence(detection.getDetails().get(0));
        }
        return ctx.getString(R.string.no_specific_evidence);
    }

    private boolean isContextOnlyEvidence(String detail) {
        if (detail == null) return true;
        return detail.startsWith("loader_depth:")
                || detail.startsWith("passes:")
                || detail.startsWith("native_score:")
                || detail.equals("art_native_flag:invoke")
                || detail.equals("sealed:coverage_loss")
                || detail.equals("deduped:corroborating_evidence");
    }

    private String firstReadableFailure(DetectionResult detection) {
        for (String reason : detection.getFailureReasons()) {
            String human = humanizeFailureReason(reason);
            if (!human.isBlank() && !human.equals(ctx.getString(R.string.unknown_error))) {
                return human;
            }
        }
        for (String detail : detection.getDetails()) {
            if (isInternalExecutionToken(detail)
                    || detail.contains("missing_map")
                    || detail.contains("text_mismatch")) {
                return humanizeEvidence(detail);
            }
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
            case "process_scan": return ctx.getString(R.string.detector_process);
            case "adb": return ctx.getString(R.string.detector_adb);
            case "emulator": return ctx.getString(R.string.detector_emulator);
            case "sandbox": return ctx.getString(R.string.detector_sandbox);
            case "debug": return ctx.getString(R.string.detector_debug);
            case "cloud_phone": return ctx.getString(R.string.detector_cloud_phone);
            case "custom_rom": return ctx.getString(R.string.detector_custom_rom);
            case "multi_source_validation": return ctx.getString(R.string.detector_multi_source);
            case "signal_correlation": return ctx.getString(R.string.detector_correlation);
            case "native_tamper": return ctx.getString(R.string.detector_native_tamper);
            case "consistency": return ctx.getString(R.string.detector_consistency);
            case "sealed_verdict": return ctx.getString(R.string.detector_sealed_verdict);
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
            // Localized keys previously leaking English on Pixel 6
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
            if (!detection.getDetails().isEmpty()) {
                summary.append(ctx.getString(R.string.redacted_report_reason,
                        primaryReadableEvidence(detection)));
            }
        }
        summary.append(ctx.getString(R.string.redacted_report_footer));
        return summary.toString();
    }

    public String humanizeEvidence(String detail) {
        if (detail == null || detail.isBlank()) return ctx.getString(R.string.no_specific_evidence);
        if (detail.startsWith("detection_unavailable:")) {
            return ctx.getString(R.string.evidence_check_unavailable,
                    humanizeFailureReason(detail.substring("detection_unavailable:".length())));
        }
        if (isInternalExecutionToken(detail)) {
            int separator = detail.indexOf(':');
            return humanizeFailureReason(separator >= 0 ? detail.substring(separator + 1) : detail);
        }
        if (detail.startsWith("settings_adb_wifi_enabled")) return ctx.getString(R.string.evidence_adb_wifi);
        if (detail.startsWith("settings_adb_enabled")) return ctx.getString(R.string.evidence_adb_usb);
        if (detail.startsWith("adb_tcp_port:")) return ctx.getString(R.string.evidence_adb_tcp);
        if (detail.startsWith("debuggable_flag")) return ctx.getString(R.string.evidence_debuggable);
        if (detail.startsWith("debugger_connected")) return ctx.getString(R.string.evidence_debugger);
        if (detail.startsWith("tracer_pid:")) return ctx.getString(R.string.evidence_tracer);
        if (detail.startsWith("su_found:") || detail.startsWith("native:su:") || detail.startsWith("path_su:")) {
            return ctx.getString(R.string.evidence_su);
        }
        if (detail.startsWith("ksu_found:") || detail.startsWith("native:ksu:")) {
            return ctx.getString(R.string.evidence_kernelsu);
        }
        if (detail.contains("mount:ksu") || detail.contains("mountinfo:ksu") || detail.contains("kernelsu_mount")) {
            return ctx.getString(R.string.evidence_kernelsu_mount);
        }
        if (detail.startsWith("apatch_found:") || detail.startsWith("native:apatch:")) {
            return ctx.getString(R.string.evidence_apatch);
        }
        if (detail.contains("syscall_mismatch")) return ctx.getString(R.string.evidence_syscall_mismatch);
        if (detail.contains("magisk_mount") || detail.contains("mount:magisk") || detail.startsWith("mountinfo:magisk")) {
            return ctx.getString(R.string.evidence_magisk_mount);
        }
        if (detail.contains("module_mount") || detail.contains("mount:module") || detail.startsWith("modules_found:")) {
            return ctx.getString(R.string.evidence_module_mount);
        }
        if (detail.startsWith("system_tmpfs_mount:") || detail.contains("mount:system_tmpfs:")) {
            return ctx.getString(R.string.evidence_system_tmpfs_mount);
        }
        if (detail.contains("debug_ramdisk_mount") || detail.contains("mount:debug_ramdisk")) {
            return ctx.getString(R.string.evidence_debug_ramdisk_mount);
        }
        if (detail.startsWith("magisk_found:") || detail.contains("magisk:") || detail.startsWith("native:magisk")) {
            return ctx.getString(R.string.evidence_magisk);
        }
        if (detail.startsWith("selinux_permissive")) return ctx.getString(R.string.evidence_selinux);
        if (detail.startsWith("test_keys")) return ctx.getString(R.string.evidence_test_keys);
        if (detail.startsWith("inline_hook:")) return ctx.getString(R.string.evidence_inline_hook);
        if (detail.startsWith("got_hook:")) return ctx.getString(R.string.evidence_got_hook);
        if (detail.startsWith("jni_table_hook:")) return ctx.getString(R.string.evidence_jni_hook);
        if (detail.startsWith("jni_slot_hook:")) {
            return ctx.getString(R.string.evidence_jni_slot_hook, detail.substring("jni_slot_hook:".length()));
        }
        if (detail.startsWith("jni_self_hook:")) return ctx.getString(R.string.evidence_jni_self_hook);
        if (detail.equals("jni_self:no_range")) return ctx.getString(R.string.failure_jni_self_range);
        if (detail.equals("art_native_flag:invoke")) return ctx.getString(R.string.evidence_art_native_invoke_platform);
        if (detail.startsWith("art_native_flag:")) {
            return ctx.getString(R.string.evidence_art_native_flag, detail.substring("art_native_flag:".length()));
        }
        if (detail.startsWith("art_native_cleared:")) {
            return ctx.getString(R.string.evidence_art_native_cleared, detail.substring("art_native_cleared:".length()));
        }
        if (detail.startsWith("memfd_private_elf:") || detail.equals("late_memfd_elf")) {
            return ctx.getString(R.string.evidence_memfd_private_elf);
        }
        if (detail.startsWith("frida_dbus_port:")) return ctx.getString(R.string.evidence_frida_dbus);
        if (detail.equals("kernel_dirty_on_release")) return ctx.getString(R.string.evidence_kernel_dirty);
        if (detail.startsWith("loader_depth:")) {
            return ctx.getString(R.string.evidence_loader_depth, detail.substring("loader_depth:".length()));
        }
        if (detail.startsWith("loader_chain_deep:")) {
            return ctx.getString(R.string.evidence_loader_chain_deep, detail.substring("loader_chain_deep:".length()));
        }
        if (detail.startsWith("loader_unexpected:")) {
            return ctx.getString(R.string.evidence_loader_unexpected, detail.substring("loader_unexpected:".length()));
        }
        if (detail.startsWith("passes:")) {
            return ctx.getString(R.string.evidence_monitor_passes, detail.substring("passes:".length()));
        }
        if (detail.equals("late_text_mismatch")) return ctx.getString(R.string.evidence_late_text_mismatch);
        if (detail.equals("late_tracer_attached")) return ctx.getString(R.string.evidence_late_tracer);
        if (detail.startsWith("late_wx_")) return ctx.getString(R.string.evidence_late_wx);
        if (detail.startsWith("native_score:")) {
            return ctx.getString(R.string.evidence_native_score, detail.substring("native_score:".length()));
        }
        if (detail.equals("sealed:root_strong")) return ctx.getString(R.string.evidence_sealed_root);
        if (detail.equals("sealed:root_hidden")) return ctx.getString(R.string.evidence_sealed_hidden_root);
        if (detail.equals("sealed:kernel_root")) return ctx.getString(R.string.evidence_sealed_kernel_root);
        if (detail.equals("sealed:hook_inline")) return ctx.getString(R.string.evidence_sealed_inline_hook);
        if (detail.equals("sealed:hook_framework")) return ctx.getString(R.string.evidence_sealed_hook_framework);
        if (detail.equals("sealed:text_mismatch")) return ctx.getString(R.string.evidence_sealed_tamper);
        if (detail.equals("sealed:emulator")) return ctx.getString(R.string.evidence_sealed_emulator);
        if (detail.equals("sealed:debugger")) return ctx.getString(R.string.evidence_sealed_debugger);
        if (detail.equals("sealed:jni_self_hook")) return ctx.getString(R.string.evidence_jni_self_hook);
        if (detail.equals("sealed:coverage_loss")) return ctx.getString(R.string.evidence_sealed_coverage);
        if (detail.equals("deduped:corroborating_evidence")) {
            return ctx.getString(R.string.evidence_duplicate_corroboration);
        }
        if (detail.startsWith("maps:gadget") || detail.contains("libgadget")) {
            return ctx.getString(R.string.evidence_gadget);
        }
        if (detail.startsWith("anon_exec:")) return ctx.getString(R.string.evidence_anon_exec);
        if (detail.contains("frida")) return ctx.getString(R.string.evidence_frida);
        if (detail.contains("xposed") || detail.contains("lsposed") || detail.contains("lspd")) {
            return ctx.getString(R.string.evidence_xposed);
        }
        if (detail.startsWith("C1:")) return ctx.getString(R.string.evidence_correlation_c1);
        if (detail.startsWith("C2:")) return ctx.getString(R.string.evidence_correlation_c2);
        if (detail.startsWith("C3:")) return ctx.getString(R.string.evidence_correlation_c3);
        if (detail.startsWith("C4:")) return ctx.getString(R.string.evidence_correlation_c4);
        if (detail.startsWith("C5:")) return ctx.getString(R.string.evidence_correlation_c5);
        if (detail.startsWith("C6:")) return ctx.getString(R.string.evidence_correlation_c6);
        if (detail.startsWith("C7:")) return ctx.getString(R.string.evidence_correlation_c7);
        if (detail.startsWith("community_rom:")) return ctx.getString(R.string.evidence_custom_rom);
        if (detail.startsWith("prop_mismatch:")) return ctx.getString(R.string.evidence_prop_mismatch);
        if (detail.startsWith("runtime_arch:")) return ctx.getString(R.string.evidence_runtime_arch);
        if (detail.startsWith("qemu_prop") || detail.startsWith("qemu_pipe") || detail.startsWith("cpu:hypervisor")) {
            return detail.startsWith("cpu:hypervisor")
                    ? ctx.getString(R.string.evidence_hypervisor_cpu)
                    : ctx.getString(R.string.evidence_qemu);
        }
        if (detail.startsWith("disk_small")) return ctx.getString(R.string.evidence_disk_small);
        if (detail.startsWith("screen_stock")) return ctx.getString(R.string.evidence_screen_stock);
        if (detail.startsWith("generic_fingerprint:")) return ctx.getString(R.string.evidence_generic_fingerprint);
        if (detail.startsWith("emu_file:")) return ctx.getString(R.string.evidence_emu_file);
        if (detail.startsWith("emu_pkg:")) return ctx.getString(R.string.evidence_emu_pkg);
        if (detail.startsWith("missing_feature:")) return ctx.getString(R.string.evidence_missing_feature);
        if (detail.startsWith("no_thermal")) return ctx.getString(R.string.evidence_no_thermal);
        if (detail.startsWith("low_sensor") || detail.startsWith("aosp_sensor") || detail.startsWith("very_low_sensor")) {
            return ctx.getString(R.string.evidence_low_sensor);
        }
        if (detail.startsWith("cloud_pkg:")) return ctx.getString(R.string.evidence_cloud_pkg);
        if (detail.startsWith("battery_")) return ctx.getString(R.string.evidence_battery_anomaly);
        if (detail.startsWith("virtual_") || detail.startsWith("sandbox_pkg:")
                || detail.startsWith("virtualized_fd:") || detail.startsWith("uid_datadir")) {
            return ctx.getString(R.string.evidence_virtual_env);
        }
        if (detail.contains("missing_map") || detail.contains("missing map")) {
            return ctx.getString(R.string.failure_so_missing_map);
        }
        if (detail.contains("apk_embedded")) return ctx.getString(R.string.failure_so_apk_embedded);
        if (detail.contains("anonymous_map") || detail.contains("anonymous map")) {
            return ctx.getString(R.string.failure_so_anonymous_map);
        }
        if (detail.contains("file_unreadable") || detail.contains("file unreadable")) {
            return ctx.getString(R.string.failure_so_unreadable);
        }
        if (detail.contains("bad_elf") || detail.contains("bad elf")) return ctx.getString(R.string.failure_so_bad_elf);
        if (detail.startsWith("text_mismatch")) return ctx.getString(R.string.evidence_native_tamper);
        if (detail.startsWith("verified_boot_state:")) {
            return ctx.getString(R.string.evidence_verified_boot_state,
                    detail.substring("verified_boot_state:".length()));
        }
        if (detail.equals("bootloader_unlocked")) return ctx.getString(R.string.evidence_bootloader_unlocked);
        if (detail.startsWith("process_source_mismatch")) return ctx.getString(R.string.evidence_process_mismatch);
        if (detail.startsWith("suspicious_process:") || detail.startsWith("native_process:")) {
            return ctx.getString(R.string.evidence_suspicious_process);
        }
        if (detail.startsWith("fingerprint:") || detail.startsWith("model:")
                || detail.startsWith("hardware:") || detail.startsWith("product:")
                || detail.startsWith("manufacturer:") || detail.startsWith("board:")) {
            return ctx.getString(R.string.evidence_emulator_build);
        }
        if (detail.startsWith("inconsistent_fields:")) return ctx.getString(R.string.evidence_inconsistent);
        int separator = detail.indexOf(':');
        if (separator > 0 && separator < detail.length() - 1) {
            return ctx.getString(R.string.evidence_generic_key_value,
                    detail.substring(0, separator).replace('_', ' '),
                    detail.substring(separator + 1).replace('_', ' '));
        }
        return ctx.getString(R.string.evidence_generic_signal, detail.replace('_', ' '));
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
        if (lower.contains("missing_map") || lower.contains("missing map")) {
            return ctx.getString(R.string.failure_so_missing_map);
        }
        if (lower.contains("apk_embedded")) return ctx.getString(R.string.failure_so_apk_embedded);
        if (lower.contains("anonymous_map") || lower.contains("anonymous map")) {
            return ctx.getString(R.string.failure_so_anonymous_map);
        }
        if (lower.contains("file_unreadable") || lower.contains("file unreadable")) {
            return ctx.getString(R.string.failure_so_unreadable);
        }
        if (lower.contains("bad_elf") || lower.contains("bad elf")) return ctx.getString(R.string.failure_so_bad_elf);
        if (lower.contains("text_mismatch") || lower.contains("text mismatch")) {
            return ctx.getString(R.string.evidence_native_tamper);
        }
        if (lower.contains("unsupported")) return ctx.getString(R.string.failure_unsupported);
        if (lower.contains("disabled")) return ctx.getString(R.string.failure_disabled);
        if (lower.contains("ns_unreadable") || lower.contains("mount_ns")) {
            return ctx.getString(R.string.failure_mount_ns_unreadable);
        }
        return normalized.replace('_', ' ');
    }
}
