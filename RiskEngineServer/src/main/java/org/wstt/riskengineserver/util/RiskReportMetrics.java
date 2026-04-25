package org.wstt.riskengineserver.util;

import org.wstt.riskengineserver.dto.DetectionResultDTO;
import org.wstt.riskengineserver.dto.RiskReportDTO;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class RiskReportMetrics {

    private RiskReportMetrics() {}

    public static void backfill(RiskReportDTO reportDTO) {
        List<DetectionResultDTO> detections = safeDetections(reportDTO);
        reportDTO.setRiskScore(resolveRiskScore(reportDTO));
        reportDTO.setMaxRiskScore(resolveMaxRiskScore(reportDTO));
        reportDTO.setDangerCount(resolveDangerCount(reportDTO));
        reportDTO.setWarningCount(resolveWarningCount(reportDTO));

        for (DetectionResultDTO detection : detections) {
            if (detection.getStatus() == null || detection.getStatus().isBlank()) {
                detection.setStatus(defaultStatus(detection.getRiskLevel()));
            }
            if (detection.getScore() <= 0 && !"SAFE".equalsIgnoreCase(detection.getRiskLevel())) {
                detection.setScore(defaultScore(detection.getRiskLevel()));
            }
            if (detection.getMaxScore() <= 0) {
                detection.setMaxScore(Math.max(10, detection.getScore()));
            }
            if ((detection.getDetails() == null || detection.getDetails().isEmpty())
                    && detection.getEvidence() != null && !detection.getEvidence().isBlank()) {
                detection.setDetails(splitEvidence(detection.getEvidence()));
            }
        }
    }

    public static int resolveRiskScore(RiskReportDTO reportDTO) {
        if (reportDTO.getRiskScore() > 0) {
            return reportDTO.getRiskScore();
        }
        int total = 0;
        for (DetectionResultDTO detection : safeDetections(reportDTO)) {
            if (!detection.isWarnOnly()) {
                total += effectiveScore(detection);
            }
        }
        return total;
    }

    public static int resolveMaxRiskScore(RiskReportDTO reportDTO) {
        if (reportDTO.getMaxRiskScore() > 0) {
            return reportDTO.getMaxRiskScore();
        }
        int total = 0;
        for (DetectionResultDTO detection : safeDetections(reportDTO)) {
            total += detection.getMaxScore() > 0 ? detection.getMaxScore() : 10;
        }
        return total;
    }

    public static int resolveDangerCount(RiskReportDTO reportDTO) {
        if (reportDTO.getDangerCount() > 0) {
            return reportDTO.getDangerCount();
        }
        int count = 0;
        for (DetectionResultDTO detection : safeDetections(reportDTO)) {
            if ("DANGER".equalsIgnoreCase(effectiveStatus(detection))) {
                count++;
            }
        }
        return count;
    }

    public static int resolveWarningCount(RiskReportDTO reportDTO) {
        if (reportDTO.getWarningCount() > 0) {
            return reportDTO.getWarningCount();
        }
        int count = 0;
        for (DetectionResultDTO detection : safeDetections(reportDTO)) {
            if ("WARNING".equalsIgnoreCase(effectiveStatus(detection))) {
                count++;
            }
        }
        return count;
    }

    public static Map<String, String> buildDetectorStatusMap(List<DetectionResultDTO> detections) {
        Map<String, String> statusMap = new LinkedHashMap<>();
        if (detections == null) {
            return statusMap;
        }
        for (DetectionResultDTO detection : detections) {
            statusMap.put(detection.getDetectorName(), effectiveStatus(detection));
        }
        return statusMap;
    }

    public static Set<String> buildDetailKeywords(List<DetectionResultDTO> detections) {
        Set<String> keywords = new LinkedHashSet<>();
        if (detections == null) {
            return keywords;
        }
        for (DetectionResultDTO detection : detections) {
            List<String> details = detection.getDetails();
            if (details == null || details.isEmpty()) {
                details = splitEvidence(detection.getEvidence());
            }
            for (String detail : details) {
                String lower = detail.toLowerCase(Locale.ROOT);
                keywords.add(lower);
                int delimiter = lower.indexOf(':');
                if (delimiter > 0) {
                    keywords.add(lower.substring(0, delimiter));
                }
            }
        }
        return keywords;
    }

    public static List<DetectionResultDTO> safeDetections(RiskReportDTO reportDTO) {
        return reportDTO.getDetections() != null ? reportDTO.getDetections() : List.of();
    }

    private static int effectiveScore(DetectionResultDTO detection) {
        return detection.getScore() > 0 ? detection.getScore() : defaultScore(detection.getRiskLevel());
    }

    private static String effectiveStatus(DetectionResultDTO detection) {
        return detection.getStatus() != null && !detection.getStatus().isBlank()
                ? detection.getStatus()
                : defaultStatus(detection.getRiskLevel());
    }

    private static int defaultScore(String riskLevel) {
        if (riskLevel == null) {
            return 0;
        }
        switch (riskLevel.toUpperCase(Locale.ROOT)) {
            case "LOW":
                return 2;
            case "MEDIUM":
                return 4;
            case "HIGH":
                return 7;
            case "DEADLY":
                return 10;
            case "SAFE":
            default:
                return 0;
        }
    }

    private static String defaultStatus(String riskLevel) {
        if (riskLevel == null || "SAFE".equalsIgnoreCase(riskLevel)) {
            return "NORMAL";
        }
        if ("LOW".equalsIgnoreCase(riskLevel) || "MEDIUM".equalsIgnoreCase(riskLevel)) {
            return "WARNING";
        }
        return "DANGER";
    }

    private static List<String> splitEvidence(String evidence) {
        if (evidence == null || evidence.isBlank()) {
            return List.of();
        }
        String[] parts = evidence.split(";\\s*");
        List<String> details = new ArrayList<>();
        for (String part : parts) {
            if (!part.isBlank()) {
                details.add(part.trim());
            }
        }
        return details;
    }
}
