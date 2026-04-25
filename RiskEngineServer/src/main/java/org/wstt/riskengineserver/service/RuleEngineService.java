package org.wstt.riskengineserver.service;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.wstt.riskengineserver.dto.CollectorResultDTO;
import org.wstt.riskengineserver.dto.DetectionResultDTO;
import org.wstt.riskengineserver.dto.DeviceFingerprintDTO;
import org.wstt.riskengineserver.dto.RiskReportDTO;
import org.wstt.riskengineserver.entity.Device;
import org.wstt.riskengineserver.entity.DeviceReport;
import org.wstt.riskengineserver.entity.RuleDefinition;
import org.wstt.riskengineserver.entity.RuleHitRecord;
import org.wstt.riskengineserver.repository.DeviceReportRepository;
import org.wstt.riskengineserver.repository.RuleDefinitionRepository;
import org.wstt.riskengineserver.repository.RuleHitRecordRepository;
import org.wstt.riskengineserver.util.RiskReportMetrics;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 规则引擎服务 - 使用SpEL表达式评估上报数据
 *
 * SpEL上下文变量:
 *   - overallRiskLevel: 综合风险等级 (String, 如 "HIGH", "DEADLY")
 *   - detections: 检测结果列表 (List<DetectionResultDTO>)
 *   - fingerprint: 指纹结果Map (Map<String, CollectorResultDTO>)
 *   - inconsistentFields: 不一致字段列表 (List<String>)
 *   - device: 设备实体 (Device)
 *   - reportCount: 设备上报次数 (int)
 *   - riskMarked: 是否已被标记 (boolean)
 *
 * 规则示例:
 *   - overallRiskLevel == 'DEADLY'
 *   - detections.?[detectorName == 'RootDetector' and riskLevel == 'HIGH'].size() > 0
 *   - inconsistentFields.size() > 2
 *   - reportCount > 100
 */
@Service
public class RuleEngineService {

    private static final Logger log = LoggerFactory.getLogger(RuleEngineService.class);

    private final RuleDefinitionRepository ruleRepository;
    private final RuleHitRecordRepository hitRecordRepository;
    private final DeviceReportRepository reportRepository;
    private final SpelExpressionParser parser = new SpelExpressionParser();
    private final Gson gson = new Gson();

    public RuleEngineService(RuleDefinitionRepository ruleRepository,
                             RuleHitRecordRepository hitRecordRepository,
                             DeviceReportRepository reportRepository) {
        this.ruleRepository = ruleRepository;
        this.hitRecordRepository = hitRecordRepository;
        this.reportRepository = reportRepository;
    }

    /**
     * 对上报数据执行所有启用的规则
     */
    public void evaluateReport(DeviceReport report, Device device, RiskReportDTO reportDTO) {
        List<RuleDefinition> rules = ruleRepository.findByEnabledTrue();
        if (rules.isEmpty()) return;
        RiskReportMetrics.backfill(reportDTO);

        // 调试: 打印检测结果概要
        if (reportDTO.getDetections() != null) {
            String detectionSummary = reportDTO.getDetections().stream()
                    .map(d -> d.getDetectorName() + "=" + d.getRiskLevel() + "/" + d.getStatus())
                    .collect(Collectors.joining(", "));
            log.info("规则评估输入: deviceId={}, detections=[{}], overallRiskLevel={}, riskScore={}",
                    device.getDeviceId().substring(0, 8), detectionSummary,
                    reportDTO.getOverallRiskLevel(), reportDTO.getRiskScore());
        }

        EvaluationContext context = buildContext(device, reportDTO);

        for (RuleDefinition rule : rules) {
            try {
                Expression expression = parser.parseExpression(rule.getRuleExpression());
                Boolean result = expression.getValue(context, Boolean.class);
                log.debug("规则评估: rule={}, expression={}, result={}",
                        rule.getRuleName(), rule.getRuleExpression(), result);

                if (Boolean.TRUE.equals(result)) {
                    RuleHitRecord hit = new RuleHitRecord();
                    hit.setRule(rule);
                    hit.setDevice(device);
                    hit.setReport(report);
                    hit.setDetail("规则[" + rule.getRuleName() + "]命中, 标记风险等级: " + rule.getRiskLevel());
                    hitRecordRepository.save(hit);

                    log.info("规则命中: rule={}, device={}, riskLevel={}",
                            rule.getRuleName(), device.getDeviceId().substring(0, 8), rule.getRiskLevel());
                }
            } catch (Exception e) {
                log.warn("规则评估异常: rule={}, expression={}, error={}",
                        rule.getRuleName(), rule.getRuleExpression(), e.getMessage());
            }
        }
    }

    /**
     * 追溯扫描: 清除旧记录后重新评估所有历史上报, 返回命中的设备列表
     */
    @Transactional
    public ScanResult scanAllReports(Long ruleId) {
        RuleDefinition rule = ruleRepository.findById(ruleId).orElseThrow();
        Expression expression = parser.parseExpression(rule.getRuleExpression());

        // 先清除该规则旧的命中记录, 允许重复扫描
        hitRecordRepository.deleteByRule(rule);

        List<DeviceReport> allReports = reportRepository.findAll();
        int hitReportCount = 0;
        // 用Set记录命中的设备(去重)
        java.util.LinkedHashSet<Device> hitDevices = new java.util.LinkedHashSet<>();

        for (DeviceReport report : allReports) {
            try {
                RiskReportDTO reportDTO = reconstructDTO(report);
                if (reportDTO == null) continue;

                Device device = report.getDevice();
                EvaluationContext context = buildContext(device, reportDTO);
                Boolean result = expression.getValue(context, Boolean.class);

                if (Boolean.TRUE.equals(result)) {
                    RuleHitRecord hit = new RuleHitRecord();
                    hit.setRule(rule);
                    hit.setDevice(device);
                    hit.setReport(report);
                    hit.setDetail("追溯扫描: 规则[" + rule.getRuleName() + "]命中, 标记风险等级: " + rule.getRiskLevel());
                    hitRecordRepository.save(hit);
                    hitReportCount++;
                    hitDevices.add(device);
                }
            } catch (Exception e) {
                log.warn("追溯扫描异常: reportId={}, error={}", report.getId(), e.getMessage());
            }
        }

        log.info("追溯扫描完成: rule={}, 扫描{}条记录, 命中{}条, 涉及{}台设备",
                rule.getRuleName(), allReports.size(), hitReportCount, hitDevices.size());
        return new ScanResult(rule, new ArrayList<>(hitDevices), hitReportCount, allReports.size());
    }

    /**
     * 扫描结果
     */
    public static class ScanResult {
        private final RuleDefinition rule;
        private final List<Device> hitDevices;
        private final int hitReportCount;
        private final int totalReportCount;

        public ScanResult(RuleDefinition rule, List<Device> hitDevices, int hitReportCount, int totalReportCount) {
            this.rule = rule;
            this.hitDevices = hitDevices;
            this.hitReportCount = hitReportCount;
            this.totalReportCount = totalReportCount;
        }

        public RuleDefinition getRule() { return rule; }
        public List<Device> getHitDevices() { return hitDevices; }
        public int getHitReportCount() { return hitReportCount; }
        public int getTotalReportCount() { return totalReportCount; }
        public int getHitDeviceCount() { return hitDevices.size(); }
    }

    /**
     * 从DeviceReport中的JSON字段重建RiskReportDTO
     */
    private RiskReportDTO reconstructDTO(DeviceReport report) {
        try {
            RiskReportDTO dto = new RiskReportDTO();
            dto.setOverallRiskLevel(report.getOverallRiskLevel());
            dto.setSdkVersion(report.getSdkVersion());
            dto.setTimestampMs(report.getReportTimestamp() != null ? report.getReportTimestamp() : 0);
            dto.setRiskScore(report.getRiskScore() != null ? report.getRiskScore() : 0);
            dto.setMaxRiskScore(report.getMaxRiskScore() != null ? report.getMaxRiskScore() : 0);
            dto.setDangerCount(report.getDangerCount() != null ? report.getDangerCount() : 0);
            dto.setWarningCount(report.getWarningCount() != null ? report.getWarningCount() : 0);

            // 反序列化detections JSON
            if (report.getDetectionsJson() != null && !report.getDetectionsJson().isEmpty()) {
                List<DetectionResultDTO> detections = gson.fromJson(report.getDetectionsJson(),
                        new TypeToken<List<DetectionResultDTO>>(){}.getType());
                dto.setDetections(detections);
            } else {
                dto.setDetections(new ArrayList<>());
            }

            // 反序列化fingerprint JSON
            if (report.getFingerprintJson() != null && !report.getFingerprintJson().isEmpty()) {
                DeviceFingerprintDTO fingerprint = gson.fromJson(report.getFingerprintJson(),
                        DeviceFingerprintDTO.class);
                dto.setFingerprint(fingerprint);
            }

            RiskReportMetrics.backfill(dto);
            return dto;
        } catch (Exception e) {
            log.warn("重建DTO失败: reportId={}, error={}", report.getId(), e.getMessage());
            return null;
        }
    }

    private EvaluationContext buildContext(Device device, RiskReportDTO reportDTO) {
        StandardEvaluationContext context = new StandardEvaluationContext();

        // 基础变量
        context.setVariable("overallRiskLevel", reportDTO.getOverallRiskLevel());
        context.setVariable("sdkVersion", reportDTO.getSdkVersion());

        // 检测结果 (确保不为null)
        List<DetectionResultDTO> detections = reportDTO.getDetections() != null
                ? reportDTO.getDetections() : new ArrayList<>();
        context.setVariable("detections", detections);
        context.setVariable("riskScore", RiskReportMetrics.resolveRiskScore(reportDTO));
        context.setVariable("dangerCount", RiskReportMetrics.resolveDangerCount(reportDTO));
        context.setVariable("warningCount", RiskReportMetrics.resolveWarningCount(reportDTO));
        context.setVariable("detectorStatusMap", RiskReportMetrics.buildDetectorStatusMap(detections));
        context.setVariable("detailKeywords", RiskReportMetrics.buildDetailKeywords(detections));

        // 指纹数据
        if (reportDTO.getFingerprint() != null) {
            context.setVariable("fingerprint",
                    reportDTO.getFingerprint().getResults() != null
                            ? reportDTO.getFingerprint().getResults() : Map.of());
            context.setVariable("inconsistentFields",
                    reportDTO.getFingerprint().getInconsistentFields() != null
                            ? reportDTO.getFingerprint().getInconsistentFields() : List.of());
        } else {
            context.setVariable("fingerprint", Map.of());
            context.setVariable("inconsistentFields", List.of());
        }

        // 设备信息
        context.setVariable("device", device);
        context.setVariable("reportCount", device.getReportCount());
        context.setVariable("riskMarked", device.getRiskMarked());

        // 为简化SpEL表达式, 提供根对象
        context.setRootObject(new RuleEvaluationRoot(reportDTO, device));

        return context;
    }

    /**
     * SpEL根对象, 简化表达式写法
     * 可直接写 overallRiskLevel == 'HIGH' 而不需要 #overallRiskLevel
     */
    public static class RuleEvaluationRoot {
        public final String overallRiskLevel;
        public final List<DetectionResultDTO> detections;
        public final Map<String, CollectorResultDTO> fingerprint;
        public final List<String> inconsistentFields;
        public final int riskScore;
        public final int dangerCount;
        public final int warningCount;
        public final Map<String, String> detectorStatusMap;
        public final Set<String> detailKeywords;
        public final int reportCount;
        public final boolean riskMarked;

        public RuleEvaluationRoot(RiskReportDTO report, Device device) {
            RiskReportMetrics.backfill(report);
            this.overallRiskLevel = report.getOverallRiskLevel();
            this.detections = report.getDetections() != null ? report.getDetections() : new ArrayList<>();
            this.fingerprint = report.getFingerprint() != null && report.getFingerprint().getResults() != null
                    ? report.getFingerprint().getResults() : Map.of();
            this.inconsistentFields = report.getFingerprint() != null && report.getFingerprint().getInconsistentFields() != null
                    ? report.getFingerprint().getInconsistentFields() : List.of();
            this.riskScore = RiskReportMetrics.resolveRiskScore(report);
            this.dangerCount = RiskReportMetrics.resolveDangerCount(report);
            this.warningCount = RiskReportMetrics.resolveWarningCount(report);
            this.detectorStatusMap = RiskReportMetrics.buildDetectorStatusMap(this.detections);
            this.detailKeywords = RiskReportMetrics.buildDetailKeywords(this.detections);
            this.reportCount = device.getReportCount();
            this.riskMarked = device.getRiskMarked();
        }
    }
}
