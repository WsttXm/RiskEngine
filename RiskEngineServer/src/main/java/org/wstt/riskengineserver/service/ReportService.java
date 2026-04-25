package org.wstt.riskengineserver.service;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.wstt.riskengineserver.dto.RiskReportDTO;
import org.wstt.riskengineserver.dto.ServerConfigResponse;
import org.wstt.riskengineserver.entity.App;
import org.wstt.riskengineserver.entity.Device;
import org.wstt.riskengineserver.entity.DeviceReport;
import org.wstt.riskengineserver.repository.DeviceReportRepository;
import org.wstt.riskengineserver.repository.DeviceRepository;
import org.wstt.riskengineserver.util.RiskReportMetrics;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * 上报数据处理服务
 */
@Service
public class ReportService {

    private static final Logger log = LoggerFactory.getLogger(ReportService.class);

    private final DeviceRepository deviceRepository;
    private final DeviceReportRepository reportRepository;
    private final DeviceIdGenerator deviceIdGenerator;
    private final RuleEngineService ruleEngineService;
    private final Gson gson = new Gson();

    public ReportService(DeviceRepository deviceRepository,
                         DeviceReportRepository reportRepository,
                         DeviceIdGenerator deviceIdGenerator,
                         RuleEngineService ruleEngineService) {
        this.deviceRepository = deviceRepository;
        this.reportRepository = reportRepository;
        this.deviceIdGenerator = deviceIdGenerator;
        this.ruleEngineService = ruleEngineService;
    }

    /**
     * 处理SDK上报的风控数据
     */
    @Transactional
    public ServerConfigResponse processReport(App app, RiskReportDTO reportDTO) {
        RiskReportMetrics.backfill(reportDTO);

        // 1. 生成设备ID, 创建或更新设备记录
        String deviceIdHash = deviceIdGenerator.generateDeviceId(reportDTO.getFingerprint());
        Device device = findOrCreateDevice(deviceIdHash, reportDTO.getOverallRiskLevel());

        // 2. 保存上报记录
        DeviceReport report = new DeviceReport();
        report.setDevice(device);
        report.setApp(app);
        report.setSdkVersion(reportDTO.getSdkVersion());
        report.setOverallRiskLevel(reportDTO.getOverallRiskLevel());
        report.setRiskScore(reportDTO.getRiskScore());
        report.setMaxRiskScore(reportDTO.getMaxRiskScore());
        report.setDangerCount(reportDTO.getDangerCount());
        report.setWarningCount(reportDTO.getWarningCount());
        report.setFingerprintJson(gson.toJson(reportDTO.getFingerprint()));
        report.setDetectionsJson(gson.toJson(reportDTO.getDetections()));
        report.setReportTimestamp(reportDTO.getTimestampMs());
        reportRepository.save(report);

        log.info("处理上报数据: deviceId={}, riskLevel={}, app={}",
                deviceIdHash.substring(0, 8), reportDTO.getOverallRiskLevel(), app.getAppName());

        // 3. 执行规则引擎
        ruleEngineService.evaluateReport(report, device, reportDTO);

        // 4. 返回配置
        ServerConfigResponse response = new ServerConfigResponse();
        response.setCollectInterval(300000);
        return response;
    }

    private Device findOrCreateDevice(String deviceIdHash, String riskLevel) {
        Optional<Device> existing = deviceRepository.findByDeviceId(deviceIdHash);
        if (existing.isPresent()) {
            Device device = existing.get();
            device.setLastSeenAt(LocalDateTime.now());
            device.setLastRiskLevel(riskLevel);
            device.setReportCount(device.getReportCount() + 1);
            return deviceRepository.save(device);
        } else {
            Device device = new Device();
            device.setDeviceId(deviceIdHash);
            device.setLastRiskLevel(riskLevel);
            device.setReportCount(1);
            return deviceRepository.save(device);
        }
    }

    public Page<DeviceReport> findAll(Pageable pageable) {
        return reportRepository.findAllWithDeviceAndApp(pageable);
    }

    public Optional<DeviceReport> findById(Long id) {
        return reportRepository.findByIdWithDeviceAndApp(id);
    }

    public RiskReportDTO reconstructReportDTO(DeviceReport report) {
        RiskReportDTO dto = new RiskReportDTO();
        dto.setOverallRiskLevel(report.getOverallRiskLevel());
        dto.setSdkVersion(report.getSdkVersion());
        dto.setTimestampMs(report.getReportTimestamp() != null ? report.getReportTimestamp() : 0);
        dto.setRiskScore(report.getRiskScore() != null ? report.getRiskScore() : 0);
        dto.setMaxRiskScore(report.getMaxRiskScore() != null ? report.getMaxRiskScore() : 0);
        dto.setDangerCount(report.getDangerCount() != null ? report.getDangerCount() : 0);
        dto.setWarningCount(report.getWarningCount() != null ? report.getWarningCount() : 0);

        if (report.getDetectionsJson() != null && !report.getDetectionsJson().isEmpty()) {
            dto.setDetections(gson.fromJson(report.getDetectionsJson(),
                    new com.google.gson.reflect.TypeToken<java.util.List<org.wstt.riskengineserver.dto.DetectionResultDTO>>(){}.getType()));
        }
        if (report.getFingerprintJson() != null && !report.getFingerprintJson().isEmpty()) {
            dto.setFingerprint(gson.fromJson(report.getFingerprintJson(),
                    org.wstt.riskengineserver.dto.DeviceFingerprintDTO.class));
        }
        RiskReportMetrics.backfill(dto);
        return dto;
    }

    public Page<DeviceReport> findByRiskLevel(String riskLevel, Pageable pageable) {
        return reportRepository.findByRiskLevelWithDeviceAndApp(riskLevel, pageable);
    }

    public long countTodayReports() {
        return reportRepository.countByReceivedAtAfter(
                LocalDateTime.now().toLocalDate().atStartOfDay());
    }
}
