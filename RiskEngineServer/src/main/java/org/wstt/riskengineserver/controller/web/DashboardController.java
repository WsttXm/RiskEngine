package org.wstt.riskengineserver.controller.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.wstt.riskengineserver.repository.DeviceRepository;
import org.wstt.riskengineserver.repository.RuleHitRecordRepository;
import org.wstt.riskengineserver.service.ReportService;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 仪表盘页面
 */
@Controller
public class DashboardController {

    private final DeviceRepository deviceRepository;
    private final ReportService reportService;
    private final RuleHitRecordRepository hitRecordRepository;

    public DashboardController(DeviceRepository deviceRepository,
                               ReportService reportService,
                               RuleHitRecordRepository hitRecordRepository) {
        this.deviceRepository = deviceRepository;
        this.reportService = reportService;
        this.hitRecordRepository = hitRecordRepository;
    }

    @GetMapping({"/", "/dashboard"})
    public String dashboard(Model model) {
        model.addAttribute("totalDevices", deviceRepository.count());
        model.addAttribute("highRiskDevices",
                deviceRepository.countByLastRiskLevelIn(List.of("HIGH", "DEADLY")));
        model.addAttribute("markedDevices", deviceRepository.countByRiskMarkedTrue());
        model.addAttribute("todayReports", reportService.countTodayReports());
        model.addAttribute("todayRuleHits",
                hitRecordRepository.countByHitAtAfter(LocalDateTime.now().toLocalDate().atStartOfDay()));
        return "dashboard";
    }
}
