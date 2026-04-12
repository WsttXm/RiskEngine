package org.wstt.riskengineserver.controller.web;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.wstt.riskengineserver.entity.DeviceReport;
import org.wstt.riskengineserver.service.ReportService;

/**
 * 上报记录页面
 */
@Controller
@RequestMapping("/reports")
public class ReportWebController {

    private final ReportService reportService;

    public ReportWebController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping
    public String list(@RequestParam(defaultValue = "0") int page,
                       @RequestParam(defaultValue = "") String riskLevel,
                       Model model) {
        PageRequest pageable = PageRequest.of(page, 20);
        Page<DeviceReport> reports;
        if (!riskLevel.isEmpty()) {
            reports = reportService.findByRiskLevel(riskLevel, pageable);
        } else {
            reports = reportService.findAll(pageable);
        }
        model.addAttribute("reports", reports);
        model.addAttribute("currentRiskLevel", riskLevel);
        return "reports/list";
    }

    @GetMapping("/{id}")
    public String detail(@PathVariable Long id, Model model) {
        DeviceReport report = reportService.findById(id).orElseThrow();
        model.addAttribute("report", report);
        return "reports/detail";
    }
}
