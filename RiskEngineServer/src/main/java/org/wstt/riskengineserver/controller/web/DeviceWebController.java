package org.wstt.riskengineserver.controller.web;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.wstt.riskengineserver.entity.Device;
import org.wstt.riskengineserver.entity.DeviceReport;
import org.wstt.riskengineserver.entity.RuleHitRecord;
import org.wstt.riskengineserver.repository.DeviceReportRepository;
import org.wstt.riskengineserver.repository.DeviceRepository;
import org.wstt.riskengineserver.repository.RuleHitRecordRepository;

/**
 * 设备管理页面
 */
@Controller
@RequestMapping("/devices")
public class DeviceWebController {

    private final DeviceRepository deviceRepository;
    private final DeviceReportRepository reportRepository;
    private final RuleHitRecordRepository hitRecordRepository;

    public DeviceWebController(DeviceRepository deviceRepository,
                               DeviceReportRepository reportRepository,
                               RuleHitRecordRepository hitRecordRepository) {
        this.deviceRepository = deviceRepository;
        this.reportRepository = reportRepository;
        this.hitRecordRepository = hitRecordRepository;
    }

    @GetMapping
    public String list(@RequestParam(defaultValue = "0") int page,
                       @RequestParam(defaultValue = "") String riskLevel,
                       Model model) {
        PageRequest pageable = PageRequest.of(page, 20, Sort.by("lastSeenAt").descending());
        Page<Device> devices;
        if (!riskLevel.isEmpty()) {
            devices = deviceRepository.findByLastRiskLevel(riskLevel, pageable);
        } else {
            devices = deviceRepository.findAll(pageable);
        }
        model.addAttribute("devices", devices);
        model.addAttribute("currentRiskLevel", riskLevel);
        return "devices/list";
    }

    @GetMapping("/{id}")
    public String detail(@PathVariable Long id, Model model) {
        Device device = deviceRepository.findById(id).orElseThrow();
        Page<DeviceReport> reports = reportRepository.findByDeviceOrderByReceivedAtDesc(
                device, PageRequest.of(0, 20));
        Page<RuleHitRecord> hits = hitRecordRepository.findByDeviceOrderByHitAtDesc(
                device, PageRequest.of(0, 20));

        model.addAttribute("device", device);
        model.addAttribute("reports", reports);
        model.addAttribute("ruleHits", hits);
        return "devices/detail";
    }

    @PostMapping("/{id}/mark")
    public String markRisk(@PathVariable Long id,
                           @RequestParam boolean riskMarked,
                           @RequestParam(defaultValue = "") String riskNote) {
        Device device = deviceRepository.findById(id).orElseThrow();
        device.setRiskMarked(riskMarked);
        device.setRiskNote(riskNote);
        deviceRepository.save(device);
        return "redirect:/devices/" + id;
    }
}
