package org.wstt.riskengineserver.controller.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.wstt.riskengineserver.entity.Device;
import org.wstt.riskengineserver.entity.RuleDefinition;
import org.wstt.riskengineserver.repository.DeviceRepository;
import org.wstt.riskengineserver.repository.RuleDefinitionRepository;
import org.wstt.riskengineserver.repository.RuleHitRecordRepository;
import org.wstt.riskengineserver.service.RuleEngineService;

import java.util.List;

/**
 * 规则管理页面
 */
@Controller
@RequestMapping("/rules")
public class RuleWebController {

    private final RuleDefinitionRepository ruleRepository;
    private final RuleEngineService ruleEngineService;
    private final RuleHitRecordRepository hitRecordRepository;
    private final DeviceRepository deviceRepository;

    public RuleWebController(RuleDefinitionRepository ruleRepository,
                             RuleEngineService ruleEngineService,
                             RuleHitRecordRepository hitRecordRepository,
                             DeviceRepository deviceRepository) {
        this.ruleRepository = ruleRepository;
        this.ruleEngineService = ruleEngineService;
        this.hitRecordRepository = hitRecordRepository;
        this.deviceRepository = deviceRepository;
    }

    @GetMapping
    public String list(Model model) {
        model.addAttribute("rules", ruleRepository.findAll());
        return "rules/list";
    }

    @GetMapping("/new")
    public String newRule(Model model) {
        model.addAttribute("rule", new RuleDefinition());
        model.addAttribute("isNew", true);
        return "rules/form";
    }

    @PostMapping
    public String create(@ModelAttribute RuleDefinition rule) {
        ruleRepository.save(rule);
        return "redirect:/rules";
    }

    @GetMapping("/{id}/edit")
    public String edit(@PathVariable Long id, Model model) {
        RuleDefinition rule = ruleRepository.findById(id).orElseThrow();
        model.addAttribute("rule", rule);
        model.addAttribute("isNew", false);
        return "rules/form";
    }

    @PostMapping("/{id}")
    public String update(@PathVariable Long id, @ModelAttribute RuleDefinition rule) {
        RuleDefinition existing = ruleRepository.findById(id).orElseThrow();
        existing.setRuleName(rule.getRuleName());
        existing.setDescription(rule.getDescription());
        existing.setRuleExpression(rule.getRuleExpression());
        existing.setRiskLevel(rule.getRiskLevel());
        existing.setEnabled(rule.getEnabled());
        ruleRepository.save(existing);
        return "redirect:/rules";
    }

    @PostMapping("/{id}/toggle")
    public String toggle(@PathVariable Long id) {
        RuleDefinition rule = ruleRepository.findById(id).orElseThrow();
        rule.setEnabled(!rule.getEnabled());
        ruleRepository.save(rule);
        return "redirect:/rules";
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable Long id) {
        ruleRepository.deleteById(id);
        return "redirect:/rules";
    }

    @PostMapping("/{id}/scan")
    public String scan(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        try {
            RuleEngineService.ScanResult result = ruleEngineService.scanAllReports(id);
            redirectAttributes.addFlashAttribute("scanResult", result);
            return "redirect:/rules/" + id + "/scan-result";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("scanError", "扫描失败: " + e.getMessage());
            return "redirect:/rules";
        }
    }

    @GetMapping("/{id}/scan-result")
    public String scanResult(@PathVariable Long id, Model model) {
        RuleDefinition rule = ruleRepository.findById(id).orElseThrow();
        model.addAttribute("rule", rule);

        // 如果不是从POST redirect来的(直接访问), 从DB查询已有命中设备
        if (!model.containsAttribute("scanResult")) {
            List<Device> hitDevices = hitRecordRepository.findDistinctDevicesByRule(rule);
            long hitReportCount = hitRecordRepository.countByRule(rule);
            RuleEngineService.ScanResult result = new RuleEngineService.ScanResult(
                    rule, hitDevices, (int) hitReportCount, -1);
            model.addAttribute("scanResult", result);
        }

        return "rules/scan-result";
    }

    @PostMapping("/{id}/batch-mark")
    public String batchMark(@PathVariable Long id,
                            @RequestParam List<Long> deviceIds,
                            RedirectAttributes redirectAttributes) {
        RuleDefinition rule = ruleRepository.findById(id).orElseThrow();
        int marked = 0;
        for (Long deviceDbId : deviceIds) {
            deviceRepository.findById(deviceDbId).ifPresent(device -> {
                if (!device.getRiskMarked()) {
                    device.setRiskMarked(true);
                    device.setRiskNote("规则扫描标记: " + rule.getRuleName() + " [" + rule.getRiskLevel() + "]");
                    deviceRepository.save(device);
                }
            });
            marked++;
        }
        redirectAttributes.addFlashAttribute("scanMessage",
                "已对 " + marked + " 台设备标记风险标签");
        return "redirect:/rules/" + id + "/scan-result";
    }
}
