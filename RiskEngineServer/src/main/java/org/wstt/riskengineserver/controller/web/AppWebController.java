package org.wstt.riskengineserver.controller.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.wstt.riskengineserver.entity.App;
import org.wstt.riskengineserver.service.AppService;

/**
 * 接入应用管理页面
 */
@Controller
@RequestMapping("/apps")
public class AppWebController {

    private final AppService appService;

    public AppWebController(AppService appService) {
        this.appService = appService;
    }

    @GetMapping
    public String list(Model model) {
        model.addAttribute("apps", appService.findAll());
        return "apps/list";
    }

    @PostMapping
    public String create(@RequestParam String appName) {
        appService.createApp(appName);
        return "redirect:/apps";
    }

    @PostMapping("/{id}/toggle")
    public String toggle(@PathVariable Long id) {
        App app = appService.findById(id).orElseThrow();
        app.setEnabled(!app.getEnabled());
        appService.save(app);
        return "redirect:/apps";
    }

    @PostMapping("/{id}/regenerate-key")
    public String regenerateKey(@PathVariable Long id) {
        appService.regenerateEncryptionKey(id);
        return "redirect:/apps";
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable Long id) {
        appService.deleteById(id);
        return "redirect:/apps";
    }
}
