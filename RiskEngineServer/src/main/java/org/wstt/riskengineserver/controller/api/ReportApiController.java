package org.wstt.riskengineserver.controller.api;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.wstt.riskengineserver.dto.RiskReportDTO;
import org.wstt.riskengineserver.dto.ServerConfigResponse;
import org.wstt.riskengineserver.entity.App;
import org.wstt.riskengineserver.service.AppService;
import org.wstt.riskengineserver.service.EncryptionService;
import org.wstt.riskengineserver.service.ReportService;

import java.util.Map;
import java.util.Optional;

/**
 * SDK上报接口 - 接收客户端风控数据
 */
@RestController
@RequestMapping("/api/v1")
public class ReportApiController {

    private static final Logger log = LoggerFactory.getLogger(ReportApiController.class);

    private final ReportService reportService;
    private final AppService appService;
    private final EncryptionService encryptionService;
    private final Gson gson = new Gson();

    public ReportApiController(ReportService reportService,
                               AppService appService,
                               EncryptionService encryptionService) {
        this.reportService = reportService;
        this.appService = appService;
        this.encryptionService = encryptionService;
    }

    /**
     * 接收SDK上报的风控数据
     * 支持明文和AES-256-GCM加密两种模式, 通过X-Encrypted头区分
     */
    @PostMapping("/report")
    public ResponseEntity<?> receiveReport(
            @RequestHeader(value = "X-App-Key", required = false) String appKey,
            @RequestHeader(value = "X-Encrypted", defaultValue = "false") String encrypted,
            @RequestBody String body) {

        // 验证App-Key
        if (appKey == null || appKey.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "Missing X-App-Key header"));
        }

        Optional<App> appOpt = appService.findByAppKey(appKey);
        if (appOpt.isEmpty()) {
            return ResponseEntity.status(401)
                    .body(Map.of("status", "error", "message", "Invalid app key"));
        }

        App app = appOpt.get();
        if (!app.getEnabled()) {
            return ResponseEntity.status(403)
                    .body(Map.of("status", "error", "message", "App disabled"));
        }

        // 解密或直接使用明文
        String jsonPayload;
        if ("true".equalsIgnoreCase(encrypted)) {
            if (app.getEncryptionKey() == null || app.getEncryptionKey().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "App encryption key not configured"));
            }
            jsonPayload = encryptionService.decrypt(body, app.getEncryptionKey());
            if (jsonPayload == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "Decryption failed"));
            }
        } else {
            jsonPayload = body;
        }

        // 解析上报数据
        RiskReportDTO reportDTO;
        try {
            reportDTO = gson.fromJson(jsonPayload, RiskReportDTO.class);
        } catch (JsonSyntaxException e) {
            log.warn("JSON解析失败: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "Invalid JSON format"));
        }

        if (reportDTO == null || reportDTO.getFingerprint() == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "Invalid report data"));
        }

        // 处理上报
        ServerConfigResponse response = reportService.processReport(app, reportDTO);
        return ResponseEntity.ok(response);
    }
}
