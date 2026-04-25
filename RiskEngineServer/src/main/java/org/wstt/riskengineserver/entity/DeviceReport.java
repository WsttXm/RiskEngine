package org.wstt.riskengineserver.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * SDK上报记录 - 每次SDK上报对应一条记录
 */
@Entity
@Table(name = "device_report")
public class DeviceReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_id", nullable = false)
    private Device device;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "app_id", nullable = false)
    private App app;

    @Column(length = 16)
    private String sdkVersion;

    @Column(nullable = false, length = 16)
    private String overallRiskLevel;

    /** SDK综合得分 */
    private Integer riskScore;

    /** SDK理论满分 */
    private Integer maxRiskScore;

    /** 危险信号数量 */
    private Integer dangerCount;

    /** 告警信号数量 */
    private Integer warningCount;

    /** 完整指纹JSON数据 */
    @Column(columnDefinition = "MEDIUMTEXT")
    private String fingerprintJson;

    /** 检测结果JSON数据 */
    @Column(columnDefinition = "MEDIUMTEXT")
    private String detectionsJson;

    /** SDK端上报时间戳 */
    private Long reportTimestamp;

    /** 服务端接收时间 */
    @Column(nullable = false, updatable = false)
    private LocalDateTime receivedAt;

    @PrePersist
    protected void onCreate() {
        receivedAt = LocalDateTime.now();
    }

    // Getters and Setters

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Device getDevice() { return device; }
    public void setDevice(Device device) { this.device = device; }

    public App getApp() { return app; }
    public void setApp(App app) { this.app = app; }

    public String getSdkVersion() { return sdkVersion; }
    public void setSdkVersion(String sdkVersion) { this.sdkVersion = sdkVersion; }

    public String getOverallRiskLevel() { return overallRiskLevel; }
    public void setOverallRiskLevel(String overallRiskLevel) { this.overallRiskLevel = overallRiskLevel; }

    public Integer getRiskScore() { return riskScore; }
    public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }

    public Integer getMaxRiskScore() { return maxRiskScore; }
    public void setMaxRiskScore(Integer maxRiskScore) { this.maxRiskScore = maxRiskScore; }

    public Integer getDangerCount() { return dangerCount; }
    public void setDangerCount(Integer dangerCount) { this.dangerCount = dangerCount; }

    public Integer getWarningCount() { return warningCount; }
    public void setWarningCount(Integer warningCount) { this.warningCount = warningCount; }

    public String getFingerprintJson() { return fingerprintJson; }
    public void setFingerprintJson(String fingerprintJson) { this.fingerprintJson = fingerprintJson; }

    public String getDetectionsJson() { return detectionsJson; }
    public void setDetectionsJson(String detectionsJson) { this.detectionsJson = detectionsJson; }

    public Long getReportTimestamp() { return reportTimestamp; }
    public void setReportTimestamp(Long reportTimestamp) { this.reportTimestamp = reportTimestamp; }

    public LocalDateTime getReceivedAt() { return receivedAt; }
}
