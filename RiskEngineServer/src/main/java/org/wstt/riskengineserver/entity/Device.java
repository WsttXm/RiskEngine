package org.wstt.riskengineserver.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * 设备记录 - 通过指纹信息生成唯一设备ID
 */
@Entity
@Table(name = "device")
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 设备唯一标识, 由指纹关键字段SHA-256生成 */
    @Column(nullable = false, unique = true, length = 64)
    private String deviceId;

    @Column(nullable = false, updatable = false)
    private LocalDateTime firstSeenAt;

    @Column(nullable = false)
    private LocalDateTime lastSeenAt;

    /** 最近一次上报的综合风险等级 */
    @Column(nullable = false, length = 16)
    private String lastRiskLevel = "SAFE";

    /** 是否被运营手动标记为风险设备 */
    @Column(nullable = false)
    private Boolean riskMarked = false;

    /** 手动标记备注 */
    @Column(length = 512)
    private String riskNote;

    /** 上报次数 */
    @Column(nullable = false)
    private Integer reportCount = 0;

    @PrePersist
    protected void onCreate() {
        firstSeenAt = LocalDateTime.now();
        lastSeenAt = LocalDateTime.now();
    }

    // Getters and Setters

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    public LocalDateTime getFirstSeenAt() { return firstSeenAt; }
    public LocalDateTime getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(LocalDateTime lastSeenAt) { this.lastSeenAt = lastSeenAt; }

    public String getLastRiskLevel() { return lastRiskLevel; }
    public void setLastRiskLevel(String lastRiskLevel) { this.lastRiskLevel = lastRiskLevel; }

    public Boolean getRiskMarked() { return riskMarked; }
    public void setRiskMarked(Boolean riskMarked) { this.riskMarked = riskMarked; }

    public String getRiskNote() { return riskNote; }
    public void setRiskNote(String riskNote) { this.riskNote = riskNote; }

    public Integer getReportCount() { return reportCount; }
    public void setReportCount(Integer reportCount) { this.reportCount = reportCount; }
}
