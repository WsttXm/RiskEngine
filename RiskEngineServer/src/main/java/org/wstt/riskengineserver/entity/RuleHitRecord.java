package org.wstt.riskengineserver.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * 规则命中记录 - 记录每次规则评估命中的详情
 */
@Entity
@Table(name = "rule_hit_record")
public class RuleHitRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rule_id", nullable = false)
    private RuleDefinition rule;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_id", nullable = false)
    private Device device;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "report_id", nullable = false)
    private DeviceReport report;

    @Column(nullable = false, updatable = false)
    private LocalDateTime hitAt;

    @Column(length = 512)
    private String detail;

    @PrePersist
    protected void onCreate() {
        hitAt = LocalDateTime.now();
    }

    // Getters and Setters

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public RuleDefinition getRule() { return rule; }
    public void setRule(RuleDefinition rule) { this.rule = rule; }

    public Device getDevice() { return device; }
    public void setDevice(Device device) { this.device = device; }

    public DeviceReport getReport() { return report; }
    public void setReport(DeviceReport report) { this.report = report; }

    public LocalDateTime getHitAt() { return hitAt; }

    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
}
