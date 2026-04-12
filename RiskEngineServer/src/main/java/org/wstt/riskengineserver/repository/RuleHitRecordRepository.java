package org.wstt.riskengineserver.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.wstt.riskengineserver.entity.Device;
import org.wstt.riskengineserver.entity.DeviceReport;
import org.wstt.riskengineserver.entity.RuleDefinition;
import org.wstt.riskengineserver.entity.RuleHitRecord;

import java.time.LocalDateTime;
import java.util.List;

public interface RuleHitRecordRepository extends JpaRepository<RuleHitRecord, Long> {
    @EntityGraph(attributePaths = {"rule"})
    Page<RuleHitRecord> findByDeviceOrderByHitAtDesc(Device device, Pageable pageable);
    long countByHitAtAfter(LocalDateTime after);
    boolean existsByRuleAndReport(RuleDefinition rule, DeviceReport report);
    void deleteByRule(RuleDefinition rule);

    @Query("SELECT DISTINCT h.device FROM RuleHitRecord h WHERE h.rule = :rule")
    List<Device> findDistinctDevicesByRule(@Param("rule") RuleDefinition rule);

    long countByRule(RuleDefinition rule);
}
