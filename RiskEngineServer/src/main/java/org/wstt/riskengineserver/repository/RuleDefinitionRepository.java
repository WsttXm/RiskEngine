package org.wstt.riskengineserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.wstt.riskengineserver.entity.RuleDefinition;

import java.util.List;

public interface RuleDefinitionRepository extends JpaRepository<RuleDefinition, Long> {
    List<RuleDefinition> findByEnabledTrue();
}
