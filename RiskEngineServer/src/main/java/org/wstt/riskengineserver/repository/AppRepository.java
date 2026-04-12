package org.wstt.riskengineserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.wstt.riskengineserver.entity.App;

import java.util.Optional;

public interface AppRepository extends JpaRepository<App, Long> {
    Optional<App> findByAppKey(String appKey);
    boolean existsByAppKey(String appKey);
}
