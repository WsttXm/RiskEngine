package org.wstt.riskengineserver.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.wstt.riskengineserver.entity.Device;

import java.util.Optional;

public interface DeviceRepository extends JpaRepository<Device, Long> {
    Optional<Device> findByDeviceId(String deviceId);
    Page<Device> findByLastRiskLevel(String riskLevel, Pageable pageable);
    Page<Device> findByRiskMarkedTrue(Pageable pageable);
    long countByLastRiskLevelIn(java.util.List<String> levels);
    long countByRiskMarkedTrue();
}
