package org.wstt.riskengineserver.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.wstt.riskengineserver.entity.Device;
import org.wstt.riskengineserver.entity.DeviceReport;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface DeviceReportRepository extends JpaRepository<DeviceReport, Long> {
    Page<DeviceReport> findByDeviceOrderByReceivedAtDesc(Device device, Pageable pageable);
    long countByReceivedAtAfter(LocalDateTime after);
    List<DeviceReport> findByDeviceIdOrderByReceivedAtDesc(Long deviceId);

    @Query("SELECT r FROM DeviceReport r JOIN FETCH r.device JOIN FETCH r.app ORDER BY r.receivedAt DESC")
    Page<DeviceReport> findAllWithDeviceAndApp(Pageable pageable);

    @Query("SELECT r FROM DeviceReport r JOIN FETCH r.device JOIN FETCH r.app WHERE r.overallRiskLevel = :riskLevel ORDER BY r.receivedAt DESC")
    Page<DeviceReport> findByRiskLevelWithDeviceAndApp(String riskLevel, Pageable pageable);

    @Query("SELECT r FROM DeviceReport r JOIN FETCH r.device JOIN FETCH r.app WHERE r.id = :id")
    Optional<DeviceReport> findByIdWithDeviceAndApp(Long id);
}
