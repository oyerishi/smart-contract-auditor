package com.security.auditor.repository;

import com.security.auditor.model.entity.Contract;
import com.security.auditor.model.entity.RiskLevel;
import com.security.auditor.model.entity.ScanResult;
import com.security.auditor.model.entity.ScanStatus;
import com.security.auditor.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * ScanResult Repository
 * Data access layer for ScanResult entity
 */
@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {

    /**
     * Find scan result by scan ID
     */
    Optional<ScanResult> findByScanId(String scanId);

    /**
     * Find scan result by scan ID with Contract eagerly fetched
     */
    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.contract LEFT JOIN FETCH s.vulnerabilities WHERE s.scanId = :scanId")
    Optional<ScanResult> findByScanIdWithContractAndVulnerabilities(@Param("scanId") String scanId);

    /**
     * Find all scan results by user
     */
    List<ScanResult> findByUser(User user);

    /**
     * Find all scan results by user ID
     */
    List<ScanResult> findByUserId(Long userId);

    /**
     * Find all scan results by user ID with Contract eagerly fetched
     */
    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.contract WHERE s.user.id = :userId ORDER BY s.createdAt DESC")
    List<ScanResult> findByUserIdWithContract(@Param("userId") Long userId);

    /**
     * Find all scan results by contract
     */
    List<ScanResult> findByContract(Contract contract);

    /**
     * Find all scan results by contract ID
     */
    List<ScanResult> findByContractId(Long contractId);

    /**
     * Find scan results by status
     */
    List<ScanResult> findByStatus(ScanStatus status);

    /**
     * Find scan results by user and status
     */
    List<ScanResult> findByUserIdAndStatus(Long userId, ScanStatus status);

    /**
     * Find scan results by risk level
     */
    List<ScanResult> findByRiskLevel(RiskLevel riskLevel);

    /**
     * Find scan results by user and risk level
     */
    List<ScanResult> findByUserIdAndRiskLevel(Long userId, RiskLevel riskLevel);

    /**
     * Find scan results with risk score greater than threshold
     */
    @Query("SELECT s FROM ScanResult s WHERE s.riskScore > :threshold")
    List<ScanResult> findHighRiskScans(@Param("threshold") Double threshold);

    /**
     * Find scan results created within date range
     */
    List<ScanResult> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Find scan results by user within date range
     */
    List<ScanResult> findByUserIdAndCreatedAtBetween(Long userId, LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Find recent scan results by user (ordered by created date)
     */
    @Query("SELECT s FROM ScanResult s WHERE s.user.id = :userId ORDER BY s.createdAt DESC")
    List<ScanResult> findRecentScansByUserId(@Param("userId") Long userId);

    /**
     * Find pending or in-progress scans
     */
    @Query("SELECT s FROM ScanResult s WHERE s.status IN ('PENDING', 'IN_PROGRESS')")
    List<ScanResult> findActiveSans();

    /**
     * Find failed scans
     */
    List<ScanResult> findByStatusAndErrorMessageIsNotNull(ScanStatus status);

    /**
     * Count scans by user
     */
    long countByUserId(Long userId);

    /**
     * Count scans by status
     */
    long countByStatus(ScanStatus status);

    /**
     * Count scans by user and status
     */
    long countByUserIdAndStatus(Long userId, ScanStatus status);

    /**
     * Find scans with vulnerabilities above threshold
     */
    @Query("SELECT s FROM ScanResult s WHERE s.totalVulnerabilities > :threshold")
    List<ScanResult> findScansWithManyVulnerabilities(@Param("threshold") Integer threshold);

    /**
     * Find scans with critical vulnerabilities
     */
    @Query("SELECT s FROM ScanResult s WHERE s.criticalCount > 0")
    List<ScanResult> findScansWithCriticalVulnerabilities();

    /**
     * Calculate average risk score for user
     */
    @Query("SELECT AVG(s.riskScore) FROM ScanResult s WHERE s.user.id = :userId AND s.status = 'COMPLETED'")
    Double calculateAverageRiskScoreForUser(@Param("userId") Long userId);

    /**
     * Calculate average scan duration
     */
    @Query("SELECT AVG(s.scanDurationMs) FROM ScanResult s WHERE s.status = 'COMPLETED' AND s.scanDurationMs IS NOT NULL")
    Double calculateAverageScanDuration();

    /**
     * Find longest running scans
     */
    @Query("SELECT s FROM ScanResult s WHERE s.scanDurationMs IS NOT NULL ORDER BY s.scanDurationMs DESC")
    List<ScanResult> findLongestScans();

    /**
     * Delete scan results by user ID
     */
    void deleteByUserId(Long userId);

    /**
     * Check if scan ID exists
     */
    boolean existsByScanId(String scanId);
}
