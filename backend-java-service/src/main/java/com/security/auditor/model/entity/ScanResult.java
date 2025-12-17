package com.security.auditor.model.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * ScanResult Entity
 * Represents the results of a security scan
 */
@Entity
@Table(name = "scan_results", indexes = {
    @Index(name = "idx_scan_user", columnList = "user_id"),
    @Index(name = "idx_scan_contract", columnList = "contract_id"),
    @Index(name = "idx_scan_status", columnList = "status"),
    @Index(name = "idx_scan_created", columnList = "created_at")
})
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_id", nullable = false, unique = true, length = 36)
    private String scanId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ScanStatus status = ScanStatus.PENDING;

    @Column(name = "risk_score")
    private Double riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", length = 20)
    private RiskLevel riskLevel;

    // JSONB columns for PostgreSQL
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "static_findings", columnDefinition = "jsonb")
    private Map<String, Object> staticFindings;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ml_findings", columnDefinition = "jsonb")
    private Map<String, Object> mlFindings;

    @Column(name = "total_vulnerabilities")
    private Integer totalVulnerabilities = 0;

    @Column(name = "critical_count")
    private Integer criticalCount = 0;

    @Column(name = "high_count")
    private Integer highCount = 0;

    @Column(name = "medium_count")
    private Integer mediumCount = 0;

    @Column(name = "low_count")
    private Integer lowCount = 0;

    @Column(name = "scan_duration_ms")
    private Long scanDurationMs;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Relationships
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "contract_id", nullable = false)
    private Contract contract;

    @OneToMany(mappedBy = "scanResult", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    // Lifecycle callbacks
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (startedAt == null) {
            startedAt = LocalDateTime.now();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Constructors
    public ScanResult() {}

    public ScanResult(String scanId, User user, Contract contract) {
        this.scanId = scanId;
        this.user = user;
        this.contract = contract;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getScanId() {
        return scanId;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public Double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Double riskScore) {
        this.riskScore = riskScore;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public Map<String, Object> getStaticFindings() {
        return staticFindings;
    }

    public void setStaticFindings(Map<String, Object> staticFindings) {
        this.staticFindings = staticFindings;
    }

    public Map<String, Object> getMlFindings() {
        return mlFindings;
    }

    public void setMlFindings(Map<String, Object> mlFindings) {
        this.mlFindings = mlFindings;
    }

    public Integer getTotalVulnerabilities() {
        return totalVulnerabilities;
    }

    public void setTotalVulnerabilities(Integer totalVulnerabilities) {
        this.totalVulnerabilities = totalVulnerabilities;
    }

    public Integer getCriticalCount() {
        return criticalCount;
    }

    public void setCriticalCount(Integer criticalCount) {
        this.criticalCount = criticalCount;
    }

    public Integer getHighCount() {
        return highCount;
    }

    public void setHighCount(Integer highCount) {
        this.highCount = highCount;
    }

    public Integer getMediumCount() {
        return mediumCount;
    }

    public void setMediumCount(Integer mediumCount) {
        this.mediumCount = mediumCount;
    }

    public Integer getLowCount() {
        return lowCount;
    }

    public void setLowCount(Integer lowCount) {
        this.lowCount = lowCount;
    }

    public Long getScanDurationMs() {
        return scanDurationMs;
    }

    public void setScanDurationMs(Long scanDurationMs) {
        this.scanDurationMs = scanDurationMs;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public LocalDateTime getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(LocalDateTime startedAt) {
        this.startedAt = startedAt;
    }

    public LocalDateTime getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(LocalDateTime completedAt) {
        this.completedAt = completedAt;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Contract getContract() {
        return contract;
    }

    public void setContract(Contract contract) {
        this.contract = contract;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    // Helper methods
    public void markAsCompleted() {
        this.status = ScanStatus.COMPLETED;
        this.completedAt = LocalDateTime.now();
        if (this.startedAt != null) {
            this.scanDurationMs = java.time.Duration.between(this.startedAt, this.completedAt).toMillis();
        }
    }

    public void markAsFailed(String errorMessage) {
        this.status = ScanStatus.FAILED;
        this.errorMessage = errorMessage;
        this.completedAt = LocalDateTime.now();
    }

    public void calculateVulnerabilityCounts() {
        this.criticalCount = 0;
        this.highCount = 0;
        this.mediumCount = 0;
        this.lowCount = 0;

        for (Vulnerability vuln : this.vulnerabilities) {
            switch (vuln.getSeverity()) {
                case CRITICAL -> this.criticalCount++;
                case HIGH -> this.highCount++;
                case MEDIUM -> this.mediumCount++;
                case LOW -> this.lowCount++;
            }
        }
        this.totalVulnerabilities = this.vulnerabilities.size();
    }
}
