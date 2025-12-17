package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ReportDTO {
    
    private Long scanId;
    private String contractName;
    private String blockchainType;
    private LocalDateTime scanDate;
    private String reportType; // PDF, JSON, HTML
    private String reportUrl;
    private Double overallRiskScore;
    private String riskLevel; // CRITICAL, HIGH, MEDIUM, LOW, SAFE
    private Integer totalVulnerabilities;
    private Map<String, Integer> vulnerabilityBreakdown; // severity -> count
    private Map<String, Integer> vulnerabilityByType; // type -> count
    private String summary;
    private String recommendations;
    private Long fileSize;
    private LocalDateTime generatedAt;
}
