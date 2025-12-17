package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ScanResponse {
    
    private String scanId;
    private String id;  // alias for scanId for frontend compatibility
    private Long contractId;
    private String contractName;
    private String status;
    private Double riskScore;
    private Integer totalVulnerabilities;
    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;
    private Integer infoCount;
    private LocalDateTime startedAt;
    private LocalDateTime completedAt;
    private LocalDateTime uploadedAt;  // alias for startedAt for frontend compatibility
    private Long executionTimeMs;
    private List<VulnerabilityDTO> vulnerabilities;
    private List<VulnerabilityDTO> staticFindings;
    private List<VulnerabilityDTO> mlFindings;
    private List<VulnerabilityDTO> allVulnerabilities;
    private String sourceCode;
    private String reportUrl;
    private String errorMessage;
    
    // Helper method to set both scanId and id
    public void setScanId(String scanId) {
        this.scanId = scanId;
        this.id = scanId;
    }
    
    // Helper method to set both startedAt and uploadedAt
    public void setStartedAt(LocalDateTime startedAt) {
        this.startedAt = startedAt;
        this.uploadedAt = startedAt;
    }
}
