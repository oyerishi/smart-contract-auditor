package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ContractDTO {
    
    private Long id;
    private String name;
    private String description;
    private String blockchainType;
    private String fileUrl;
    private String fileName;
    private Long fileSize;
    private String solcVersion;
    private LocalDateTime uploadedAt;
    private Long uploadedBy;
    private String uploaderUsername;
    private Integer scanCount;
    private Double latestRiskScore;
}
