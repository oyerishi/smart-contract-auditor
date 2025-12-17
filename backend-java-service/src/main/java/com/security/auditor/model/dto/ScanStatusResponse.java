package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ScanStatusResponse {
    
    private String scanId;  // UUID string to match frontend
    private String id;      // alias for frontend compatibility
    private String status;
    private Integer progress; // 0-100
    private String currentStep;
    private String message;
    private String errorMessage;
    private Long estimatedTimeRemainingMs;
    
    public void setScanId(String scanId) {
        this.scanId = scanId;
        this.id = scanId;
    }
}
