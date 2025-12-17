package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MLAnalysisResponse {
    private Boolean success;
    private String message;
    private List<MLVulnerability> vulnerabilities;
    private MLMetrics metrics;
    private Long processingTimeMs;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MLVulnerability {
        private String id;
        private String name;           // vulnerability name (e.g., "tx.origin Authentication")
        private String category;       // category (e.g., "ACCESS_CONTROL")
        private String severity;
        private String description;
        private Double confidence;
        private String location;
        private Integer lineNumber;
        private String codeSnippet;
        private String recommendation;
        private String cweId;
        private String swcId;
        private Map<String, Object> metadata;
        
        // For backward compatibility, provide getType() that returns name or category
        public String getType() {
            return name != null ? name : category;
        }
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MLMetrics {
        private Double overallRiskScore;
        private Integer totalVulnerabilities;
        private Map<String, Integer> severityCount;
        private Map<String, Integer> categoryCount;
        private Double modelConfidence;
    }
}
