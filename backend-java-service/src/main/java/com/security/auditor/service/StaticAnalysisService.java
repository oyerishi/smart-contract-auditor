package com.security.auditor.service;

import com.security.auditor.model.dto.ParsedContract;
import com.security.auditor.service.analysis.AnalysisRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class StaticAnalysisService {
    
    private final List<AnalysisRule> analysisRules;
    
    /**
     * Run all analysis rules on parsed contract
     */
    public List<AnalysisRule.Finding> analyzeContract(ParsedContract parsedContract) {
        log.info("Starting static analysis for contract: {}", parsedContract.getContractName());
        
        List<AnalysisRule.Finding> allFindings = new ArrayList<>();
        
        for (AnalysisRule rule : analysisRules) {
            try {
                log.debug("Running rule: {}", rule.getClass().getSimpleName());
                List<AnalysisRule.Finding> findings = rule.analyze(parsedContract);
                allFindings.addAll(findings);
                log.debug("Rule {} found {} issues", rule.getClass().getSimpleName(), findings.size());
            } catch (Exception e) {
                log.error("Error running rule {}: {}", rule.getClass().getSimpleName(), e.getMessage(), e);
            }
        }
        
        log.info("Static analysis completed. Total findings: {}", allFindings.size());
        return allFindings;
    }
    
    /**
     * Get findings by severity
     */
    public List<AnalysisRule.Finding> getFindingsBySeverity(List<AnalysisRule.Finding> findings, String severity) {
        return findings.stream()
                .filter(f -> f.getSeverity().equalsIgnoreCase(severity))
                .toList();
    }
    
    /**
     * Get findings by category
     */
    public List<AnalysisRule.Finding> getFindingsByCategory(List<AnalysisRule.Finding> findings, String category) {
        return findings.stream()
                .filter(f -> f.getCategory().equalsIgnoreCase(category))
                .toList();
    }
    
    /**
     * Count findings by severity
     */
    public java.util.Map<String, Long> countBySeverity(List<AnalysisRule.Finding> findings) {
        return findings.stream()
                .collect(java.util.stream.Collectors.groupingBy(
                        AnalysisRule.Finding::getSeverity,
                        java.util.stream.Collectors.counting()
                ));
    }
    
    /**
     * Get critical and high severity findings
     */
    public List<AnalysisRule.Finding> getCriticalAndHighFindings(List<AnalysisRule.Finding> findings) {
        return findings.stream()
                .filter(f -> f.getSeverity().equalsIgnoreCase("CRITICAL") || 
                           f.getSeverity().equalsIgnoreCase("HIGH"))
                .toList();
    }
}
