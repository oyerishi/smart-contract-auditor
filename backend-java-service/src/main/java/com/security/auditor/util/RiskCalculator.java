package com.security.auditor.util;

import com.security.auditor.model.entity.RiskLevel;
import com.security.auditor.model.entity.Vulnerability;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Utility class for calculating risk scores based on vulnerabilities
 */
@Slf4j
public class RiskCalculator {
    
    // Severity weights for risk calculation
    private static final double CRITICAL_WEIGHT = 10.0;
    private static final double HIGH_WEIGHT = 7.0;
    private static final double MEDIUM_WEIGHT = 4.0;
    private static final double LOW_WEIGHT = 2.0;
    
    // Maximum risk score
    private static final double MAX_RISK_SCORE = 100.0;
    
    // Normalization factor (based on expected maximum vulnerabilities)
    private static final double NORMALIZATION_FACTOR = 10.0;
    
    private RiskCalculator() {
        // Private constructor to prevent instantiation
    }
    
    /**
     * Calculate overall risk score based on vulnerabilities
     * 
     * @param vulnerabilities List of vulnerabilities
     * @return Risk score between 0 and 100
     */
    public static double calculateRiskScore(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return 0.0;
        }
        
        Map<RiskLevel, Long> severityCounts = vulnerabilities.stream()
                .collect(Collectors.groupingBy(Vulnerability::getSeverity, Collectors.counting()));
        
        return calculateRiskScore(
                severityCounts.getOrDefault(RiskLevel.CRITICAL, 0L).intValue(),
                severityCounts.getOrDefault(RiskLevel.HIGH, 0L).intValue(),
                severityCounts.getOrDefault(RiskLevel.MEDIUM, 0L).intValue(),
                severityCounts.getOrDefault(RiskLevel.LOW, 0L).intValue()
        );
    }
    
    /**
     * Calculate risk score from severity counts
     * 
     * @param criticalCount Number of critical vulnerabilities
     * @param highCount Number of high vulnerabilities
     * @param mediumCount Number of medium vulnerabilities
     * @param lowCount Number of low vulnerabilities
     * @return Risk score between 0 and 100
     */
    public static double calculateRiskScore(int criticalCount, int highCount, int mediumCount, int lowCount) {
        double weightedSum = (criticalCount * CRITICAL_WEIGHT) +
                            (highCount * HIGH_WEIGHT) +
                            (mediumCount * MEDIUM_WEIGHT) +
                            (lowCount * LOW_WEIGHT);
        
        // Normalize to 0-100 scale
        double riskScore = (weightedSum / NORMALIZATION_FACTOR) * 10.0;
        
        // Cap at maximum score and round to 2 decimal places
        return Math.round(Math.min(riskScore, MAX_RISK_SCORE) * 100.0) / 100.0;
    }
    
    /**
     * Calculate risk score with confidence adjustment
     * 
     * @param vulnerabilities List of vulnerabilities with confidence scores
     * @return Adjusted risk score between 0 and 100
     */
    public static double calculateConfidenceAdjustedRiskScore(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return 0.0;
        }
        
        double weightedSum = vulnerabilities.stream()
                .mapToDouble(vuln -> {
                    double severityWeight = getSeverityWeight(vuln.getSeverity());
                    double confidence = vuln.getConfidenceScore() != null ? vuln.getConfidenceScore() : 1.0;
                    return severityWeight * confidence;
                })
                .sum();
        
        // Normalize to 0-100 scale
        double riskScore = (weightedSum / NORMALIZATION_FACTOR) * 10.0;
        
        // Cap at maximum score and round to 2 decimal places
        return Math.round(Math.min(riskScore, MAX_RISK_SCORE) * 100.0) / 100.0;
    }
    
    /**
     * Get risk level category from risk score
     * 
     * @param riskScore Risk score (0-100)
     * @return Risk level category as string
     */
    public static String getRiskLevel(double riskScore) {
        if (riskScore >= 70) return "CRITICAL";
        if (riskScore >= 50) return "HIGH";
        if (riskScore >= 30) return "MEDIUM";
        if (riskScore >= 10) return "LOW";
        return "MINIMAL";
    }
    
    /**
     * Get risk level as enum from risk score
     * 
     * @param riskScore Risk score (0-100)
     * @return RiskLevel enum
     */
    public static RiskLevel getRiskLevelEnum(double riskScore) {
        if (riskScore >= 70) return RiskLevel.CRITICAL;
        if (riskScore >= 50) return RiskLevel.HIGH;
        if (riskScore >= 30) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }
    
    /**
     * Calculate weighted severity score for a single vulnerability
     * 
     * @param severity Vulnerability severity
     * @param confidenceScore Confidence score (0.0 to 1.0)
     * @return Weighted score
     */
    public static double calculateVulnerabilityScore(RiskLevel severity, Double confidenceScore) {
        double severityWeight = getSeverityWeight(severity);
        double confidence = confidenceScore != null ? confidenceScore : 1.0;
        return severityWeight * confidence;
    }
    
    /**
     * Get severity weight for a risk level
     * 
     * @param severity Risk level
     * @return Weight value
     */
    public static double getSeverityWeight(RiskLevel severity) {
        return switch (severity) {
            case CRITICAL -> CRITICAL_WEIGHT;
            case HIGH -> HIGH_WEIGHT;
            case MEDIUM -> MEDIUM_WEIGHT;
            case LOW -> LOW_WEIGHT;
            default -> LOW_WEIGHT;
        };
    }
    
    /**
     * Calculate the percentage of critical and high severity vulnerabilities
     * 
     * @param vulnerabilities List of vulnerabilities
     * @return Percentage (0-100)
     */
    public static double calculateCriticalHighPercentage(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return 0.0;
        }
        
        long criticalHighCount = vulnerabilities.stream()
                .filter(v -> v.getSeverity() == RiskLevel.CRITICAL || v.getSeverity() == RiskLevel.HIGH)
                .count();
        
        return (criticalHighCount * 100.0) / vulnerabilities.size();
    }
    
    /**
     * Get severity distribution as percentages
     * 
     * @param vulnerabilities List of vulnerabilities
     * @return Map of severity to percentage
     */
    public static Map<RiskLevel, Double> getSeverityDistribution(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return Map.of(
                RiskLevel.CRITICAL, 0.0,
                RiskLevel.HIGH, 0.0,
                RiskLevel.MEDIUM, 0.0,
                RiskLevel.LOW, 0.0
            );
        }
        
        int total = vulnerabilities.size();
        Map<RiskLevel, Long> counts = vulnerabilities.stream()
                .collect(Collectors.groupingBy(Vulnerability::getSeverity, Collectors.counting()));
        
        return Map.of(
            RiskLevel.CRITICAL, (counts.getOrDefault(RiskLevel.CRITICAL, 0L) * 100.0) / total,
            RiskLevel.HIGH, (counts.getOrDefault(RiskLevel.HIGH, 0L) * 100.0) / total,
            RiskLevel.MEDIUM, (counts.getOrDefault(RiskLevel.MEDIUM, 0L) * 100.0) / total,
            RiskLevel.LOW, (counts.getOrDefault(RiskLevel.LOW, 0L) * 100.0) / total
        );
    }
    
    /**
     * Calculate comparative risk score (relative to industry baseline)
     * 
     * @param riskScore Calculated risk score
     * @param baselineScore Industry baseline score (default 30.0)
     * @return Comparative percentage (> 100 means worse than baseline)
     */
    public static double calculateComparativeRisk(double riskScore, double baselineScore) {
        if (baselineScore == 0) {
            return riskScore > 0 ? 200.0 : 100.0;
        }
        return (riskScore / baselineScore) * 100.0;
    }
    
    /**
     * Determine if a contract passes security threshold
     * 
     * @param riskScore Risk score
     * @param threshold Acceptable risk threshold (default 30.0)
     * @return true if passes, false otherwise
     */
    public static boolean passesSecurityThreshold(double riskScore, double threshold) {
        return riskScore < threshold;
    }
    
    /**
     * Calculate risk score trend (comparing two scores)
     * 
     * @param previousScore Previous risk score
     * @param currentScore Current risk score
     * @return Percentage change (negative means improvement)
     */
    public static double calculateRiskTrend(double previousScore, double currentScore) {
        if (previousScore == 0) {
            return currentScore > 0 ? 100.0 : 0.0;
        }
        return ((currentScore - previousScore) / previousScore) * 100.0;
    }
    
    /**
     * Get risk assessment summary
     * 
     * @param vulnerabilities List of vulnerabilities
     * @return Summary string
     */
    public static String getRiskAssessmentSummary(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return "No vulnerabilities detected. Contract appears secure.";
        }
        
        double riskScore = calculateRiskScore(vulnerabilities);
        String riskLevel = getRiskLevel(riskScore);
        int totalCount = vulnerabilities.size();
        
        Map<RiskLevel, Long> counts = vulnerabilities.stream()
                .collect(Collectors.groupingBy(Vulnerability::getSeverity, Collectors.counting()));
        
        int criticalCount = counts.getOrDefault(RiskLevel.CRITICAL, 0L).intValue();
        int highCount = counts.getOrDefault(RiskLevel.HIGH, 0L).intValue();
        
        StringBuilder summary = new StringBuilder();
        summary.append(String.format("Risk Level: %s (Score: %.2f/100)\n", riskLevel, riskScore));
        summary.append(String.format("Total Vulnerabilities: %d\n", totalCount));
        
        if (criticalCount > 0) {
            summary.append(String.format("⚠️ %d Critical vulnerabilities require immediate attention!\n", criticalCount));
        }
        if (highCount > 0) {
            summary.append(String.format("⚠️ %d High severity vulnerabilities should be addressed before deployment.\n", highCount));
        }
        
        if (riskScore >= 70) {
            summary.append("❌ NOT RECOMMENDED for deployment. Critical security issues found.");
        } else if (riskScore >= 50) {
            summary.append("⚠️ CAUTION: Significant security concerns. Address high-priority issues.");
        } else if (riskScore >= 30) {
            summary.append("⚠️ MODERATE: Some security issues detected. Review and fix recommended.");
        } else if (riskScore >= 10) {
            summary.append("✓ ACCEPTABLE: Minor security concerns. Consider fixing low-priority issues.");
        } else {
            summary.append("✓ GOOD: Minimal security concerns detected.");
        }
        
        return summary.toString();
    }
}
