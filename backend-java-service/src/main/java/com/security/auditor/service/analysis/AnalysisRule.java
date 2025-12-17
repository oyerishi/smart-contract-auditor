package com.security.auditor.service.analysis;

import com.security.auditor.model.dto.ParsedContract;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public abstract class AnalysisRule {
    
    protected final String ruleId;
    protected final String ruleName;
    protected final String severity;
    protected final String category;
    
    protected AnalysisRule(String ruleId, String ruleName, String severity, String category) {
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.severity = severity;
        this.category = category;
    }
    
    /**
     * Analyze parsed contract and return findings
     */
    public abstract List<Finding> analyze(ParsedContract contract);
    
    /**
     * Check if line contains pattern
     */
    protected boolean containsPattern(String line, Pattern pattern) {
        return pattern.matcher(line).find();
    }
    
    /**
     * Find all matches of pattern in text
     */
    protected List<String> findMatches(String text, Pattern pattern) {
        List<String> matches = new ArrayList<>();
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            matches.add(matcher.group());
        }
        return matches;
    }
    
    /**
     * Get line number from source code
     */
    protected int getLineNumber(String sourceCode, String searchText) {
        String[] lines = sourceCode.split("\n");
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains(searchText)) {
                return i + 1;
            }
        }
        return -1;
    }
    
    /**
     * Extract code snippet around line number
     */
    protected String getCodeSnippet(String sourceCode, int lineNumber, int contextLines) {
        String[] lines = sourceCode.split("\n");
        int start = Math.max(0, lineNumber - contextLines - 1);
        int end = Math.min(lines.length, lineNumber + contextLines);
        
        StringBuilder snippet = new StringBuilder();
        for (int i = start; i < end; i++) {
            snippet.append(lines[i]).append("\n");
        }
        return snippet.toString();
    }
    
    /**
     * Finding data class
     */
    @Data
    public static class Finding {
        private String ruleId;
        private String ruleName;
        private String severity;
        private String category;
        private String title;
        private String description;
        private String location;
        private Integer lineNumber;
        private String codeSnippet;
        private String recommendation;
        private Double confidenceScore;
        private String cweId;
        private String owaspCategory;
        
        public static FindingBuilder builder() {
            return new FindingBuilder();
        }
        
        public static class FindingBuilder {
            private Finding finding = new Finding();
            
            public FindingBuilder ruleId(String ruleId) {
                finding.ruleId = ruleId;
                return this;
            }
            
            public FindingBuilder ruleName(String ruleName) {
                finding.ruleName = ruleName;
                return this;
            }
            
            public FindingBuilder severity(String severity) {
                finding.severity = severity;
                return this;
            }
            
            public FindingBuilder category(String category) {
                finding.category = category;
                return this;
            }
            
            public FindingBuilder title(String title) {
                finding.title = title;
                return this;
            }
            
            public FindingBuilder description(String description) {
                finding.description = description;
                return this;
            }
            
            public FindingBuilder location(String location) {
                finding.location = location;
                return this;
            }
            
            public FindingBuilder lineNumber(Integer lineNumber) {
                finding.lineNumber = lineNumber;
                return this;
            }
            
            public FindingBuilder codeSnippet(String codeSnippet) {
                finding.codeSnippet = codeSnippet;
                return this;
            }
            
            public FindingBuilder recommendation(String recommendation) {
                finding.recommendation = recommendation;
                return this;
            }
            
            public FindingBuilder confidenceScore(Double confidenceScore) {
                finding.confidenceScore = confidenceScore;
                return this;
            }
            
            public FindingBuilder cweId(String cweId) {
                finding.cweId = cweId;
                return this;
            }
            
            public FindingBuilder owaspCategory(String owaspCategory) {
                finding.owaspCategory = owaspCategory;
                return this;
            }
            
            public Finding build() {
                return finding;
            }
        }
    }
}
