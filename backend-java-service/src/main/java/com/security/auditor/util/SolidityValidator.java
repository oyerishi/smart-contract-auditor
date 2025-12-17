package com.security.auditor.util;

import com.security.auditor.exception.ValidationException;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

/**
 * Utility class for validating Solidity smart contract code
 */
@Slf4j
public class SolidityValidator {
    
    private static final Pattern PRAGMA_PATTERN = Pattern.compile("pragma\\s+solidity\\s+[^;]+;");
    private static final Pattern CONTRACT_PATTERN = Pattern.compile("contract\\s+\\w+");
    private static final Pattern MALICIOUS_PATTERNS = Pattern.compile(
            "(?i)(eval|exec|system|shell_exec|passthru|popen|proc_open|" +
            "assert\\s*\\(.*\\$|create_function|unserialize|import.*os|__import__|" +
            "subprocess|command|runtime\\.exec)"
    );
    
    // Maximum file size: 5MB
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024;
    
    // Maximum lines of code
    private static final int MAX_LINES = 10000;
    
    private SolidityValidator() {
        // Private constructor to prevent instantiation
    }
    
    /**
     * Validate Solidity source code
     * 
     * @param sourceCode Solidity source code
     * @throws ValidationException if validation fails
     */
    public static void validateSolidityCode(String sourceCode) {
        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            throw new ValidationException("sourceCode", "Source code cannot be empty");
        }
        
        // Check file size
        if (sourceCode.length() > MAX_FILE_SIZE) {
            throw new ValidationException("sourceCode", 
                    String.format("Source code exceeds maximum size of %d bytes", MAX_FILE_SIZE));
        }
        
        // Check line count
        int lineCount = sourceCode.split("\n").length;
        if (lineCount > MAX_LINES) {
            throw new ValidationException("sourceCode", 
                    String.format("Source code exceeds maximum of %d lines", MAX_LINES));
        }
        
        // Check for pragma directive
        if (!PRAGMA_PATTERN.matcher(sourceCode).find()) {
            throw new ValidationException("sourceCode", 
                    "Invalid Solidity file: missing pragma directive");
        }
        
        // Check for contract definition
        if (!CONTRACT_PATTERN.matcher(sourceCode).find()) {
            throw new ValidationException("sourceCode", 
                    "Invalid Solidity file: no contract definition found");
        }
        
        // Check for potentially malicious code patterns
        if (MALICIOUS_PATTERNS.matcher(sourceCode).find()) {
            log.warn("Potentially malicious code pattern detected in source");
            throw new ValidationException("sourceCode", 
                    "Source code contains potentially malicious patterns");
        }
        
        // Check for balanced braces
        if (!hasBalancedBraces(sourceCode)) {
            throw new ValidationException("sourceCode", 
                    "Invalid Solidity file: unbalanced braces");
        }
    }
    
    /**
     * Check if code has balanced braces
     */
    private static boolean hasBalancedBraces(String code) {
        int braceCount = 0;
        boolean inString = false;
        boolean inComment = false;
        boolean inLineComment = false;
        
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            char next = (i + 1 < code.length()) ? code.charAt(i + 1) : '\0';
            
            // Handle line comments
            if (c == '/' && next == '/' && !inString && !inComment) {
                inLineComment = true;
                i++;
                continue;
            }
            if (inLineComment && c == '\n') {
                inLineComment = false;
                continue;
            }
            if (inLineComment) {
                continue;
            }
            
            // Handle block comments
            if (c == '/' && next == '*' && !inString) {
                inComment = true;
                i++;
                continue;
            }
            if (inComment && c == '*' && next == '/') {
                inComment = false;
                i++;
                continue;
            }
            if (inComment) {
                continue;
            }
            
            // Handle strings
            if (c == '"' && (i == 0 || code.charAt(i - 1) != '\\')) {
                inString = !inString;
                continue;
            }
            if (inString) {
                continue;
            }
            
            // Count braces
            if (c == '{') {
                braceCount++;
            } else if (c == '}') {
                braceCount--;
                if (braceCount < 0) {
                    return false;
                }
            }
        }
        
        return braceCount == 0;
    }
    
    /**
     * Validate Solidity version string
     */
    public static void validateSolidityVersion(String version) {
        if (version == null || version.trim().isEmpty()) {
            throw new ValidationException("version", "Solidity version cannot be empty");
        }
        
        Pattern versionPattern = Pattern.compile("^(\\^|>=|<=|>|<|=)?\\s*\\d+\\.\\d+\\.\\d+$");
        if (!versionPattern.matcher(version.trim()).matches()) {
            throw new ValidationException("version", 
                    "Invalid Solidity version format. Expected format: ^0.8.0 or 0.8.0");
        }
    }
    
    /**
     * Check if source code contains specific vulnerability patterns
     */
    public static boolean containsReentrancyPattern(String sourceCode) {
        Pattern callPattern = Pattern.compile("\\.call\\s*\\{");
        Pattern sendPattern = Pattern.compile("\\.send\\s*\\(");
        Pattern transferPattern = Pattern.compile("\\.transfer\\s*\\(");
        
        return callPattern.matcher(sourceCode).find() || 
               sendPattern.matcher(sourceCode).find() || 
               transferPattern.matcher(sourceCode).find();
    }
    
    /**
     * Check if source code uses SafeMath
     */
    public static boolean usesSafeMath(String sourceCode) {
        return sourceCode.contains("SafeMath") || 
               sourceCode.contains("using SafeMath for");
    }
    
    /**
     * Extract Solidity version from pragma
     */
    public static String extractSolidityVersion(String sourceCode) {
        Pattern pattern = Pattern.compile("pragma\\s+solidity\\s+([^;]+);");
        java.util.regex.Matcher matcher = pattern.matcher(sourceCode);
        
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        
        return null;
    }
}
