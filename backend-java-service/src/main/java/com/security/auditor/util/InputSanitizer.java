package com.security.auditor.util;

import com.security.auditor.exception.ValidationException;

import java.util.regex.Pattern;

/**
 * Utility class for sanitizing user inputs
 */
public class InputSanitizer {
    
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );
    
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,30}$");
    
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)<script|javascript:|onerror=|onload=|<iframe|eval\\(|alert\\(",
            Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i)(union.*select|insert.*into|delete.*from|drop.*table|update.*set|" +
            "exec\\(|execute\\(|script|<script|javascript|\\bor\\b.*=|\\band\\b.*=)",
            Pattern.CASE_INSENSITIVE
    );
    
    private InputSanitizer() {
        // Private constructor to prevent instantiation
    }
    
    /**
     * Sanitize HTML content to prevent XSS attacks
     */
    public static String sanitizeHtml(String input) {
        if (input == null) {
            return null;
        }
        
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }
    
    /**
     * Sanitize string to prevent SQL injection
     */
    public static String sanitizeSql(String input) {
        if (input == null) {
            return null;
        }
        
        // Escape single quotes
        return input.replace("'", "''")
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"");
    }
    
    /**
     * Validate and sanitize email address
     */
    public static String sanitizeEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new ValidationException("email", "Email cannot be empty");
        }
        
        String trimmedEmail = email.trim().toLowerCase();
        
        if (trimmedEmail.length() > 254) {
            throw new ValidationException("email", "Email is too long");
        }
        
        if (!EMAIL_PATTERN.matcher(trimmedEmail).matches()) {
            throw new ValidationException("email", "Invalid email format");
        }
        
        return trimmedEmail;
    }
    
    /**
     * Validate and sanitize username
     */
    public static String sanitizeUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new ValidationException("username", "Username cannot be empty");
        }
        
        String trimmedUsername = username.trim();
        
        if (!USERNAME_PATTERN.matcher(trimmedUsername).matches()) {
            throw new ValidationException("username", 
                    "Username must be 3-30 characters and contain only letters, numbers, hyphens, and underscores");
        }
        
        return trimmedUsername;
    }
    
    /**
     * Check for XSS patterns
     */
    public static void checkForXss(String input) {
        if (input != null && XSS_PATTERN.matcher(input).find()) {
            throw new ValidationException("input", 
                    "Input contains potentially malicious content");
        }
    }
    
    /**
     * Check for SQL injection patterns
     */
    public static void checkForSqlInjection(String input) {
        if (input != null && SQL_INJECTION_PATTERN.matcher(input).find()) {
            throw new ValidationException("input", 
                    "Input contains potentially malicious SQL patterns");
        }
    }
    
    /**
     * Sanitize general text input
     */
    public static String sanitizeText(String input) {
        if (input == null) {
            return null;
        }
        
        // Check for malicious patterns
        checkForXss(input);
        
        // Trim and normalize whitespace
        String sanitized = input.trim().replaceAll("\\s+", " ");
        
        // Remove control characters except newlines and tabs
        sanitized = sanitized.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
        
        return sanitized;
    }
    
    /**
     * Sanitize and validate password
     */
    public static void validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new ValidationException("password", "Password cannot be empty");
        }
        
        if (password.length() < 8) {
            throw new ValidationException("password", "Password must be at least 8 characters long");
        }
        
        if (password.length() > 128) {
            throw new ValidationException("password", "Password is too long (maximum 128 characters)");
        }
        
        // Check for at least one uppercase letter
        if (!password.matches(".*[A-Z].*")) {
            throw new ValidationException("password", 
                    "Password must contain at least one uppercase letter");
        }
        
        // Check for at least one lowercase letter
        if (!password.matches(".*[a-z].*")) {
            throw new ValidationException("password", 
                    "Password must contain at least one lowercase letter");
        }
        
        // Check for at least one digit
        if (!password.matches(".*\\d.*")) {
            throw new ValidationException("password", 
                    "Password must contain at least one digit");
        }
        
        // Check for at least one special character
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            throw new ValidationException("password", 
                    "Password must contain at least one special character");
        }
    }
    
    /**
     * Sanitize contract name
     */
    public static String sanitizeContractName(String contractName) {
        if (contractName == null || contractName.trim().isEmpty()) {
            throw new ValidationException("contractName", "Contract name cannot be empty");
        }
        
        String sanitized = contractName.trim();
        
        if (sanitized.length() > 100) {
            throw new ValidationException("contractName", 
                    "Contract name is too long (maximum 100 characters)");
        }
        
        // Allow filenames with extensions (e.g., "Contract.sol")
        // or simple identifiers (e.g., "MyContract")
        if (!sanitized.matches("^[a-zA-Z][a-zA-Z0-9_.-]*$")) {
            throw new ValidationException("contractName", 
                    "Contract name must start with a letter and contain only letters, numbers, underscores, dots, and hyphens");
        }
        
        return sanitized;
    }
    
    /**
     * Truncate string to maximum length
     */
    public static String truncate(String input, int maxLength) {
        if (input == null) {
            return null;
        }
        
        if (input.length() <= maxLength) {
            return input;
        }
        
        return input.substring(0, maxLength);
    }
    
    /**
     * Remove all HTML tags
     */
    public static String stripHtmlTags(String input) {
        if (input == null) {
            return null;
        }
        
        return input.replaceAll("<[^>]*>", "");
    }
}
