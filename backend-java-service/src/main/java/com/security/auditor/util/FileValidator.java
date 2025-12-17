package com.security.auditor.util;

import com.security.auditor.exception.ValidationException;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Utility class for validating file uploads
 */
@Slf4j
public class FileValidator {
    
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(".sol", ".solidity");
    private static final List<String> ALLOWED_MIME_TYPES = Arrays.asList(
            "text/plain",
            "application/octet-stream",
            "text/x-solidity"
    );
    
    // Maximum file size: 5MB
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024;
    
    // Minimum file size: 10 bytes
    private static final long MIN_FILE_SIZE = 10;
    
    private static final Pattern FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\.]+$");
    
    private FileValidator() {
        // Private constructor to prevent instantiation
    }
    
    /**
     * Validate uploaded file
     */
    public static void validateFile(String fileName, String contentType, long fileSize) {
        validateFileName(fileName);
        validateFileSize(fileSize);
        validateFileExtension(fileName);
        validateContentType(contentType);
    }
    
    /**
     * Validate file name
     */
    public static void validateFileName(String fileName) {
        if (fileName == null || fileName.trim().isEmpty()) {
            throw new ValidationException("fileName", "File name cannot be empty");
        }
        
        if (fileName.length() > 255) {
            throw new ValidationException("fileName", "File name is too long (max 255 characters)");
        }
        
        // Check for path traversal attempts
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            throw new ValidationException("fileName", "Invalid file name: path traversal detected");
        }
        
        // Check for valid characters
        if (!FILENAME_PATTERN.matcher(fileName).matches()) {
            throw new ValidationException("fileName", 
                    "Invalid file name: only alphanumeric characters, hyphens, underscores, and dots are allowed");
        }
    }
    
    /**
     * Validate file size
     */
    public static void validateFileSize(long fileSize) {
        if (fileSize < MIN_FILE_SIZE) {
            throw new ValidationException("fileSize", 
                    String.format("File is too small (minimum %d bytes)", MIN_FILE_SIZE));
        }
        
        if (fileSize > MAX_FILE_SIZE) {
            throw new ValidationException("fileSize", 
                    String.format("File is too large (maximum %d MB)", MAX_FILE_SIZE / (1024 * 1024)));
        }
    }
    
    /**
     * Validate file extension
     */
    public static void validateFileExtension(String fileName) {
        String extension = getFileExtension(fileName);
        
        if (extension == null || !ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new ValidationException("fileName", 
                    "Invalid file type. Only .sol files are allowed");
        }
    }
    
    /**
     * Validate content type
     */
    public static void validateContentType(String contentType) {
        if (contentType == null || contentType.trim().isEmpty()) {
            log.warn("Content type is missing, skipping validation");
            return;
        }
        
        // Extract base content type (remove charset, etc.)
        String baseContentType = contentType.split(";")[0].trim();
        
        if (!ALLOWED_MIME_TYPES.contains(baseContentType)) {
            log.warn("Unexpected content type: {}", baseContentType);
            // Don't throw exception as some browsers send different MIME types for .sol files
        }
    }
    
    /**
     * Get file extension
     */
    public static String getFileExtension(String fileName) {
        if (fileName == null || !fileName.contains(".")) {
            return null;
        }
        
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot == -1 || lastDot == fileName.length() - 1) {
            return null;
        }
        
        return fileName.substring(lastDot);
    }
    
    /**
     * Sanitize file name
     */
    public static String sanitizeFileName(String fileName) {
        if (fileName == null) {
            return null;
        }
        
        // Remove path components
        fileName = fileName.replaceAll(".*[/\\\\]", "");
        
        // Remove non-alphanumeric characters except dot, hyphen, underscore
        fileName = fileName.replaceAll("[^a-zA-Z0-9.\\-_]", "_");
        
        // Limit length
        if (fileName.length() > 255) {
            String extension = getFileExtension(fileName);
            int maxNameLength = 255 - (extension != null ? extension.length() : 0);
            fileName = fileName.substring(0, maxNameLength) + (extension != null ? extension : "");
        }
        
        return fileName;
    }
    
    /**
     * Check if file is a Solidity file
     */
    public static boolean isSolidityFile(String fileName) {
        String extension = getFileExtension(fileName);
        return extension != null && ALLOWED_EXTENSIONS.contains(extension.toLowerCase());
    }
}
