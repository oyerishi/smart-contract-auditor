package com.security.auditor.exception;

/**
 * Exception thrown when scan operations fail
 */
public class ScanException extends RuntimeException {
    
    private final String scanId;
    private final String phase;
    
    public ScanException(String message) {
        super(message);
        this.scanId = null;
        this.phase = null;
    }
    
    public ScanException(String message, Throwable cause) {
        super(message, cause);
        this.scanId = null;
        this.phase = null;
    }
    
    public ScanException(String message, String scanId, String phase) {
        super(message);
        this.scanId = scanId;
        this.phase = phase;
    }
    
    public ScanException(String message, String scanId, String phase, Throwable cause) {
        super(message, cause);
        this.scanId = scanId;
        this.phase = phase;
    }
    
    public String getScanId() {
        return scanId;
    }
    
    public String getPhase() {
        return phase;
    }
}
