package com.security.auditor.exception;

/**
 * Exception thrown when user is not authorized to perform an action
 */
public class UnauthorizedException extends RuntimeException {
    
    private final String userId;
    private final String resource;
    
    public UnauthorizedException(String message) {
        super(message);
        this.userId = null;
        this.resource = null;
    }
    
    public UnauthorizedException(String message, String userId, String resource) {
        super(message);
        this.userId = userId;
        this.resource = resource;
    }
    
    public String getUserId() {
        return userId;
    }
    
    public String getResource() {
        return resource;
    }
}
