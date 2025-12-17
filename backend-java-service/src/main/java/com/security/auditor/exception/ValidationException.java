package com.security.auditor.exception;

import java.util.HashMap;
import java.util.Map;

/**
 * Exception thrown when validation fails
 */
public class ValidationException extends RuntimeException {
    
    private final Map<String, String> errors;
    
    public ValidationException(String message) {
        super(message);
        this.errors = new HashMap<>();
    }
    
    public ValidationException(String message, Map<String, String> errors) {
        super(message);
        this.errors = errors != null ? errors : new HashMap<>();
    }
    
    public ValidationException(String field, String error) {
        super("Validation failed");
        this.errors = new HashMap<>();
        this.errors.put(field, error);
    }
    
    public Map<String, String> getErrors() {
        return errors;
    }
    
    public void addError(String field, String error) {
        this.errors.put(field, error);
    }
}
