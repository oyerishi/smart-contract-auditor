package com.security.auditor.model.dto;

import lombok.Data;

@Data
public class ApiResponse<T> {
    
    private boolean success;
    private String message;
    private T data;
    private ErrorDetails error;
    
    public ApiResponse() {}
    
    public ApiResponse(boolean success, String message, T data, ErrorDetails error) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.error = error;
    }
    
    @Data
    public static class ErrorDetails {
        private String code;
        private String detail;
        private Long timestamp;
        
        public ErrorDetails() {}
        
        public ErrorDetails(String code, String detail, Long timestamp) {
            this.code = code;
            this.detail = detail;
            this.timestamp = timestamp;
        }
    }
    
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<T>(true, null, data, null);
    }
    
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<T>(true, message, data, null);
    }
    
    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<T>(false, message, null, null);
    }
    
    public static <T> ApiResponse<T> error(String message, ErrorDetails error) {
        return new ApiResponse<T>(false, message, null, error);
    }
}
