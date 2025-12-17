package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    
    private String token;
    private String refreshToken;
    @Builder.Default
    private String tokenType = "Bearer";
    private Long userId;
    private String username;
    private String email;
    private String role;
    private LocalDateTime expiresAt;
    
    public AuthResponse(String token, String refreshToken, Long userId, String username, String email, String role, LocalDateTime expiresAt) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.role = role;
        this.expiresAt = expiresAt;
        this.tokenType = "Bearer";
    }
}
