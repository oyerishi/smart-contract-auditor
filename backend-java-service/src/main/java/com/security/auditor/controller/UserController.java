package com.security.auditor.controller;

import com.security.auditor.exception.ResourceNotFoundException;
import com.security.auditor.exception.UnauthorizedException;
import com.security.auditor.exception.ValidationException;
import com.security.auditor.model.dto.*;
import com.security.auditor.model.entity.ScanResult;
import com.security.auditor.model.entity.User;
import com.security.auditor.repository.ScanResultRepository;
import com.security.auditor.repository.UserRepository;
import com.security.auditor.util.InputSanitizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    
    private final UserRepository userRepository;
    private final ScanResultRepository scanResultRepository;
    private final PasswordEncoder passwordEncoder;
    
    /**
     * Get current user profile
     * GET /api/users/profile
     */
    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<UserDTO>> getProfile(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("Profile request for user: {}", userDetails.getUsername());
        
        try {
            User user = getUserFromDetails(userDetails);
            UserDTO userDTO = toUserDTO(user);
            
            return ResponseEntity.ok(ApiResponse.success(userDTO));
            
        } catch (Exception e) {
            log.error("Error getting profile: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve profile"));
        }
    }
    
    /**
     * Update user profile
     * PUT /api/users/profile
     */
    @PutMapping("/profile")
    public ResponseEntity<ApiResponse<UserDTO>> updateProfile(
            @RequestBody UserDTO userDTO,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Update profile request for user: {}", userDetails.getUsername());
        
        try {
            User user = getUserFromDetails(userDetails);
            
            // Update allowed fields
            if (userDTO.getFullName() != null) {
                String sanitizedFullName = InputSanitizer.sanitizeText(userDTO.getFullName());
                user.setFullName(sanitizedFullName);
            }
            if (userDTO.getEmail() != null && !userDTO.getEmail().equals(user.getEmail())) {
                // Validate and sanitize email
                String sanitizedEmail = InputSanitizer.sanitizeEmail(userDTO.getEmail());
                
                // Check if email is already taken
                if (userRepository.findByEmail(sanitizedEmail).isPresent()) {
                    return ResponseEntity.badRequest()
                            .body(ApiResponse.error("Email already in use"));
                }
                user.setEmail(sanitizedEmail);
            }
            
            user = userRepository.save(user);
            
            return ResponseEntity.ok(ApiResponse.success(toUserDTO(user)));
            
        } catch (Exception e) {
            log.error("Error updating profile: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to update profile"));
        }
    }
    
    /**
     * Change password
     * POST /api/users/change-password
     */
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @RequestBody Map<String, String> request,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Change password request for user: {}", userDetails.getUsername());
        
        try {
            String currentPassword = request.get("currentPassword");
            String newPassword = request.get("newPassword");
            
            if (currentPassword == null || newPassword == null) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Current password and new password are required"));
            }
            
            // Validate new password
            InputSanitizer.validatePassword(newPassword);
            
            User user = getUserFromDetails(userDetails);
            
            // Verify current password
            if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Current password is incorrect"));
            }
            
            // Update password
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            
            return ResponseEntity.ok(ApiResponse.success("Password changed successfully"));
            
        } catch (Exception e) {
            log.error("Error changing password: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to change password"));
        }
    }
    
    /**
     * Get user statistics
     * GET /api/users/stats
     */
    @GetMapping("/stats")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserStats(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("User stats request for: {}", userDetails.getUsername());
        
        try {
            User user = getUserFromDetails(userDetails);
            
            List<ScanResult> scans = scanResultRepository.findByUser(user);
            
            Map<String, Object> stats = new HashMap<>();
            stats.put("totalScans", scans.size());
            stats.put("completedScans", scans.stream()
                    .filter(s -> s.getStatus().name().equals("COMPLETED"))
                    .count());
            stats.put("failedScans", scans.stream()
                    .filter(s -> s.getStatus().name().equals("FAILED"))
                    .count());
            stats.put("pendingScans", scans.stream()
                    .filter(s -> s.getStatus().name().equals("PENDING") || 
                               s.getStatus().name().equals("IN_PROGRESS"))
                    .count());
            
            // Calculate total vulnerabilities found
            long totalVulnerabilities = scans.stream()
                    .filter(s -> s.getStatus().name().equals("COMPLETED"))
                    .mapToLong(s -> s.getTotalVulnerabilities() != null ? s.getTotalVulnerabilities() : 0)
                    .sum();
            stats.put("totalVulnerabilitiesFound", totalVulnerabilities);
            
            // Calculate average risk score
            double avgRiskScore = scans.stream()
                    .filter(s -> s.getStatus().name().equals("COMPLETED") && s.getRiskScore() != null)
                    .mapToDouble(ScanResult::getRiskScore)
                    .average()
                    .orElse(0.0);
            stats.put("averageRiskScore", Math.round(avgRiskScore * 100.0) / 100.0);
            
            // Vulnerability breakdown
            Map<String, Long> severityBreakdown = new HashMap<>();
            severityBreakdown.put("critical", scans.stream()
                    .filter(s -> s.getStatus().name().equals("COMPLETED"))
                    .mapToLong(s -> s.getCriticalCount() != null ? s.getCriticalCount() : 0)
                    .sum());
            severityBreakdown.put("high", scans.stream()
                    .filter(s -> s.getStatus().name().equals("COMPLETED"))
                    .mapToLong(s -> s.getHighCount() != null ? s.getHighCount() : 0)
                    .sum());
            severityBreakdown.put("medium", scans.stream()
                    .filter(s -> s.getStatus().name().equals("COMPLETED"))
                    .mapToLong(s -> s.getMediumCount() != null ? s.getMediumCount() : 0)
                    .sum());
            severityBreakdown.put("low", scans.stream()
                    .filter(s -> s.getStatus().name().equals("COMPLETED"))
                    .mapToLong(s -> s.getLowCount() != null ? s.getLowCount() : 0)
                    .sum());
            stats.put("severityBreakdown", severityBreakdown);
            
            // Most recent scan
            scans.stream()
                    .max((a, b) -> a.getStartedAt().compareTo(b.getStartedAt()))
                    .ifPresent(recent -> {
                        Map<String, Object> recentScan = new HashMap<>();
                        recentScan.put("scanId", recent.getScanId());
                        recentScan.put("status", recent.getStatus().name());
                        recentScan.put("startedAt", recent.getStartedAt());
                        recentScan.put("riskScore", recent.getRiskScore());
                        stats.put("mostRecentScan", recentScan);
                    });
            
            return ResponseEntity.ok(ApiResponse.success(stats));
            
        } catch (Exception e) {
            log.error("Error getting user stats: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve statistics"));
        }
    }
    
    /**
     * Delete user account
     * DELETE /api/users/account
     */
    @DeleteMapping("/account")
    public ResponseEntity<ApiResponse<String>> deleteAccount(
            @RequestBody Map<String, String> request,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.warn("Account deletion request for user: {}", userDetails.getUsername());
        
        try {
            String password = request.get("password");
            
            if (password == null) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Password confirmation is required"));
            }
            
            User user = getUserFromDetails(userDetails);
            
            // Verify password
            if (!passwordEncoder.matches(password, user.getPassword())) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Password is incorrect"));
            }
            
            // Soft delete by deactivating
            user.setIsActive(false);
            userRepository.save(user);
            
            log.info("User account deactivated: {}", user.getUsername());
            
            return ResponseEntity.ok(ApiResponse.success("Account deleted successfully"));
            
        } catch (Exception e) {
            log.error("Error deleting account: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to delete account"));
        }
    }
    
    /**
     * Get user preferences/settings
     * GET /api/users/settings
     */
    @GetMapping("/settings")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSettings(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("Settings request for user: {}", userDetails.getUsername());
        
        try {
            User user = getUserFromDetails(userDetails);
            
            Map<String, Object> settings = new HashMap<>();
            settings.put("username", user.getUsername());
            settings.put("email", user.getEmail());
            settings.put("fullName", user.getFullName());
            settings.put("role", user.getRole().name());
            settings.put("emailVerified", user.getIsEmailVerified());
            settings.put("accountCreatedAt", user.getCreatedAt());
            settings.put("lastLoginAt", user.getLastLogin());
            
            return ResponseEntity.ok(ApiResponse.success(settings));
            
        } catch (Exception e) {
            log.error("Error getting settings: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve settings"));
        }
    }
    
    /**
     * Update user settings
     * PATCH /api/users/settings
     */
    @PatchMapping("/settings")
    public ResponseEntity<ApiResponse<String>> updateSettings(
            @RequestBody Map<String, Object> settings,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Update settings request for user: {}", userDetails.getUsername());
        
        try {
            User user = getUserFromDetails(userDetails);
            
            // Update email verification preference (if provided)
            if (settings.containsKey("emailNotifications")) {
                // This would require adding an emailNotifications field to User entity
                log.debug("Email notifications preference: {}", settings.get("emailNotifications"));
            }
            
            userRepository.save(user);
            
            return ResponseEntity.ok(ApiResponse.success("Settings updated successfully"));
            
        } catch (Exception e) {
            log.error("Error updating settings: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to update settings"));
        }
    }
    
    /**
     * Get user activity log
     * GET /api/users/activity
     */
    @GetMapping("/activity")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getActivity(
            @RequestParam(defaultValue = "10") int limit,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("Activity log request for user: {}", userDetails.getUsername());
        
        try {
            User user = getUserFromDetails(userDetails);
            
            List<ScanResult> recentScans = scanResultRepository.findByUser(user);
            recentScans.sort((a, b) -> b.getStartedAt().compareTo(a.getStartedAt()));
            
            List<Map<String, Object>> activity = recentScans.stream()
                    .limit(limit)
                    .map(scan -> {
                        Map<String, Object> item = new HashMap<>();
                        item.put("type", "SCAN");
                        item.put("scanId", scan.getScanId());
                        item.put("status", scan.getStatus().name());
                        item.put("timestamp", scan.getStartedAt());
                        item.put("contractName", scan.getContract() != null ? 
                                scan.getContract().getFilename() : "Unknown");
                        if (scan.getStatus().name().equals("COMPLETED")) {
                            item.put("vulnerabilitiesFound", scan.getTotalVulnerabilities());
                            item.put("riskScore", scan.getRiskScore());
                        }
                        return item;
                    })
                    .toList();
            
            return ResponseEntity.ok(ApiResponse.success(activity));
            
        } catch (Exception e) {
            log.error("Error getting activity: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve activity"));
        }
    }
    
    // Helper methods
    
    private User getUserFromDetails(UserDetails userDetails) {
        if (userDetails instanceof User) {
            return (User) userDetails;
        }
        
        // Fallback: query by username
        return userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User", "username", userDetails.getUsername()));
    }
    
    private UserDTO toUserDTO(User user) {
        UserDTO dto = new UserDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setFullName(user.getFullName());
        dto.setRole(user.getRole().name());
        dto.setActive(user.getIsActive());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setLastLogin(user.getLastLogin());
        
        return dto;
    }
}
