package com.security.auditor.service;

import com.security.auditor.exception.ValidationException;
import com.security.auditor.model.dto.AuthResponse;
import com.security.auditor.model.dto.LoginRequest;
import com.security.auditor.model.dto.RegisterRequest;
import com.security.auditor.model.entity.User;
import com.security.auditor.model.entity.UserRole;
import com.security.auditor.repository.UserRepository;
import com.security.auditor.util.InputSanitizer;
import com.security.auditor.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Slf4j
public class AuthService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    
    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            @Lazy AuthenticationManager authenticationManager,
            @Lazy UserDetailsService userDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }
    
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Attempting to register user: {}", request.getUsername());
        
        // Validate and sanitize inputs
        String sanitizedUsername = InputSanitizer.sanitizeUsername(request.getUsername());
        String sanitizedEmail = InputSanitizer.sanitizeEmail(request.getEmail());
        InputSanitizer.validatePassword(request.getPassword());
        
        String sanitizedFullName = request.getFullName() != null ? 
                InputSanitizer.sanitizeText(request.getFullName()) : null;
        
        // Check if username already exists
        if (userRepository.existsByUsername(sanitizedUsername)) {
            throw new ValidationException("username", "Username already exists");
        }
        
        // Check if email already exists
        if (userRepository.existsByEmail(sanitizedEmail)) {
            throw new ValidationException("email", "Email already exists");
        }
        
        // Create new user
        User user = new User();
        user.setUsername(sanitizedUsername);
        user.setEmail(sanitizedEmail);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFullName(sanitizedFullName);
        user.setRole(UserRole.USER);
        user.setIsActive(true);
        
        // Save user
        user = userRepository.save(user);
        log.info("User registered successfully: {}", user.getUsername());
        
        // Load UserDetails for token generation
        org.springframework.security.core.userdetails.UserDetails userDetails = 
                userDetailsService.loadUserByUsername(user.getUsername());
        
        // Generate tokens
        String token = jwtUtil.generateToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(24);
        
        return new AuthResponse(
                token,
                refreshToken,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                expiresAt
        );
    }
    
    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("Attempting to login user: {}", request.getUsername());
        
        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        
        // Get user details
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        // Check if user is active
        if (!user.getIsActive()) {
            throw new IllegalStateException("User account is disabled");
        }
        
        // Update last login
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);
        
        // Load UserDetails for token generation
        org.springframework.security.core.userdetails.UserDetails userDetails = 
                userDetailsService.loadUserByUsername(user.getUsername());
        
        // Generate tokens
        String token = jwtUtil.generateToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(24);
        
        log.info("User logged in successfully: {}", user.getUsername());
        
        return new AuthResponse(
                token,
                refreshToken,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                expiresAt
        );
    }
    
    public AuthResponse refreshToken(String refreshToken) {
        log.info("Attempting to refresh token");
        
        // Validate refresh token
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }
        
        // Extract username from token
        String username = jwtUtil.extractUsername(refreshToken);
        
        // Get user
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        // Check if user is active
        if (!user.getIsActive()) {
            throw new IllegalStateException("User account is disabled");
        }
        
        // Load UserDetails for token generation
        org.springframework.security.core.userdetails.UserDetails userDetails = 
                userDetailsService.loadUserByUsername(user.getUsername());
        
        // Generate new tokens
        String newToken = jwtUtil.generateToken(userDetails);
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getUsername());
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(24);
        
        log.info("Token refreshed successfully for user: {}", username);
        
        return new AuthResponse(
                newToken,
                newRefreshToken,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                expiresAt
        );
    }
    
    public void validateToken(String token) {
        if (!jwtUtil.validateToken(token)) {
            throw new IllegalArgumentException("Invalid token");
        }
    }
}
