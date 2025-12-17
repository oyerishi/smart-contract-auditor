package com.security.auditor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Main Application Entry Point
 * Smart Contract Security Auditor Backend Service
 */
@SpringBootApplication
@EnableAsync
public class AuditorApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditorApplication.class, args);
    }
}
