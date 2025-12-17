package com.security.auditor.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Database Connection Verifier
 * Tests database connectivity on application startup
 */
@Configuration
public class DatabaseConnectionVerifier {

    private static final Logger log = LoggerFactory.getLogger(DatabaseConnectionVerifier.class);

    @Autowired
    private DataSource dataSource;

    @PostConstruct
    public void verifyConnection() {
        try (Connection connection = dataSource.getConnection()) {
            if (connection != null && !connection.isClosed()) {
                log.info("✅ Database connection established successfully!");
                log.info("Database URL: {}", connection.getMetaData().getURL());
                log.info("Database Product: {}", connection.getMetaData().getDatabaseProductName());
                log.info("Database Version: {}", connection.getMetaData().getDatabaseProductVersion());
            }
        } catch (SQLException e) {
            log.error("❌ Failed to connect to database: {}", e.getMessage());
            log.warn("Application will continue but database operations will fail");
            log.warn("Please ensure PostgreSQL is running and credentials are correct");
        }
    }
}
