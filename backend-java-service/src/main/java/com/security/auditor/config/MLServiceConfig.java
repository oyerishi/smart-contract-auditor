package com.security.auditor.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
@ConfigurationProperties(prefix = "ml.service")
@Data
public class MLServiceConfig {
    
    private String baseUrl = "http://localhost:5000";
    private String apiKey;
    private Integer timeout = 30000; // 30 seconds
    private Integer maxRetries = 3;
    private Integer retryDelay = 1000; // 1 second
    private Boolean enabled = true;
    
    @Bean
    public RestTemplate mlRestTemplate() {
        return new RestTemplate();
    }
}
