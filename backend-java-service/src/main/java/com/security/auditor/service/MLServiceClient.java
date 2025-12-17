package com.security.auditor.service;

import com.security.auditor.config.MLServiceConfig;
import com.security.auditor.model.dto.MLAnalysisRequest;
import com.security.auditor.model.dto.MLAnalysisResponse;
import com.security.auditor.model.dto.ParsedContract;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class MLServiceClient {
    
    private final RestTemplate mlRestTemplate;
    private final MLServiceConfig mlServiceConfig;
    
    /**
     * Analyze contract using ML service
     */
    public MLAnalysisResponse analyzeContract(String contractCode, String contractName, 
                                              String solcVersion, ParsedContract parsedContract) {
        if (!mlServiceConfig.getEnabled()) {
            log.info("ML service is disabled, returning empty response");
            return createEmptyResponse("ML service is disabled");
        }
        
        log.info("Sending contract to ML service for analysis: {}", contractName);
        
        try {
            MLAnalysisRequest request = new MLAnalysisRequest(
                    contractCode, 
                    contractName, 
                    solcVersion, 
                    parsedContract
            );
            
            String url = mlServiceConfig.getBaseUrl() + "/api/ml/analyze";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            if (mlServiceConfig.getApiKey() != null && !mlServiceConfig.getApiKey().isEmpty()) {
                headers.set("X-API-Key", mlServiceConfig.getApiKey());
            }
            
            HttpEntity<MLAnalysisRequest> entity = new HttpEntity<>(request, headers);
            
            // Attempt with retries
            MLAnalysisResponse response = executeWithRetry(url, entity);
            
            log.info("ML analysis completed. Found {} vulnerabilities", 
                    response.getVulnerabilities() != null ? response.getVulnerabilities().size() : 0);
            
            return response;
            
        } catch (Exception e) {
            log.error("Error communicating with ML service: {}", e.getMessage(), e);
            return createErrorResponse("ML service unavailable: " + e.getMessage());
        }
    }
    
    /**
     * Execute REST call with retry logic
     */
    private MLAnalysisResponse executeWithRetry(String url, HttpEntity<MLAnalysisRequest> entity) {
        int attempts = 0;
        Exception lastException = null;
        
        while (attempts < mlServiceConfig.getMaxRetries()) {
            try {
                ResponseEntity<MLAnalysisResponse> response = mlRestTemplate.exchange(
                        url,
                        HttpMethod.POST,
                        entity,
                        MLAnalysisResponse.class
                );
                
                if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                    return response.getBody();
                }
                
                log.warn("ML service returned non-success status: {}", response.getStatusCode());
                
            } catch (RestClientException e) {
                lastException = e;
                attempts++;
                
                if (attempts < mlServiceConfig.getMaxRetries()) {
                    log.warn("ML service call failed (attempt {}/{}), retrying in {}ms: {}", 
                            attempts, mlServiceConfig.getMaxRetries(), 
                            mlServiceConfig.getRetryDelay(), e.getMessage());
                    
                    try {
                        Thread.sleep(mlServiceConfig.getRetryDelay());
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Interrupted while retrying ML service call", ie);
                    }
                } else {
                    log.error("ML service call failed after {} attempts", attempts);
                }
            }
        }
        
        throw new RuntimeException("Failed to communicate with ML service after " + 
                                  mlServiceConfig.getMaxRetries() + " attempts", lastException);
    }
    
    /**
     * Check ML service health
     */
    public boolean isServiceHealthy() {
        if (!mlServiceConfig.getEnabled()) {
            return false;
        }
        
        try {
            String url = mlServiceConfig.getBaseUrl() + "/health";
            
            ResponseEntity<Map> response = mlRestTemplate.getForEntity(url, Map.class);
            
            return response.getStatusCode().is2xxSuccessful();
            
        } catch (Exception e) {
            log.debug("ML service health check failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Get ML service info
     */
    public Map<String, Object> getServiceInfo() {
        if (!mlServiceConfig.getEnabled()) {
            return Map.of("status", "disabled");
        }
        
        try {
            String url = mlServiceConfig.getBaseUrl() + "/api/ml/info";
            
            ResponseEntity<Map> response = mlRestTemplate.getForEntity(url, Map.class);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            }
            
        } catch (Exception e) {
            log.debug("Failed to get ML service info: {}", e.getMessage());
        }
        
        return Map.of("status", "unavailable");
    }
    
    /**
     * Batch analyze multiple contracts
     */
    public Map<String, MLAnalysisResponse> batchAnalyze(Map<String, MLAnalysisRequest> requests) {
        Map<String, MLAnalysisResponse> results = new HashMap<>();
        
        if (!mlServiceConfig.getEnabled()) {
            log.info("ML service is disabled, returning empty results");
            requests.keySet().forEach(key -> 
                    results.put(key, createEmptyResponse("ML service is disabled")));
            return results;
        }
        
        try {
            String url = mlServiceConfig.getBaseUrl() + "/api/ml/batch-analyze";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            if (mlServiceConfig.getApiKey() != null && !mlServiceConfig.getApiKey().isEmpty()) {
                headers.set("X-API-Key", mlServiceConfig.getApiKey());
            }
            
            HttpEntity<Map<String, MLAnalysisRequest>> entity = new HttpEntity<>(requests, headers);
            
            ResponseEntity<Map> response = mlRestTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    entity,
                    Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                // Process response - would need proper deserialization in production
                log.info("Batch analysis completed for {} contracts", requests.size());
            }
            
        } catch (Exception e) {
            log.error("Error in batch analysis: {}", e.getMessage(), e);
            requests.keySet().forEach(key -> 
                    results.put(key, createErrorResponse("Batch analysis failed: " + e.getMessage())));
        }
        
        return results;
    }
    
    /**
     * Create empty response when ML service is disabled
     */
    private MLAnalysisResponse createEmptyResponse(String message) {
        MLAnalysisResponse response = new MLAnalysisResponse();
        response.setSuccess(true);
        response.setMessage(message);
        response.setVulnerabilities(Collections.emptyList());
        response.setProcessingTimeMs(0L);
        
        MLAnalysisResponse.MLMetrics metrics = new MLAnalysisResponse.MLMetrics();
        metrics.setOverallRiskScore(0.0);
        metrics.setTotalVulnerabilities(0);
        metrics.setSeverityCount(Collections.emptyMap());
        metrics.setCategoryCount(Collections.emptyMap());
        metrics.setModelConfidence(0.0);
        
        response.setMetrics(metrics);
        
        return response;
    }
    
    /**
     * Create error response
     */
    private MLAnalysisResponse createErrorResponse(String message) {
        MLAnalysisResponse response = new MLAnalysisResponse();
        response.setSuccess(false);
        response.setMessage(message);
        response.setVulnerabilities(Collections.emptyList());
        response.setProcessingTimeMs(0L);
        
        MLAnalysisResponse.MLMetrics metrics = new MLAnalysisResponse.MLMetrics();
        metrics.setOverallRiskScore(0.0);
        metrics.setTotalVulnerabilities(0);
        metrics.setSeverityCount(Collections.emptyMap());
        metrics.setCategoryCount(Collections.emptyMap());
        metrics.setModelConfidence(0.0);
        
        response.setMetrics(metrics);
        
        return response;
    }
}
