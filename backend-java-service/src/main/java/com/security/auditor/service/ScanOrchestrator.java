package com.security.auditor.service;

import com.security.auditor.model.dto.MLAnalysisResponse;
import com.security.auditor.model.dto.ParsedContract;
import com.security.auditor.model.entity.*;
import com.security.auditor.repository.ContractRepository;
import com.security.auditor.repository.ScanResultRepository;
import com.security.auditor.repository.VulnerabilityRepository;
import com.security.auditor.service.analysis.AnalysisRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanOrchestrator {
    
    private final LocalFileStorageService localFileStorageService;
    private final SolidityParserService solidityParserService;
    private final StaticAnalysisService staticAnalysisService;
    private final MLServiceClient mlServiceClient;
    private final ContractRepository contractRepository;
    private final ScanResultRepository scanResultRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    
    /**
     * Orchestrate complete scan process
     */
    @Async
    @Transactional
    public CompletableFuture<ScanResult> orchestrateScan(MultipartFile file, User user, 
                                                          String contractName, String description) {
        log.info("Starting scan orchestration for contract: {}", contractName);
        
        ScanResult scanResult = null;
        
        try {
            // Step 1: Save file locally (instead of S3)
            log.debug("Step 1: Saving contract locally");
            String filePath = localFileStorageService.saveContractLocally(file, user.getId());
            
            // Step 2: Create and save contract entity FIRST
            log.debug("Step 2: Creating contract entity");
            Contract contract = createContract(user, contractName, description, filePath, file);
            String sourceCode = new String(file.getBytes());
            contract.setSourceCode(sourceCode);
            contract = contractRepository.save(contract);
            
            // Step 3: Initialize scan result WITH contract
            log.debug("Step 3: Initializing scan result");
            scanResult = initializeScanResult(user, contractName, contract);
            
            // Step 4: Parse Solidity code
            log.debug("Step 4: Parsing Solidity code");
            ParsedContract parsedContract = solidityParserService.parseContract(sourceCode);
            
            // Step 5: Run static analysis
            log.debug("Step 5: Running static analysis");
            List<AnalysisRule.Finding> staticFindings = staticAnalysisService.analyzeContract(parsedContract);
            log.info("Static analysis found {} issues", staticFindings.size());
            
            // Step 6: Run ML analysis
            log.debug("Step 6: Running ML analysis");
            MLAnalysisResponse mlResponse = mlServiceClient.analyzeContract(
                    sourceCode, 
                    contractName, 
                    parsedContract.getSolcVersion(), 
                    parsedContract
            );
            log.info("ML analysis found {} issues", 
                    mlResponse.getVulnerabilities() != null ? mlResponse.getVulnerabilities().size() : 0);
            
            // Step 7: Aggregate results
            log.debug("Step 7: Aggregating results");
            List<Vulnerability> vulnerabilities = aggregateFindings(
                    scanResult, 
                    staticFindings, 
                    mlResponse
            );
            
            // Step 8: Calculate risk score
            log.debug("Step 8: Calculating risk score");
            double riskScore = calculateRiskScore(vulnerabilities);
            
            // Step 9: Update scan result
            scanResult.setStatus(ScanStatus.COMPLETED);
            scanResult.setCompletedAt(LocalDateTime.now());
            scanResult.setRiskScore(riskScore);
            scanResult.setTotalVulnerabilities(vulnerabilities.size());
            
            // Count by severity
            Map<String, Long> severityCounts = vulnerabilities.stream()
                    .collect(java.util.stream.Collectors.groupingBy(
                            v -> v.getSeverity().name(),
                            java.util.stream.Collectors.counting()
                    ));
            
            scanResult.setCriticalCount(severityCounts.getOrDefault("CRITICAL", 0L).intValue());
            scanResult.setHighCount(severityCounts.getOrDefault("HIGH", 0L).intValue());
            scanResult.setMediumCount(severityCounts.getOrDefault("MEDIUM", 0L).intValue());
            scanResult.setLowCount(severityCounts.getOrDefault("LOW", 0L).intValue());
            
            // Save vulnerabilities
            vulnerabilityRepository.saveAll(vulnerabilities);
            
            // Save final result
            scanResult = scanResultRepository.save(scanResult);
            
            log.info("Scan orchestration completed successfully for contract: {}", contractName);
            return CompletableFuture.completedFuture(scanResult);
            
        } catch (Exception e) {
            log.error("Error during scan orchestration: {}", e.getMessage(), e);
            
            // Update scan status to FAILED if we have a scan result
            if (scanResult != null && scanResult.getId() != null) {
                try {
                    scanResult.setStatus(ScanStatus.FAILED);
                    scanResult.setCompletedAt(LocalDateTime.now());
                    scanResult.setErrorMessage(e.getMessage());
                    scanResultRepository.save(scanResult);
                    log.info("Scan status updated to FAILED for scanId: {}", scanResult.getScanId());
                    return CompletableFuture.completedFuture(scanResult);
                } catch (Exception saveEx) {
                    log.error("Failed to update scan status to FAILED: {}", saveEx.getMessage());
                }
            }
            
            throw new RuntimeException("Scan orchestration failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Initialize scan result entity with contract
     */
    private ScanResult initializeScanResult(User user, String contractName, Contract contract) {
        ScanResult scanResult = new ScanResult();
        scanResult.setUser(user);
        scanResult.setContract(contract);
        scanResult.setScanId(UUID.randomUUID().toString());
        scanResult.setStatus(ScanStatus.PENDING);
        scanResult.setStartedAt(LocalDateTime.now());
        scanResult.setTotalVulnerabilities(0);
        scanResult.setCriticalCount(0);
        scanResult.setHighCount(0);
        scanResult.setMediumCount(0);
        scanResult.setLowCount(0);
        scanResult.setRiskScore(0.0);
        
        return scanResultRepository.save(scanResult);
    }
    
    /**
     * Create contract entity
     */
    private Contract createContract(User user, String contractName, String description, 
                                     String s3Key, MultipartFile file) throws IOException {
        Contract contract = new Contract();
        contract.setUser(user);
        contract.setFilename(contractName);
        contract.setFilePath(s3Key);
        contract.setFileSize(file.getSize());
        
        return contractRepository.save(contract);
    }
    
    /**
     * Aggregate findings from static analysis and ML
     */
    private List<Vulnerability> aggregateFindings(ScanResult scanResult,
                                                   List<AnalysisRule.Finding> staticFindings,
                                                   MLAnalysisResponse mlResponse) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Add static analysis findings
        for (AnalysisRule.Finding finding : staticFindings) {
            Vulnerability vulnerability = new Vulnerability();
            vulnerability.setScanResult(scanResult);
            vulnerability.setVulnerabilityType(finding.getCategory());
            vulnerability.setSeverity(mapSeverity(finding.getSeverity()));
            vulnerability.setTitle(finding.getTitle());
            vulnerability.setDescription(finding.getDescription());
            vulnerability.setLineNumber(finding.getLineNumber());
            vulnerability.setCodeSnippet(finding.getCodeSnippet());
            vulnerability.setRecommendation(finding.getRecommendation());
            vulnerability.setConfidenceScore(finding.getConfidenceScore());
            vulnerability.setCweId(finding.getCweId());
            vulnerability.setDetectionSource(DetectionSource.STATIC);
            
            vulnerabilities.add(vulnerability);
        }
        
        // Add ML findings
        if (mlResponse.getVulnerabilities() != null) {
            for (MLAnalysisResponse.MLVulnerability mlVuln : mlResponse.getVulnerabilities()) {
                Vulnerability vulnerability = new Vulnerability();
                vulnerability.setScanResult(scanResult);
                
                // Use name or category for vulnerability type, ensuring it's not null
                String vulnType = mlVuln.getName() != null ? mlVuln.getName() : 
                                  (mlVuln.getCategory() != null ? mlVuln.getCategory() : "Unknown");
                vulnerability.setVulnerabilityType(vulnType);
                vulnerability.setSeverity(mapSeverity(mlVuln.getSeverity()));
                vulnerability.setTitle(mlVuln.getName() != null ? mlVuln.getName() : vulnType + " detected by ML");
                vulnerability.setDescription(mlVuln.getDescription());
                vulnerability.setLineNumber(mlVuln.getLineNumber());
                vulnerability.setCodeSnippet(mlVuln.getCodeSnippet());
                vulnerability.setRecommendation(mlVuln.getRecommendation());
                vulnerability.setConfidenceScore(mlVuln.getConfidence());
                vulnerability.setCweId(mlVuln.getCweId());
                vulnerability.setSwcId(mlVuln.getSwcId());
                vulnerability.setDetectionSource(DetectionSource.ML);
                
                vulnerabilities.add(vulnerability);
            }
        }
        
        // Deduplicate similar vulnerabilities
        vulnerabilities = deduplicateVulnerabilities(vulnerabilities);
        
        return vulnerabilities;
    }
    
    /**
     * Map string severity to enum
     */
    private RiskLevel mapSeverity(String severity) {
        if (severity == null) return RiskLevel.MEDIUM;
        
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> RiskLevel.CRITICAL;
            case "HIGH" -> RiskLevel.HIGH;
            case "MEDIUM" -> RiskLevel.MEDIUM;
            case "LOW" -> RiskLevel.LOW;
            case "INFO" -> RiskLevel.LOW;
            default -> RiskLevel.MEDIUM;
        };
    }
    
    /**
     * Deduplicate vulnerabilities based on type, line number, and similarity
     */
    private List<Vulnerability> deduplicateVulnerabilities(List<Vulnerability> vulnerabilities) {
        Map<String, Vulnerability> uniqueVulns = new LinkedHashMap<>();
        
        for (Vulnerability vuln : vulnerabilities) {
            String key = vuln.getVulnerabilityType() + ":" + vuln.getLineNumber();
            
            if (!uniqueVulns.containsKey(key)) {
                uniqueVulns.put(key, vuln);
            } else {
                // Keep the one with higher confidence
                Vulnerability existing = uniqueVulns.get(key);
                if (vuln.getConfidenceScore() != null && existing.getConfidenceScore() != null &&
                    vuln.getConfidenceScore() > existing.getConfidenceScore()) {
                    uniqueVulns.put(key, vuln);
                }
            }
        }
        
        return new ArrayList<>(uniqueVulns.values());
    }
    
    /**
     * Calculate overall risk score
     */
    private double calculateRiskScore(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities.isEmpty()) {
            return 0.0;
        }
        
        double score = 0.0;
        Map<RiskLevel, Double> weights = Map.of(
                RiskLevel.CRITICAL, 10.0,
                RiskLevel.HIGH, 7.0,
                RiskLevel.MEDIUM, 4.0,
                RiskLevel.LOW, 2.0
        );
        
        for (Vulnerability vuln : vulnerabilities) {
            double weight = weights.getOrDefault(vuln.getSeverity(), 1.0);
            double confidence = vuln.getConfidenceScore() != null ? vuln.getConfidenceScore() : 0.5;
            score += weight * confidence;
        }
        
        // Normalize to 0-100 scale (cap at 100)
        return Math.min(100.0, score);
    }
    
    /**
     * Get scan status
     */
    public ScanResult getScanStatus(String scanId) {
        return scanResultRepository.findByScanId(scanId)
                .orElseThrow(() -> new RuntimeException("Scan not found: " + scanId));
    }
    
    /**
     * Get scan status with contract and vulnerabilities eagerly loaded
     */
    public ScanResult getScanStatusWithDetails(String scanId) {
        return scanResultRepository.findByScanIdWithContractAndVulnerabilities(scanId)
                .orElseThrow(() -> new RuntimeException("Scan not found: " + scanId));
    }
    
    /**
     * Cancel ongoing scan
     */
    @Transactional
    public void cancelScan(String scanId) {
        ScanResult scanResult = getScanStatus(scanId);
        
        if (scanResult.getStatus() == ScanStatus.COMPLETED || 
            scanResult.getStatus() == ScanStatus.FAILED) {
            throw new RuntimeException("Cannot cancel completed or failed scan");
        }
        
        scanResult.setStatus(ScanStatus.FAILED);
        scanResult.setCompletedAt(LocalDateTime.now());
        scanResult.setErrorMessage("Scan cancelled by user");
        
        scanResultRepository.save(scanResult);
        log.info("Scan cancelled: {}", scanId);
    }
    
    /**
     * Retry failed scan
     */
    @Async
    @Transactional
    public CompletableFuture<ScanResult> retryScan(String scanId) {
        ScanResult oldScan = getScanStatus(scanId);
        
        if (oldScan.getStatus() != ScanStatus.FAILED) {
            throw new RuntimeException("Can only retry failed scans");
        }
        
        if (oldScan.getContract() == null) {
            throw new RuntimeException("Contract information not found for scan");
        }
        
        log.info("Retrying scan: {}", scanId);
        
        // Create new scan result with existing contract
        ScanResult newScan = initializeScanResult(oldScan.getUser(), 
                oldScan.getContract().getFilename(), oldScan.getContract());
        
        try {
            // Download contract from local storage
            byte[] contractBytes = localFileStorageService.readContract(oldScan.getContract().getFilePath());
            String sourceCode = new String(contractBytes);
            
            // Parse contract
            ParsedContract parsedContract = solidityParserService.parseContract(sourceCode);
            
            // Run analyses
            List<AnalysisRule.Finding> staticFindings = staticAnalysisService.analyzeContract(parsedContract);
            MLAnalysisResponse mlResponse = mlServiceClient.analyzeContract(
                    sourceCode,
                    oldScan.getContract().getFilename(),
                    parsedContract.getSolcVersion(),
                    parsedContract
            );
            
            // Aggregate and save
            List<Vulnerability> vulnerabilities = aggregateFindings(newScan, staticFindings, mlResponse);
            double riskScore = calculateRiskScore(vulnerabilities);
            
            newScan.setStatus(ScanStatus.COMPLETED);
            newScan.setCompletedAt(LocalDateTime.now());
            newScan.setRiskScore(riskScore);
            newScan.setTotalVulnerabilities(vulnerabilities.size());
            
            vulnerabilityRepository.saveAll(vulnerabilities);
            newScan = scanResultRepository.save(newScan);
            
            log.info("Scan retry completed successfully: {}", scanId);
            return CompletableFuture.completedFuture(newScan);
            
        } catch (Exception e) {
            log.error("Error during scan retry: {}", e.getMessage(), e);
            newScan.setStatus(ScanStatus.FAILED);
            newScan.setCompletedAt(LocalDateTime.now());
            newScan.setErrorMessage(e.getMessage());
            scanResultRepository.save(newScan);
            throw new RuntimeException("Scan retry failed: " + e.getMessage(), e);
        }
    }
}
