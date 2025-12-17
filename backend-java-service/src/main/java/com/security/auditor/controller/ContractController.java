package com.security.auditor.controller;

import com.security.auditor.exception.ResourceNotFoundException;
import com.security.auditor.exception.UnauthorizedException;
import com.security.auditor.exception.ValidationException;
import com.security.auditor.model.dto.*;
import com.security.auditor.model.entity.DetectionSource;
import com.security.auditor.model.entity.ScanResult;
import com.security.auditor.model.entity.ScanStatus;
import com.security.auditor.model.entity.User;
import com.security.auditor.model.entity.Vulnerability;
import com.security.auditor.repository.ScanResultRepository;
import com.security.auditor.repository.UserRepository;
import com.security.auditor.repository.VulnerabilityRepository;
import com.security.auditor.service.ScanOrchestrator;
import com.security.auditor.service.ReportService;
import com.security.auditor.util.FileValidator;
import com.security.auditor.util.InputSanitizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/contracts")
@RequiredArgsConstructor
@Slf4j
public class ContractController {
    
    private final ScanOrchestrator scanOrchestrator;
    private final ScanResultRepository scanResultRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final UserRepository userRepository;
    private final ReportService reportService;
    
    /**
     * Upload contract and initiate scan
     * POST /api/contracts/upload
     */
    @PostMapping("/upload")
    public ResponseEntity<ApiResponse<ScanResponse>> uploadContract(
            @RequestParam("file") MultipartFile file,
            @RequestParam("contractName") String contractName,
            @RequestParam(value = "description", required = false) String description,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Contract upload request received: {}", contractName);
        
        try {
            // Validate file
            if (file.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("File is empty"));
            }
            
            // Validate using FileValidator
            FileValidator.validateFile(
                    file.getOriginalFilename(),
                    file.getContentType(),
                    file.getSize()
            );
            
            // Sanitize contract name
            String sanitizedContractName = InputSanitizer.sanitizeContractName(contractName);
            
            // Sanitize description if provided
            String sanitizedDescription = description != null ? 
                    InputSanitizer.sanitizeText(description) : null;
            
            // Get user from UserDetails (assuming CustomUserDetailsService returns User entity)
            User user = getUserFromDetails(userDetails);
            
            // Initiate async scan
            CompletableFuture<ScanResult> scanFuture = scanOrchestrator.orchestrateScan(
                    file, user, sanitizedContractName, sanitizedDescription);
            
            // Get initial scan result
            ScanResult scanResult = scanFuture.getNow(null);
            
            if (scanResult == null) {
                // If scan hasn't started yet, wait briefly
                scanResult = scanFuture.get();
            }
            
            ScanResponse response = new ScanResponse();
            response.setScanId(scanResult.getScanId());
            response.setStatus(scanResult.getStatus().name());
            
            return ResponseEntity.ok(ApiResponse.success(response));
            
        } catch (Exception e) {
            log.error("Error uploading contract: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to upload contract: " + e.getMessage()));
        }
    }
    
    /**
     * Get scan status
     * GET /api/contracts/scan/{scanId}/status
     */
    @GetMapping("/scan/{scanId}/status")
    public ResponseEntity<ApiResponse<ScanStatusResponse>> getScanStatus(
            @PathVariable String scanId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("Scan status request for: {}", scanId);
        
        try {
            ScanResult scanResult = scanOrchestrator.getScanStatus(scanId);
            
            // Verify user owns this scan
            User user = getUserFromDetails(userDetails);
            if (!scanResult.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Access denied"));
            }
            
            ScanStatusResponse response = new ScanStatusResponse();
            response.setScanId(scanResult.getScanId());  // Use UUID scanId, not numeric ID
            response.setStatus(scanResult.getStatus().name().toLowerCase());  // Return lowercase for frontend
            response.setProgress(calculateProgress(scanResult));
            response.setEstimatedTimeRemainingMs(estimateTimeRemaining(scanResult).longValue());
            
            if (scanResult.getStatus() == ScanStatus.COMPLETED) {
                response.setMessage("Scan completed successfully");
            } else if (scanResult.getStatus() == ScanStatus.FAILED) {
                response.setMessage("Scan failed");
                response.setErrorMessage(scanResult.getErrorMessage());
            } else {
                response.setMessage("Scan in progress");
            }
            
            return ResponseEntity.ok(ApiResponse.success(response));
            
        } catch (RuntimeException e) {
            log.error("Error getting scan status: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Scan not found: " + scanId));
        }
    }
    
    /**
     * Get scan results with vulnerabilities
     * GET /api/contracts/scan/{scanId}/results
     */
    @GetMapping("/scan/{scanId}/results")
    public ResponseEntity<ApiResponse<ScanResponse>> getScanResults(
            @PathVariable String scanId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("Scan results request for: {}", scanId);
        
        try {
            // Use eager fetching to avoid LazyInitializationException
            ScanResult scanResult = scanOrchestrator.getScanStatusWithDetails(scanId);
            
            // Verify user owns this scan
            User user = getUserFromDetails(userDetails);
            if (!scanResult.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Access denied"));
            }
            
            // Vulnerabilities are already loaded via JOIN FETCH
            List<Vulnerability> vulnerabilities = scanResult.getVulnerabilities() != null 
                    ? scanResult.getVulnerabilities() 
                    : vulnerabilityRepository.findByScanResult(scanResult);
            
            ScanResponse response = buildScanResponse(scanResult, vulnerabilities);
            
            return ResponseEntity.ok(ApiResponse.success(response));
            
        } catch (RuntimeException e) {
            log.error("Error getting scan results: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Scan not found: " + scanId));
        }
    }
    
    /**
     * Get vulnerabilities for a scan
     * GET /api/contracts/scan/{scanId}/vulnerabilities
     */
    @GetMapping("/scan/{scanId}/vulnerabilities")
    public ResponseEntity<ApiResponse<List<VulnerabilityDTO>>> getVulnerabilities(
            @PathVariable String scanId,
            @RequestParam(required = false) String severity,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("Vulnerabilities request for scan: {}", scanId);
        
        try {
            ScanResult scanResult = scanOrchestrator.getScanStatus(scanId);
            
            // Verify user owns this scan
            User user = getUserFromDetails(userDetails);
            if (!scanResult.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Access denied"));
            }
            
            List<Vulnerability> vulnerabilities = vulnerabilityRepository.findByScanResult(scanResult);
            
            if (severity != null) {
                com.security.auditor.model.entity.RiskLevel riskLevel = 
                        com.security.auditor.model.entity.RiskLevel.valueOf(severity.toUpperCase());
                vulnerabilities = vulnerabilities.stream()
                        .filter(v -> v.getSeverity() == riskLevel)
                        .collect(Collectors.toList());
            }
            
            List<VulnerabilityDTO> dtos = vulnerabilities.stream()
                    .map(this::toVulnerabilityDTO)
                    .collect(Collectors.toList());
            
            return ResponseEntity.ok(ApiResponse.success(dtos));
            
        } catch (RuntimeException e) {
            log.error("Error getting vulnerabilities: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Scan not found: " + scanId));
        }
    }
    
    /**
     * Cancel ongoing scan
     * POST /api/contracts/scan/{scanId}/cancel
     */
    @PostMapping("/scan/{scanId}/cancel")
    public ResponseEntity<ApiResponse<String>> cancelScan(
            @PathVariable String scanId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Cancel scan request for: {}", scanId);
        
        try {
            ScanResult scanResult = scanOrchestrator.getScanStatus(scanId);
            
            // Verify user owns this scan
            User user = getUserFromDetails(userDetails);
            if (!scanResult.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Access denied"));
            }
            
            scanOrchestrator.cancelScan(scanId);
            
            return ResponseEntity.ok(ApiResponse.success("Scan cancelled successfully"));
            
        } catch (RuntimeException e) {
            log.error("Error cancelling scan: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        }
    }
    
    /**
     * Retry failed scan
     * POST /api/contracts/scan/{scanId}/retry
     */
    @PostMapping("/scan/{scanId}/retry")
    public ResponseEntity<ApiResponse<ScanResponse>> retryScan(
            @PathVariable String scanId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Retry scan request for: {}", scanId);
        
        try {
            ScanResult oldScan = scanOrchestrator.getScanStatus(scanId);
            
            // Verify user owns this scan
            User user = getUserFromDetails(userDetails);
            if (!oldScan.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Access denied"));
            }
            
            CompletableFuture<ScanResult> scanFuture = scanOrchestrator.retryScan(scanId);
            ScanResult newScan = scanFuture.get();
            
            ScanResponse response = new ScanResponse();
            response.setScanId(newScan.getScanId());
            response.setStatus(newScan.getStatus().name());
            
            return ResponseEntity.ok(ApiResponse.success(response));
            
        } catch (RuntimeException e) {
            log.error("Error retrying scan: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Error retrying scan: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retry scan"));
        }
    }
    
    /**
     * Get user's scan history
     * GET /api/contracts/scans
     */
    @GetMapping("/scans")
    public ResponseEntity<ApiResponse<List<ScanResponse>>> getScanHistory(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.debug("Scan history request");
        
        try {
            User user = getUserFromDetails(userDetails);
            
            // Use the query that eagerly fetches Contract to avoid LazyInitializationException
            List<ScanResult> scans = scanResultRepository.findByUserIdWithContract(user.getId());
            
            List<ScanResponse> responses = scans.stream()
                    .map(scan -> {
                        List<Vulnerability> vulnerabilities = vulnerabilityRepository.findByScanResult(scan);
                        return buildScanResponse(scan, vulnerabilities);
                    })
                    .collect(Collectors.toList());
            
            return ResponseEntity.ok(ApiResponse.success(responses));
            
        } catch (Exception e) {
            log.error("Error getting scan history: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve scan history"));
        }
    }
    
    // Helper methods
    
    private boolean isValidSolidityFile(MultipartFile file) {
        String filename = file.getOriginalFilename();
        return filename != null && filename.toLowerCase().endsWith(".sol");
    }
    
    private User getUserFromDetails(UserDetails userDetails) {
        // Query the repository to get the User entity by username
        return userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new UnauthorizedException("User not found: " + userDetails.getUsername()));
    }
    
    private int calculateProgress(ScanResult scanResult) {
        switch (scanResult.getStatus()) {
            case PENDING:
                return 10;
            case IN_PROGRESS:
                return 50;
            case COMPLETED:
                return 100;
            case FAILED:
            case CANCELLED:
                return 0;
            default:
                return 0;
        }
    }
    
    private Integer estimateTimeRemaining(ScanResult scanResult) {
        if (scanResult.getStatus().name().equals("COMPLETED") || 
            scanResult.getStatus().name().equals("FAILED") ||
            scanResult.getStatus().name().equals("CANCELLED")) {
            return 0;
        }
        
        // Simple estimation: average scan takes 30 seconds
        return 30;
    }
    
    private ScanResponse buildScanResponse(ScanResult scanResult, List<Vulnerability> vulnerabilities) {
        ScanResponse response = new ScanResponse();
        response.setScanId(scanResult.getScanId());
        response.setStatus(scanResult.getStatus().name());
        response.setContractName(scanResult.getContract() != null ? 
                scanResult.getContract().getFilename() : "Unknown");
        response.setStartedAt(scanResult.getStartedAt());
        response.setCompletedAt(scanResult.getCompletedAt());
        response.setRiskScore(scanResult.getRiskScore());
        response.setTotalVulnerabilities(scanResult.getTotalVulnerabilities());
        response.setCriticalCount(scanResult.getCriticalCount());
        response.setHighCount(scanResult.getHighCount());
        response.setMediumCount(scanResult.getMediumCount());
        response.setLowCount(scanResult.getLowCount());
        response.setErrorMessage(scanResult.getErrorMessage());
        
        // Get source code from contract
        if (scanResult.getContract() != null && scanResult.getContract().getSourceCode() != null) {
            response.setSourceCode(scanResult.getContract().getSourceCode());
        }
        
        // Separate vulnerabilities by detection source
        List<VulnerabilityDTO> allVulns = new ArrayList<>();
        List<VulnerabilityDTO> staticVulns = new ArrayList<>();
        List<VulnerabilityDTO> mlVulns = new ArrayList<>();
        
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            for (Vulnerability vuln : vulnerabilities) {
                VulnerabilityDTO dto = toVulnerabilityDTO(vuln);
                allVulns.add(dto);
                
                if (vuln.getDetectionSource() == DetectionSource.STATIC) {
                    staticVulns.add(dto);
                } else if (vuln.getDetectionSource() == DetectionSource.ML) {
                    mlVulns.add(dto);
                }
            }
        }
        
        response.setVulnerabilities(allVulns);
        response.setAllVulnerabilities(allVulns);
        response.setStaticFindings(staticVulns);
        response.setMlFindings(mlVulns);
        
        return response;
    }
    
    private VulnerabilityDTO toVulnerabilityDTO(Vulnerability vulnerability) {
        VulnerabilityDTO dto = new VulnerabilityDTO();
        dto.setId(vulnerability.getId());
        dto.setType(vulnerability.getVulnerabilityType());
        dto.setTitle(vulnerability.getTitle());
        dto.setDescription(vulnerability.getDescription());
        dto.setSeverity(vulnerability.getSeverity().name());
        dto.setLineNumber(vulnerability.getLineNumber());
        dto.setCodeSnippet(vulnerability.getCodeSnippet());
        dto.setRecommendation(vulnerability.getRecommendation());
        dto.setCweId(vulnerability.getCweId());
        dto.setConfidenceScore(vulnerability.getConfidenceScore());
        dto.setDetectionMethod(vulnerability.getDetectionSource().name());
        dto.setFalsePositive(vulnerability.getFalsePositive());
        
        return dto;
    }
    
    /**
     * Generate and download PDF report for scan
     * GET /api/contracts/scan/{scanId}/report
     */
    @GetMapping("/scan/{scanId}/report")
    public ResponseEntity<?> downloadReport(
            @PathVariable String scanId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Report download request for scan: {}", scanId);
        
        try {
            User user = getUserFromDetails(userDetails);
            ScanResult scan = scanResultRepository.findByScanIdWithContractAndVulnerabilities(scanId)
                    .orElseThrow(() -> new ResourceNotFoundException("Scan", "scanId", scanId));
            
            // Verify ownership
            if (!user.getId().equals(scan.getUser().getId())) {
                throw new UnauthorizedException("Unauthorized access to scan", 
                        user.getId().toString(), "Scan:" + scanId);
            }
            
            // Generate PDF report
            byte[] pdfBytes = reportService.generatePdfReport(scan);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", 
                    String.format("scan_report_%s.pdf", scanId));
            
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(pdfBytes);
            
        } catch (Exception e) {
            log.error("Error generating report: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to generate report: " + e.getMessage()));
        }
    }
    
    /**
     * Generate report and upload to S3, return URL
     * POST /api/contracts/scan/{scanId}/report/generate
     */
    @PostMapping("/scan/{scanId}/report/generate")
    public ResponseEntity<ApiResponse<String>> generateReport(
            @PathVariable String scanId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        log.info("Report generation request for scan: {}", scanId);
        
        try {
            User user = getUserFromDetails(userDetails);
            ScanResult scan = scanResultRepository.findByScanIdWithContractAndVulnerabilities(scanId)
                    .orElseThrow(() -> new ResourceNotFoundException("Scan", "scanId", scanId));
            
            // Verify ownership
            if (!user.getId().equals(scan.getUser().getId())) {
                throw new UnauthorizedException("Unauthorized access to scan", 
                        user.getId().toString(), "Scan:" + scanId);
            }
            
            // Generate and upload report
            String reportUrl = reportService.generateAndUploadReport(scan);
            
            return ResponseEntity.ok(ApiResponse.success(reportUrl, "Report generated successfully"));
            
        } catch (Exception e) {
            log.error("Error generating and uploading report: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to generate report: " + e.getMessage()));
        }
    }
}
