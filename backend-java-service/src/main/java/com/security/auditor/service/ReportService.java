package com.security.auditor.service;

import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.*;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import com.security.auditor.model.entity.RiskLevel;
import com.security.auditor.model.entity.ScanResult;
import com.security.auditor.model.entity.Vulnerability;
import com.security.auditor.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReportService {
    
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FileStorageService fileStorageService;
    
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    /**
     * Generate PDF report for scan results
     */
    public byte[] generatePdfReport(ScanResult scanResult) throws Exception {
        log.info("Generating PDF report for scan: {}", scanResult.getScanId());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter writer = new PdfWriter(baos);
        PdfDocument pdf = new PdfDocument(writer);
        Document document = new Document(pdf);
        
        try {
            // Title
            addTitle(document, "Smart Contract Security Audit Report");
            
            // Executive Summary
            addExecutiveSummary(document, scanResult);
            
            // Scan Details
            addScanDetails(document, scanResult);
            
            // Risk Assessment
            addRiskAssessment(document, scanResult);
            
            // Vulnerabilities
            List<Vulnerability> vulnerabilities = vulnerabilityRepository.findByScanResult(scanResult);
            addVulnerabilitiesSection(document, vulnerabilities);
            
            // Recommendations
            addRecommendations(document, scanResult, vulnerabilities);
            
            // Footer
            addFooter(document);
            
            document.close();
            
            log.info("PDF report generated successfully");
            return baos.toByteArray();
            
        } catch (Exception e) {
            log.error("Error generating PDF report: {}", e.getMessage(), e);
            throw new Exception("Failed to generate PDF report", e);
        }
    }
    
    /**
     * Generate and upload report to S3
     */
    public String generateAndUploadReport(ScanResult scanResult) throws Exception {
        byte[] pdfBytes = generatePdfReport(scanResult);
        
        String reportFileName = String.format("report_%s_%s.pdf", 
                scanResult.getScanId(), 
                System.currentTimeMillis());
        
        return fileStorageService.uploadReport(pdfBytes, reportFileName, scanResult.getId());
    }
    
    private void addTitle(Document document, String title) {
        Paragraph titleParagraph = new Paragraph(title)
                .setFontSize(24)
                .setBold()
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(20);
        document.add(titleParagraph);
    }
    
    private void addExecutiveSummary(Document document, ScanResult scanResult) {
        document.add(new Paragraph("Executive Summary")
                .setFontSize(18)
                .setBold()
                .setMarginTop(10));
        
        String summary = String.format(
                "This report presents the results of a comprehensive security audit conducted on the smart contract. " +
                "The analysis identified %d vulnerabilities with an overall risk score of %.2f out of 100.",
                scanResult.getTotalVulnerabilities(),
                scanResult.getRiskScore()
        );
        
        document.add(new Paragraph(summary)
                .setMarginBottom(15));
        
        // Risk level indicator
        String riskLevel = getRiskLevelFromScore(scanResult.getRiskScore());
        DeviceRgb riskColor = getRiskColor(riskLevel);
        
        Paragraph riskParagraph = new Paragraph()
                .add(new Text("Overall Risk Level: ").setBold())
                .add(new Text(riskLevel)
                        .setBold()
                        .setFontColor(riskColor));
        document.add(riskParagraph.setMarginBottom(20));
    }
    
    private void addScanDetails(Document document, ScanResult scanResult) {
        document.add(new Paragraph("Scan Details")
                .setFontSize(18)
                .setBold()
                .setMarginTop(10));
        
        Table table = new Table(UnitValue.createPercentArray(new float[]{1, 2}))
                .useAllAvailableWidth();
        
        addTableRow(table, "Scan ID", scanResult.getScanId());
        addTableRow(table, "Contract Name", scanResult.getContract() != null ? 
                scanResult.getContract().getFilename() : "N/A");
        addTableRow(table, "Scan Started", scanResult.getStartedAt().format(DATE_FORMATTER));
        addTableRow(table, "Scan Completed", scanResult.getCompletedAt() != null ? 
                scanResult.getCompletedAt().format(DATE_FORMATTER) : "In Progress");
        addTableRow(table, "Status", scanResult.getStatus().name());
        
        document.add(table.setMarginBottom(20));
    }
    
    private void addRiskAssessment(Document document, ScanResult scanResult) {
        document.add(new Paragraph("Risk Assessment")
                .setFontSize(18)
                .setBold()
                .setMarginTop(10));
        
        Table table = new Table(UnitValue.createPercentArray(new float[]{1, 1}))
                .useAllAvailableWidth();
        
        // Header
        table.addHeaderCell(createHeaderCell("Severity"));
        table.addHeaderCell(createHeaderCell("Count"));
        
        // Rows
        addSeverityRow(table, "Critical", scanResult.getCriticalCount(), new DeviceRgb(220, 53, 69));
        addSeverityRow(table, "High", scanResult.getHighCount(), new DeviceRgb(255, 193, 7));
        addSeverityRow(table, "Medium", scanResult.getMediumCount(), new DeviceRgb(255, 152, 0));
        addSeverityRow(table, "Low", scanResult.getLowCount(), new DeviceRgb(76, 175, 80));
        
        document.add(table.setMarginBottom(20));
        
        // Risk Score
        Paragraph riskScore = new Paragraph()
                .add(new Text("Overall Risk Score: ").setBold())
                .add(new Text(String.format("%.2f / 100", scanResult.getRiskScore()))
                        .setFontColor(getRiskColorFromScore(scanResult.getRiskScore())));
        document.add(riskScore.setMarginBottom(20));
    }
    
    private void addVulnerabilitiesSection(Document document, List<Vulnerability> vulnerabilities) {
        document.add(new Paragraph("Identified Vulnerabilities")
                .setFontSize(18)
                .setBold()
                .setMarginTop(10));
        
        if (vulnerabilities.isEmpty()) {
            document.add(new Paragraph("No vulnerabilities detected.")
                    .setItalic()
                    .setMarginBottom(20));
            return;
        }
        
        // Group by severity
        Map<RiskLevel, List<Vulnerability>> grouped = vulnerabilities.stream()
                .collect(Collectors.groupingBy(Vulnerability::getSeverity));
        
        // Critical vulnerabilities
        addVulnerabilitiesBySeverity(document, grouped.get(RiskLevel.CRITICAL), "Critical", 
                new DeviceRgb(220, 53, 69));
        
        // High vulnerabilities
        addVulnerabilitiesBySeverity(document, grouped.get(RiskLevel.HIGH), "High", 
                new DeviceRgb(255, 193, 7));
        
        // Medium vulnerabilities
        addVulnerabilitiesBySeverity(document, grouped.get(RiskLevel.MEDIUM), "Medium", 
                new DeviceRgb(255, 152, 0));
        
        // Low vulnerabilities
        addVulnerabilitiesBySeverity(document, grouped.get(RiskLevel.LOW), "Low", 
                new DeviceRgb(76, 175, 80));
    }
    
    private void addVulnerabilitiesBySeverity(Document document, List<Vulnerability> vulnerabilities, 
                                               String severity, DeviceRgb color) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return;
        }
        
        document.add(new Paragraph(severity + " Severity Vulnerabilities")
                .setFontSize(14)
                .setBold()
                .setFontColor(color)
                .setMarginTop(10));
        
        int count = 1;
        for (Vulnerability vuln : vulnerabilities) {
            document.add(new Paragraph(String.format("%d. %s", count++, vuln.getTitle()))
                    .setBold()
                    .setMarginTop(5));
            
            document.add(new Paragraph("Type: " + vuln.getVulnerabilityType()));
            
            if (vuln.getDescription() != null) {
                document.add(new Paragraph("Description: " + vuln.getDescription()));
            }
            
            if (vuln.getLineNumber() != null) {
                document.add(new Paragraph("Location: Line " + vuln.getLineNumber()));
            }
            
            if (vuln.getCodeSnippet() != null) {
                document.add(new Paragraph("Code Snippet:")
                        .setBold());
                document.add(new Paragraph(vuln.getCodeSnippet())
                        .setFontSize(9)
                        .setBackgroundColor(new DeviceRgb(245, 245, 245))
                        .setPadding(5));
            }
            
            if (vuln.getRecommendation() != null) {
                document.add(new Paragraph("Recommendation: " + vuln.getRecommendation())
                        .setItalic());
            }
            
            if (vuln.getCweId() != null) {
                document.add(new Paragraph("CWE ID: " + vuln.getCweId())
                        .setFontSize(9));
            }
            
            document.add(new Paragraph().setMarginBottom(10));
        }
    }
    
    private void addRecommendations(Document document, ScanResult scanResult, 
                                     List<Vulnerability> vulnerabilities) {
        document.add(new Paragraph("Security Recommendations")
                .setFontSize(18)
                .setBold()
                .setMarginTop(10));
        
        com.itextpdf.layout.element.List recommendations = new com.itextpdf.layout.element.List()
                .setSymbolIndent(12)
                .setMarginBottom(20);
        
        if (scanResult.getCriticalCount() > 0) {
            recommendations.add("Address all CRITICAL vulnerabilities immediately before deployment.");
        }
        
        if (scanResult.getHighCount() > 0) {
            recommendations.add("Review and fix HIGH severity issues as a priority.");
        }
        
        // Check for specific vulnerability types
        boolean hasReentrancy = vulnerabilities.stream()
                .anyMatch(v -> v.getVulnerabilityType() != null && 
                              v.getVulnerabilityType().toLowerCase().contains("reentrancy"));
        if (hasReentrancy) {
            recommendations.add("Implement the Checks-Effects-Interactions pattern to prevent reentrancy attacks.");
        }
        
        boolean hasAccessControl = vulnerabilities.stream()
                .anyMatch(v -> v.getVulnerabilityType() != null && 
                              v.getVulnerabilityType().toLowerCase().contains("access"));
        if (hasAccessControl) {
            recommendations.add("Implement proper access control mechanisms using modifiers like onlyOwner.");
        }
        
        recommendations.add("Conduct thorough testing including unit tests and integration tests.");
        recommendations.add("Consider a professional security audit before mainnet deployment.");
        recommendations.add("Implement monitoring and alerting for deployed contracts.");
        recommendations.add("Keep dependencies up to date and use well-audited libraries.");
        
        document.add((com.itextpdf.layout.element.IBlockElement) recommendations);
    }
    
    private void addFooter(Document document) {
        document.add(new Paragraph()
                .setMarginTop(30)
                .setTextAlignment(TextAlignment.CENTER)
                .setFontSize(9)
                .add("Generated by Smart Contract Security Auditor\n")
                .add(java.time.LocalDateTime.now().format(DATE_FORMATTER)));
    }
    
    // Helper methods
    
    private void addTableRow(Table table, String key, String value) {
        table.addCell(new Cell().add(new Paragraph(key).setBold()));
        table.addCell(new Cell().add(new Paragraph(value)));
    }
    
    private Cell createHeaderCell(String text) {
        return new Cell()
                .add(new Paragraph(text).setBold())
                .setBackgroundColor(new DeviceRgb(52, 58, 64))
                .setFontColor(ColorConstants.WHITE)
                .setTextAlignment(TextAlignment.CENTER);
    }
    
    private void addSeverityRow(Table table, String severity, Integer count, DeviceRgb color) {
        table.addCell(new Cell()
                .add(new Paragraph(severity)
                        .setBold()
                        .setFontColor(color)));
        table.addCell(new Cell()
                .add(new Paragraph(String.valueOf(count != null ? count : 0))));
    }
    
    private String getRiskLevelFromScore(Double score) {
        if (score == null) return "UNKNOWN";
        if (score >= 70) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 30) return "MEDIUM";
        if (score >= 10) return "LOW";
        return "MINIMAL";
    }
    
    private DeviceRgb getRiskColor(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> new DeviceRgb(220, 53, 69);
            case "HIGH" -> new DeviceRgb(255, 193, 7);
            case "MEDIUM" -> new DeviceRgb(255, 152, 0);
            case "LOW" -> new DeviceRgb(76, 175, 80);
            default -> new DeviceRgb(108, 117, 125);
        };
    }
    
    private DeviceRgb getRiskColorFromScore(Double score) {
        String riskLevel = getRiskLevelFromScore(score);
        return getRiskColor(riskLevel);
    }
}
