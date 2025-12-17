package com.security.auditor.service.analysis.rules;

import com.security.auditor.model.dto.ParsedContract;
import com.security.auditor.service.analysis.AnalysisRule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Component
@Slf4j
public class IntegerOverflowRule extends AnalysisRule {
    
    private static final Pattern ARITHMETIC_PATTERN = Pattern.compile(
            "[\\w\\[\\]]+\\s*[+\\-*\\/]\\s*[\\w\\[\\]]+");
    
    private static final Pattern UNCHECKED_PATTERN = Pattern.compile("unchecked\\s*\\{");
    
    private static final Pattern SAFE_MATH_PATTERN = Pattern.compile(
            "using\\s+SafeMath\\s+for\\s+uint|SafeMath\\.");
    
    public IntegerOverflowRule() {
        super("IO001", "Integer Overflow/Underflow", "HIGH", "Arithmetic");
    }
    
    @Override
    public List<Finding> analyze(ParsedContract contract) {
        List<Finding> findings = new ArrayList<>();
        
        // Check Solidity version
        String solcVersion = contract.getSolcVersion();
        boolean isOldVersion = isOldSolidityVersion(solcVersion);
        
        // Check for SafeMath usage
        boolean usesSafeMath = contract.getSourceCode() != null && 
                                containsPattern(contract.getSourceCode(), SAFE_MATH_PATTERN);
        
        if (contract.getFunctions() == null) {
            return findings;
        }
        
        for (ParsedContract.FunctionInfo function : contract.getFunctions()) {
            if (function.getBody() == null) continue;
            
            String body = function.getBody();
            
            // Check for arithmetic operations
            if (containsPattern(body, ARITHMETIC_PATTERN)) {
                // For Solidity < 0.8.0, check if SafeMath is used
                if (isOldVersion && !usesSafeMath && !containsPattern(body, SAFE_MATH_PATTERN)) {
                    String[] lines = body.split("\n");
                    for (int i = 0; i < lines.length; i++) {
                        if (containsPattern(lines[i], ARITHMETIC_PATTERN) && 
                            !containsPattern(lines[i], UNCHECKED_PATTERN)) {
                            
                            findings.add(createFinding(
                                    contract,
                                    function,
                                    function.getStartLine() + i,
                                    "Potential integer overflow/underflow in function: " + function.getName(),
                                    isOldVersion
                            ));
                        }
                    }
                }
                
                // For Solidity >= 0.8.0, check for unchecked blocks
                if (!isOldVersion && containsPattern(body, UNCHECKED_PATTERN)) {
                    findings.add(createUncheckedBlockFinding(contract, function));
                }
            }
        }
        
        return findings;
    }
    
    private boolean isOldSolidityVersion(String version) {
        if (version == null) return true;
        
        // Extract major.minor version
        String versionNumber = version.replaceAll("[^0-9.]", "");
        String[] parts = versionNumber.split("\\.");
        
        if (parts.length >= 2) {
            try {
                int major = Integer.parseInt(parts[0]);
                int minor = Integer.parseInt(parts[1]);
                return major == 0 && minor < 8;
            } catch (NumberFormatException e) {
                return true;
            }
        }
        
        return true;
    }
    
    private Finding createFinding(ParsedContract contract, ParsedContract.FunctionInfo function,
                                   int lineNumber, String title, boolean isOldVersion) {
        String description = isOldVersion ?
                "The function '" + function.getName() + "' performs arithmetic operations without SafeMath. " +
                "In Solidity versions prior to 0.8.0, arithmetic operations can overflow or underflow silently." :
                "The function '" + function.getName() + "' uses unchecked arithmetic operations. " +
                "Ensure overflow/underflow is intended behavior.";
        
        String recommendation = isOldVersion ?
                "Use SafeMath library for all arithmetic operations or upgrade to Solidity 0.8.0+." :
                "Review unchecked blocks carefully. Only use unchecked arithmetic when overflow/underflow is intentional.";
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity(severity)
                .category(category)
                .title(title)
                .description(description)
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation(recommendation)
                .confidenceScore(0.8)
                .cweId("CWE-190")
                .owaspCategory("A4:2021 - Insecure Design")
                .build();
    }
    
    private Finding createUncheckedBlockFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity("MEDIUM")
                .category(category)
                .title("Unchecked arithmetic block in function: " + function.getName())
                .description("The function uses unchecked blocks which disable overflow/underflow checks.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(function.getStartLine())
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), function.getStartLine(), 5))
                .recommendation("Review unchecked blocks carefully to ensure overflow/underflow cannot occur.")
                .confidenceScore(0.7)
                .cweId("CWE-190")
                .owaspCategory("A4:2021 - Insecure Design")
                .build();
    }
}
