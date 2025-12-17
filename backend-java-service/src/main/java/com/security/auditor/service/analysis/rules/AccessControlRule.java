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
public class AccessControlRule extends AnalysisRule {
    
    private static final Pattern ONLY_OWNER_PATTERN = Pattern.compile("onlyOwner");
    private static final Pattern TX_ORIGIN_PATTERN = Pattern.compile("tx\\.origin");
    private static final Pattern SELFDESTRUCT_PATTERN = Pattern.compile("selfdestruct\\s*\\(");
    private static final Pattern DELEGATECALL_PATTERN = Pattern.compile("\\.delegatecall\\s*\\(");
    
    public AccessControlRule() {
        super("AC001", "Access Control Issues", "HIGH", "Access Control");
    }
    
    @Override
    public List<Finding> analyze(ParsedContract contract) {
        List<Finding> findings = new ArrayList<>();
        
        if (contract.getFunctions() == null) {
            return findings;
        }
        
        // Check for missing access control on critical functions
        for (ParsedContract.FunctionInfo function : contract.getFunctions()) {
            if (function.getBody() == null) continue;
            
            String body = function.getBody();
            
            // Check for tx.origin usage
            if (containsPattern(body, TX_ORIGIN_PATTERN)) {
                findings.add(createTxOriginFinding(contract, function));
            }
            
            // Check for unprotected selfdestruct
            if (containsPattern(body, SELFDESTRUCT_PATTERN)) {
                if (!hasAccessControl(function)) {
                    findings.add(createUnprotectedSelfdestructFinding(contract, function));
                }
            }
            
            // Check for unprotected delegatecall
            if (containsPattern(body, DELEGATECALL_PATTERN)) {
                if (!hasAccessControl(function)) {
                    findings.add(createUnprotectedDelegatecallFinding(contract, function));
                }
            }
            
            // Check for missing access control on state-changing public/external functions
            if (isStateChangingFunction(function) && 
                (function.getVisibility().equals("public") || function.getVisibility().equals("external")) &&
                !hasAccessControl(function) &&
                !Boolean.TRUE.equals(function.getIsConstructor())) {
                
                findings.add(createMissingAccessControlFinding(contract, function));
            }
        }
        
        return findings;
    }
    
    private boolean hasAccessControl(ParsedContract.FunctionInfo function) {
        if (function.getModifiers() != null && !function.getModifiers().isEmpty()) {
            return true;
        }
        
        if (function.getBody() != null) {
            String body = function.getBody();
            return containsPattern(body, Pattern.compile("require\\s*\\(.*msg\\.sender")) ||
                   containsPattern(body, Pattern.compile("require\\s*\\(.*owner")) ||
                   containsPattern(body, ONLY_OWNER_PATTERN);
        }
        
        return false;
    }
    
    private boolean isStateChangingFunction(ParsedContract.FunctionInfo function) {
        String mutability = function.getStateMutability();
        return mutability == null || 
               (!mutability.equals("pure") && !mutability.equals("view"));
    }
    
    private Finding createTxOriginFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        int lineNumber = getLineNumber(contract.getSourceCode(), "tx.origin");
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity("HIGH")
                .category(category)
                .title("Use of tx.origin for authorization in function: " + function.getName())
                .description("The function uses tx.origin for authorization checks. This is dangerous as " +
                           "it can be exploited through phishing attacks where users are tricked into " +
                           "calling a malicious contract.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Replace tx.origin with msg.sender for access control checks.")
                .confidenceScore(0.95)
                .cweId("CWE-863")
                .owaspCategory("A1:2021 - Broken Access Control")
                .build();
    }
    
    private Finding createUnprotectedSelfdestructFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        int lineNumber = getLineNumber(contract.getSourceCode(), "selfdestruct");
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity("CRITICAL")
                .category(category)
                .title("Unprotected selfdestruct in function: " + function.getName())
                .description("The function contains a selfdestruct call without proper access control. " +
                           "This allows anyone to destroy the contract and drain its funds.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Add access control modifiers (e.g., onlyOwner) to restrict who can call selfdestruct.")
                .confidenceScore(0.9)
                .cweId("CWE-284")
                .owaspCategory("A1:2021 - Broken Access Control")
                .build();
    }
    
    private Finding createUnprotectedDelegatecallFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        int lineNumber = getLineNumber(contract.getSourceCode(), "delegatecall");
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity("CRITICAL")
                .category(category)
                .title("Unprotected delegatecall in function: " + function.getName())
                .description("The function uses delegatecall without proper access control. " +
                           "Delegatecall executes code in the context of the calling contract, " +
                           "which can lead to complete contract takeover if misused.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Add strict access control to functions using delegatecall. " +
                              "Only allow trusted addresses to execute delegatecall.")
                .confidenceScore(0.9)
                .cweId("CWE-284")
                .owaspCategory("A1:2021 - Broken Access Control")
                .build();
    }
    
    private Finding createMissingAccessControlFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity("MEDIUM")
                .category(category)
                .title("Missing access control in function: " + function.getName())
                .description("The public/external function '" + function.getName() + 
                           "' modifies contract state but lacks access control mechanisms.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(function.getStartLine())
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), function.getStartLine(), 5))
                .recommendation("Add appropriate access control modifiers or require statements to restrict function access.")
                .confidenceScore(0.7)
                .cweId("CWE-284")
                .owaspCategory("A1:2021 - Broken Access Control")
                .build();
    }
}
