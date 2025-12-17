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
public class RandomnessRule extends AnalysisRule {
    
    private static final Pattern BLOCK_TIMESTAMP_PATTERN = Pattern.compile(
            "block\\.timestamp|now\\b");
    
    private static final Pattern BLOCK_NUMBER_PATTERN = Pattern.compile(
            "block\\.number");
    
    private static final Pattern BLOCK_HASH_PATTERN = Pattern.compile(
            "blockhash\\s*\\(|block\\.blockhash");
    
    private static final Pattern RANDOM_USAGE_PATTERN = Pattern.compile(
            "random|rand|lottery|winner");
    
    public RandomnessRule() {
        super("RN001", "Weak Randomness", "MEDIUM", "Randomness");
    }
    
    @Override
    public List<Finding> analyze(ParsedContract contract) {
        List<Finding> findings = new ArrayList<>();
        
        if (contract.getFunctions() == null) {
            return findings;
        }
        
        for (ParsedContract.FunctionInfo function : contract.getFunctions()) {
            if (function.getBody() == null) continue;
            
            String body = function.getBody();
            boolean hasRandomUsage = containsPattern(function.getName().toLowerCase(), RANDOM_USAGE_PATTERN) ||
                                    containsPattern(body.toLowerCase(), RANDOM_USAGE_PATTERN);
            
            // Check for block.timestamp usage
            if (containsPattern(body, BLOCK_TIMESTAMP_PATTERN)) {
                if (hasRandomUsage || seemsLikeRandomness(body)) {
                    findings.add(createTimestampFinding(contract, function));
                }
            }
            
            // Check for block.number usage
            if (containsPattern(body, BLOCK_NUMBER_PATTERN)) {
                if (hasRandomUsage || seemsLikeRandomness(body)) {
                    findings.add(createBlockNumberFinding(contract, function));
                }
            }
            
            // Check for blockhash usage
            if (containsPattern(body, BLOCK_HASH_PATTERN)) {
                if (hasRandomUsage || seemsLikeRandomness(body)) {
                    findings.add(createBlockhashFinding(contract, function));
                }
            }
        }
        
        return findings;
    }
    
    private boolean seemsLikeRandomness(String body) {
        // Check if body contains modulo operations with block variables
        return body.contains("%") && 
               (containsPattern(body, BLOCK_TIMESTAMP_PATTERN) ||
                containsPattern(body, BLOCK_NUMBER_PATTERN) ||
                containsPattern(body, BLOCK_HASH_PATTERN));
    }
    
    private Finding createTimestampFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        int lineNumber = getLineNumber(contract.getSourceCode(), "block.timestamp");
        if (lineNumber == -1) {
            lineNumber = getLineNumber(contract.getSourceCode(), "now");
        }
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity(severity)
                .category(category)
                .title("Weak randomness using block.timestamp in function: " + function.getName())
                .description("The function uses block.timestamp (or now) for randomness. " +
                           "Miners can manipulate timestamps within a certain range, making this " +
                           "source of randomness predictable and exploitable.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Use Chainlink VRF (Verifiable Random Function) or commit-reveal schemes " +
                              "for secure randomness. Never use block variables for random number generation.")
                .confidenceScore(0.8)
                .cweId("CWE-330")
                .owaspCategory("A2:2021 - Cryptographic Failures")
                .build();
    }
    
    private Finding createBlockNumberFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        int lineNumber = getLineNumber(contract.getSourceCode(), "block.number");
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity(severity)
                .category(category)
                .title("Weak randomness using block.number in function: " + function.getName())
                .description("The function uses block.number for randomness. Block numbers are " +
                           "predictable and can be anticipated by attackers, making them unsuitable " +
                           "for random number generation.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Use Chainlink VRF or other secure randomness sources. " +
                              "Block variables should not be used for random number generation.")
                .confidenceScore(0.8)
                .cweId("CWE-330")
                .owaspCategory("A2:2021 - Cryptographic Failures")
                .build();
    }
    
    private Finding createBlockhashFinding(ParsedContract contract, ParsedContract.FunctionInfo function) {
        int lineNumber = getLineNumber(contract.getSourceCode(), "blockhash");
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity(severity)
                .category(category)
                .title("Weak randomness using blockhash in function: " + function.getName())
                .description("The function uses blockhash for randomness. While better than timestamp, " +
                           "blockhash can still be influenced by miners and is only available for the " +
                           "most recent 256 blocks.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Use Chainlink VRF for truly random and verifiable random numbers. " +
                              "Blockhash is not suitable for applications requiring secure randomness.")
                .confidenceScore(0.75)
                .cweId("CWE-330")
                .owaspCategory("A2:2021 - Cryptographic Failures")
                .build();
    }
}
