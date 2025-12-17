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
public class ReentrancyRule extends AnalysisRule {
    
    private static final Pattern EXTERNAL_CALL_PATTERN = Pattern.compile(
            "\\.(call|delegatecall|staticcall|send|transfer)\\s*\\(");
    
    private static final Pattern STATE_CHANGE_PATTERN = Pattern.compile(
            "\\w+\\s*=\\s*[^=]|\\w+\\+\\+|\\w+--|\\w+\\s*\\+=|\\w+\\s*-=");
    
    public ReentrancyRule() {
        super("RE001", "Reentrancy Vulnerability", "CRITICAL", "Reentrancy");
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
            
            // Check for external calls followed by state changes
            if (containsPattern(body, EXTERNAL_CALL_PATTERN)) {
                // Split function body into lines
                String[] lines = body.split("\n");
                int externalCallLine = -1;
                
                for (int i = 0; i < lines.length; i++) {
                    if (containsPattern(lines[i], EXTERNAL_CALL_PATTERN)) {
                        externalCallLine = i;
                        
                        // Check if there are state changes after the call
                        for (int j = i + 1; j < lines.length; j++) {
                            if (containsPattern(lines[j], STATE_CHANGE_PATTERN)) {
                                findings.add(createFinding(
                                        contract,
                                        function,
                                        function.getStartLine() + j,
                                        "State change after external call in function: " + function.getName()
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        return findings;
    }
    
    private Finding createFinding(ParsedContract contract, ParsedContract.FunctionInfo function, 
                                   int lineNumber, String title) {
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity(severity)
                .category(category)
                .title(title)
                .description("The function '" + function.getName() + 
                           "' modifies state after making an external call. This can lead to reentrancy attacks " +
                           "where malicious contracts can re-enter the function before state changes are complete.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Apply the Checks-Effects-Interactions pattern: perform all state changes before " +
                              "making external calls. Consider using ReentrancyGuard from OpenZeppelin.")
                .confidenceScore(0.85)
                .cweId("CWE-841")
                .owaspCategory("A4:2021 - Insecure Design")
                .build();
    }
}
