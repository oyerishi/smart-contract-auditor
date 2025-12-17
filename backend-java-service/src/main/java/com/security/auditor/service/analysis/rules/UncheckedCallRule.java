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
public class UncheckedCallRule extends AnalysisRule {
    
    private static final Pattern LOW_LEVEL_CALL_PATTERN = Pattern.compile(
            "\\.(call|send|delegatecall|staticcall|callcode)\\s*\\(");
    
    private static final Pattern RETURN_CHECK_PATTERN = Pattern.compile(
            "\\(\\s*bool\\s+\\w+\\s*,.*\\)\\s*=.*\\.(call|send)");
    
    private static final Pattern REQUIRE_PATTERN = Pattern.compile("require\\s*\\(");
    
    public UncheckedCallRule() {
        super("UC001", "Unchecked External Call", "HIGH", "External Calls");
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
            String[] lines = body.split("\n");
            
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                
                // Check for low-level calls
                if (containsPattern(line, LOW_LEVEL_CALL_PATTERN)) {
                    boolean hasReturnCheck = containsPattern(line, RETURN_CHECK_PATTERN);
                    boolean hasRequireAfter = false;
                    
                    // Check next few lines for require statement
                    for (int j = i + 1; j < Math.min(i + 3, lines.length); j++) {
                        if (containsPattern(lines[j], REQUIRE_PATTERN)) {
                            hasRequireAfter = true;
                            break;
                        }
                    }
                    
                    if (!hasReturnCheck && !hasRequireAfter) {
                        findings.add(createFinding(
                                contract,
                                function,
                                function.getStartLine() + i,
                                line.trim()
                        ));
                    }
                }
            }
        }
        
        return findings;
    }
    
    private Finding createFinding(ParsedContract contract, ParsedContract.FunctionInfo function,
                                   int lineNumber, String callLine) {
        String callType = extractCallType(callLine);
        
        return Finding.builder()
                .ruleId(ruleId)
                .ruleName(ruleName)
                .severity(severity)
                .category(category)
                .title("Unchecked " + callType + " return value in function: " + function.getName())
                .description("The function makes a low-level " + callType + " without checking its return value. " +
                           "External calls can fail silently, and unchecked failures can lead to unexpected behavior.")
                .location(contract.getContractName() + "." + function.getName())
                .lineNumber(lineNumber)
                .codeSnippet(getCodeSnippet(contract.getSourceCode(), lineNumber, 3))
                .recommendation("Always check the return value of low-level calls. Use require() to ensure " +
                              "the call succeeded: require(success, \"Call failed\");")
                .confidenceScore(0.85)
                .cweId("CWE-252")
                .owaspCategory("A4:2021 - Insecure Design")
                .build();
    }
    
    private String extractCallType(String line) {
        if (line.contains(".call(")) return "call";
        if (line.contains(".send(")) return "send";
        if (line.contains(".delegatecall(")) return "delegatecall";
        if (line.contains(".staticcall(")) return "staticcall";
        if (line.contains(".callcode(")) return "callcode";
        return "external call";
    }
}
