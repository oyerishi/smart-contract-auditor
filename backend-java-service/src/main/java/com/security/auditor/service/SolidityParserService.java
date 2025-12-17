package com.security.auditor.service;

import com.security.auditor.model.dto.ParsedContract;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SolidityParserService {
    
    // Regex patterns for Solidity parsing
    private static final Pattern CONTRACT_PATTERN = Pattern.compile(
            "contract\\s+(\\w+)(?:\\s+is\\s+([\\w,\\s]+))?\\s*\\{");
    
    private static final Pattern FUNCTION_PATTERN = Pattern.compile(
            "function\\s+(\\w+)\\s*\\([^)]*\\)\\s*(?:(public|private|internal|external))?\\s*(?:(pure|view|payable))?\\s*(?:returns\\s*\\([^)]*\\))?");
    
    private static final Pattern MODIFIER_PATTERN = Pattern.compile(
            "modifier\\s+(\\w+)\\s*\\([^)]*\\)");
    
    private static final Pattern STATE_VAR_PATTERN = Pattern.compile(
            "(uint|int|bool|address|string|bytes\\d*|mapping\\([^)]+\\))\\s+(public|private|internal)?\\s*(constant|immutable)?\\s+(\\w+)");
    
    private static final Pattern EVENT_PATTERN = Pattern.compile(
            "event\\s+(\\w+)\\s*\\([^)]*\\)");
    
    private static final Pattern PRAGMA_PATTERN = Pattern.compile(
            "pragma\\s+solidity\\s+([^;]+);");
    
    private static final Pattern IMPORT_PATTERN = Pattern.compile(
            "import\\s+[\"']([^\"']+)[\"']");
    
    /**
     * Parse Solidity source code from InputStream
     */
    public ParsedContract parseContract(InputStream inputStream) throws IOException {
        String sourceCode = readInputStream(inputStream);
        return parseContract(sourceCode);
    }
    
    /**
     * Parse Solidity source code from String
     */
    public ParsedContract parseContract(String sourceCode) {
        log.info("Starting Solidity contract parsing");
        
        try {
            ParsedContract.ParsedContractBuilder builder = ParsedContract.builder();
            
            // Basic info
            builder.sourceCode(sourceCode);
            builder.totalLines(countLines(sourceCode));
            
            // Extract contract name and inheritance
            extractContractInfo(sourceCode, builder);
            
            // Extract pragma version
            extractPragmaVersion(sourceCode, builder);
            
            // Extract imports
            builder.imports(extractImports(sourceCode));
            
            // Extract functions
            builder.functions(extractFunctions(sourceCode));
            
            // Extract modifiers
            builder.modifiers(extractModifiers(sourceCode));
            
            // Extract state variables
            builder.stateVariables(extractStateVariables(sourceCode));
            
            // Extract events
            builder.events(extractEvents(sourceCode));
            
            // Add metadata
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("hasFallback", hasFallbackFunction(sourceCode));
            metadata.put("hasReceive", hasReceiveFunction(sourceCode));
            metadata.put("hasConstructor", hasConstructor(sourceCode));
            metadata.put("functionCount", builder.build().getFunctions() != null ? builder.build().getFunctions().size() : 0);
            builder.metadata(metadata);
            
            ParsedContract parsed = builder.build();
            log.info("Successfully parsed contract: {}", parsed.getContractName());
            
            return parsed;
        } catch (Exception e) {
            log.error("Error parsing Solidity contract: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to parse Solidity contract: " + e.getMessage(), e);
        }
    }
    
    /**
     * Extract contract name and inherited contracts
     */
    private void extractContractInfo(String sourceCode, ParsedContract.ParsedContractBuilder builder) {
        Matcher matcher = CONTRACT_PATTERN.matcher(sourceCode);
        if (matcher.find()) {
            builder.contractName(matcher.group(1));
            
            if (matcher.group(2) != null) {
                List<String> inherited = Arrays.stream(matcher.group(2).split(","))
                        .map(String::trim)
                        .collect(Collectors.toList());
                builder.inheritedContracts(inherited);
            } else {
                builder.inheritedContracts(new ArrayList<>());
            }
        }
    }
    
    /**
     * Extract pragma version
     */
    private void extractPragmaVersion(String sourceCode, ParsedContract.ParsedContractBuilder builder) {
        Matcher matcher = PRAGMA_PATTERN.matcher(sourceCode);
        if (matcher.find()) {
            builder.solcVersion(matcher.group(1).trim());
        }
    }
    
    /**
     * Extract import statements
     */
    private List<String> extractImports(String sourceCode) {
        List<String> imports = new ArrayList<>();
        Matcher matcher = IMPORT_PATTERN.matcher(sourceCode);
        while (matcher.find()) {
            imports.add(matcher.group(1));
        }
        return imports;
    }
    
    /**
     * Extract functions from source code
     */
    private List<ParsedContract.FunctionInfo> extractFunctions(String sourceCode) {
        List<ParsedContract.FunctionInfo> functions = new ArrayList<>();
        String[] lines = sourceCode.split("\n");
        
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            
            if (line.startsWith("function") || line.contains(" function ")) {
                ParsedContract.FunctionInfo functionInfo = parseFunctionDeclaration(line, i + 1);
                if (functionInfo != null) {
                    // Extract function body
                    int startLine = i;
                    int braceCount = 0;
                    StringBuilder body = new StringBuilder();
                    
                    for (int j = i; j < lines.length; j++) {
                        String currentLine = lines[j];
                        body.append(currentLine).append("\n");
                        
                        for (char c : currentLine.toCharArray()) {
                            if (c == '{') braceCount++;
                            if (c == '}') braceCount--;
                        }
                        
                        if (braceCount == 0 && currentLine.contains("{")) {
                            functionInfo.setStartLine(startLine + 1);
                            functionInfo.setEndLine(j + 1);
                            functionInfo.setBody(body.toString());
                            break;
                        }
                    }
                    
                    functions.add(functionInfo);
                }
            }
        }
        
        return functions;
    }
    
    /**
     * Parse function declaration
     */
    private ParsedContract.FunctionInfo parseFunctionDeclaration(String declaration, int lineNumber) {
        ParsedContract.FunctionInfo.FunctionInfoBuilder builder = ParsedContract.FunctionInfo.builder();
        
        // Check for constructor
        if (declaration.contains("constructor")) {
            builder.name("constructor");
            builder.isConstructor(true);
        } else {
            Matcher matcher = Pattern.compile("function\\s+(\\w+)").matcher(declaration);
            if (matcher.find()) {
                builder.name(matcher.group(1));
            } else {
                return null;
            }
        }
        
        // Extract visibility
        if (declaration.contains("public")) builder.visibility("public");
        else if (declaration.contains("private")) builder.visibility("private");
        else if (declaration.contains("internal")) builder.visibility("internal");
        else if (declaration.contains("external")) builder.visibility("external");
        else builder.visibility("public"); // default
        
        // Extract state mutability
        if (declaration.contains("pure")) builder.stateMutability("pure");
        else if (declaration.contains("view")) builder.stateMutability("view");
        else if (declaration.contains("payable")) {
            builder.stateMutability("payable");
            builder.isPayable(true);
        }
        
        // Check special functions
        builder.isFallback(declaration.contains("fallback"));
        builder.isReceive(declaration.contains("receive"));
        
        builder.startLine(lineNumber);
        builder.parameters(new ArrayList<>());
        builder.returnParameters(new ArrayList<>());
        builder.modifiers(new ArrayList<>());
        
        return builder.build();
    }
    
    /**
     * Extract modifiers
     */
    private List<ParsedContract.ModifierInfo> extractModifiers(String sourceCode) {
        List<ParsedContract.ModifierInfo> modifiers = new ArrayList<>();
        String[] lines = sourceCode.split("\n");
        
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            
            if (line.startsWith("modifier")) {
                Matcher matcher = MODIFIER_PATTERN.matcher(line);
                if (matcher.find()) {
                    ParsedContract.ModifierInfo modifierInfo = ParsedContract.ModifierInfo.builder()
                            .name(matcher.group(1))
                            .startLine(i + 1)
                            .parameters(new ArrayList<>())
                            .build();
                    
                    modifiers.add(modifierInfo);
                }
            }
        }
        
        return modifiers;
    }
    
    /**
     * Extract state variables
     */
    private List<ParsedContract.StateVariableInfo> extractStateVariables(String sourceCode) {
        List<ParsedContract.StateVariableInfo> variables = new ArrayList<>();
        String[] lines = sourceCode.split("\n");
        
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            
            // Skip functions and modifiers
            if (line.startsWith("function") || line.startsWith("modifier") || 
                line.startsWith("constructor") || line.startsWith("event")) {
                continue;
            }
            
            Matcher matcher = STATE_VAR_PATTERN.matcher(line);
            if (matcher.find()) {
                ParsedContract.StateVariableInfo varInfo = ParsedContract.StateVariableInfo.builder()
                        .type(matcher.group(1))
                        .visibility(matcher.group(2) != null ? matcher.group(2) : "internal")
                        .isConstant(line.contains("constant"))
                        .isImmutable(line.contains("immutable"))
                        .name(matcher.group(4))
                        .lineNumber(i + 1)
                        .build();
                
                variables.add(varInfo);
            }
        }
        
        return variables;
    }
    
    /**
     * Extract events
     */
    private List<ParsedContract.EventInfo> extractEvents(String sourceCode) {
        List<ParsedContract.EventInfo> events = new ArrayList<>();
        String[] lines = sourceCode.split("\n");
        
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            
            if (line.startsWith("event")) {
                Matcher matcher = EVENT_PATTERN.matcher(line);
                if (matcher.find()) {
                    ParsedContract.EventInfo eventInfo = ParsedContract.EventInfo.builder()
                            .name(matcher.group(1))
                            .lineNumber(i + 1)
                            .parameters(new ArrayList<>())
                            .build();
                    
                    events.add(eventInfo);
                }
            }
        }
        
        return events;
    }
    
    /**
     * Check if contract has fallback function
     */
    private boolean hasFallbackFunction(String sourceCode) {
        return sourceCode.contains("fallback()") || 
               Pattern.compile("function\\s+\\(\\)\\s+external").matcher(sourceCode).find();
    }
    
    /**
     * Check if contract has receive function
     */
    private boolean hasReceiveFunction(String sourceCode) {
        return sourceCode.contains("receive()");
    }
    
    /**
     * Check if contract has constructor
     */
    private boolean hasConstructor(String sourceCode) {
        return sourceCode.contains("constructor(");
    }
    
    /**
     * Read InputStream to String
     */
    private String readInputStream(InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
    
    /**
     * Count lines in source code
     */
    private int countLines(String sourceCode) {
        if (sourceCode == null || sourceCode.isEmpty()) {
            return 0;
        }
        return (int) sourceCode.lines().count();
    }
    
    /**
     * Validate Solidity source code
     */
    public boolean isValidSolidityCode(String sourceCode) {
        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            return false;
        }
        
        // Check for basic Solidity syntax
        return sourceCode.contains("pragma solidity") && 
               (sourceCode.contains("contract") || sourceCode.contains("interface") || sourceCode.contains("library"));
    }
    
    /**
     * Extract function calls from function body
     */
    public List<String> extractFunctionCalls(String functionBody) {
        List<String> calls = new ArrayList<>();
        
        if (functionBody == null || functionBody.isEmpty()) {
            return calls;
        }
        
        // Pattern to match function calls: identifier followed by parentheses
        Pattern callPattern = Pattern.compile("(\\w+)\\s*\\(");
        Matcher matcher = callPattern.matcher(functionBody);
        
        while (matcher.find()) {
            String functionName = matcher.group(1);
            // Filter out keywords
            if (!isKeyword(functionName)) {
                calls.add(functionName);
            }
        }
        
        return calls;
    }
    
    /**
     * Check if string is a Solidity keyword
     */
    private boolean isKeyword(String word) {
        Set<String> keywords = Set.of(
                "if", "else", "for", "while", "do", "return", "require", "assert", "revert",
                "new", "delete", "this", "super", "true", "false", "function", "modifier"
        );
        return keywords.contains(word);
    }
}
