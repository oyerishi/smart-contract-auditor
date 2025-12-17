package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ParsedContract {
    
    private String contractName;
    private String sourceCode;
    private List<String> imports;
    private List<FunctionInfo> functions;
    private List<ModifierInfo> modifiers;
    private List<StateVariableInfo> stateVariables;
    private List<EventInfo> events;
    private List<String> inheritedContracts;
    private String solcVersion;
    private Integer totalLines;
    private Map<String, Object> metadata;
    
    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class FunctionInfo {
        private String name;
        private String visibility;
        private String stateMutability;
        private List<ParameterInfo> parameters;
        private List<ParameterInfo> returnParameters;
        private List<String> modifiers;
        private String body;
        private Integer startLine;
        private Integer endLine;
        private Boolean isConstructor;
        private Boolean isFallback;
        private Boolean isReceive;
        private Boolean isPayable;
    }
    
    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ModifierInfo {
        private String name;
        private List<ParameterInfo> parameters;
        private String body;
        private Integer startLine;
        private Integer endLine;
    }
    
    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class StateVariableInfo {
        private String name;
        private String type;
        private String visibility;
        private Boolean isConstant;
        private Boolean isImmutable;
        private String initialValue;
        private Integer lineNumber;
    }
    
    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class EventInfo {
        private String name;
        private List<ParameterInfo> parameters;
        private Integer lineNumber;
    }
    
    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ParameterInfo {
        private String name;
        private String type;
        private Boolean indexed;
    }
}
