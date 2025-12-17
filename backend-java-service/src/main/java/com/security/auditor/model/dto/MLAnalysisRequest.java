package com.security.auditor.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MLAnalysisRequest {
    private String contractCode;
    private String contractName;
    private String solcVersion;
    private ParsedContract parsedContract;
}
