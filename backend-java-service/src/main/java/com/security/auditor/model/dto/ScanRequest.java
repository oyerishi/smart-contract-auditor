package com.security.auditor.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ScanRequest {
    
    @NotBlank(message = "Contract name is required")
    @Size(min = 1, max = 255, message = "Contract name must be between 1 and 255 characters")
    private String contractName;
    
    @Size(max = 500, message = "Description must not exceed 500 characters")
    private String description;
    
    @NotBlank(message = "Blockchain type is required")
    @Pattern(regexp = "ETHEREUM|BINANCE_SMART_CHAIN|POLYGON|AVALANCHE|ARBITRUM|OPTIMISM", 
             message = "Invalid blockchain type")
    private String blockchainType;
    
    @NotNull(message = "File ID is required")
    private Long fileId;
    
    @Builder.Default
    private boolean enableMlAnalysis = true;
    
    @Builder.Default
    private boolean enableStaticAnalysis = true;
}
