package com.security.auditor.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

/**
 * Local file storage service as fallback when S3 is not configured
 */
@Service
@Slf4j
public class LocalFileStorageService {
    
    @Value("${app.storage.local-path:./uploads}")
    private String localStoragePath;
    
    /**
     * Save contract file locally
     */
    public String saveContractLocally(MultipartFile file, Long userId) throws IOException {
        // Create directory if not exists
        Path uploadDir = Paths.get(localStoragePath, "contracts", userId.toString());
        Files.createDirectories(uploadDir);
        
        // Generate unique filename
        String originalFilename = file.getOriginalFilename();
        String extension = originalFilename != null && originalFilename.contains(".") 
                ? originalFilename.substring(originalFilename.lastIndexOf(".")) 
                : ".sol";
        String filename = UUID.randomUUID().toString() + extension;
        
        // Save file
        Path filePath = uploadDir.resolve(filename);
        Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
        
        log.info("Saved contract file locally: {}", filePath);
        return filePath.toString();
    }
    
    /**
     * Read contract file from local storage
     */
    public byte[] readContract(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }
    
    /**
     * Delete contract file from local storage
     */
    public void deleteContract(String filePath) throws IOException {
        Files.deleteIfExists(Paths.get(filePath));
        log.info("Deleted contract file: {}", filePath);
    }
}
