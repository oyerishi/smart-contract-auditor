package com.security.auditor.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class FileStorageService {
    
    private final S3Client s3Client;
    private final S3Presigner s3Presigner;
    
    @Value("${aws.s3.bucket-name}")
    private String bucketName;
    
    @Value("${aws.s3.contract-folder:contracts}")
    private String contractFolder;
    
    @Value("${aws.s3.report-folder:reports}")
    private String reportFolder;
    
    /**
     * Upload contract file to S3
     */
    public String uploadContract(MultipartFile file, Long userId) throws IOException {
        validateFile(file);
        
        String fileName = generateFileName(file.getOriginalFilename(), userId);
        String key = contractFolder + "/" + fileName;
        
        log.info("Uploading contract file: {} to S3 bucket: {}", fileName, bucketName);
        
        try (InputStream inputStream = file.getInputStream()) {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .contentType(file.getContentType())
                    .contentLength(file.getSize())
                    .metadata(java.util.Map.of(
                            "original-filename", file.getOriginalFilename(),
                            "user-id", userId.toString(),
                            "upload-timestamp", String.valueOf(System.currentTimeMillis())
                    ))
                    .build();
            
            s3Client.putObject(putObjectRequest, RequestBody.fromInputStream(inputStream, file.getSize()));
            
            log.info("Successfully uploaded contract file: {}", key);
            return key;
        } catch (S3Exception e) {
            log.error("Failed to upload file to S3: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to upload file to S3: " + e.getMessage(), e);
        }
    }
    
    /**
     * Upload report file to S3
     */
    public String uploadReport(byte[] reportData, String fileName, Long scanId) {
        String key = reportFolder + "/" + generateReportFileName(fileName, scanId);
        
        log.info("Uploading report file: {} to S3 bucket: {}", key, bucketName);
        
        try {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .contentType("application/pdf")
                    .contentLength((long) reportData.length)
                    .metadata(java.util.Map.of(
                            "scan-id", scanId.toString(),
                            "upload-timestamp", String.valueOf(System.currentTimeMillis())
                    ))
                    .build();
            
            s3Client.putObject(putObjectRequest, RequestBody.fromBytes(reportData));
            
            log.info("Successfully uploaded report file: {}", key);
            return key;
        } catch (S3Exception e) {
            log.error("Failed to upload report to S3: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to upload report to S3: " + e.getMessage(), e);
        }
    }
    
    /**
     * Download file from S3
     */
    public InputStream downloadFile(String key) {
        log.info("Downloading file from S3: {}", key);
        
        try {
            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            
            return s3Client.getObject(getObjectRequest);
        } catch (S3Exception e) {
            log.error("Failed to download file from S3: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to download file from S3: " + e.getMessage(), e);
        }
    }
    
    /**
     * Generate presigned URL for file download
     */
    public String generatePresignedUrl(String key, Duration duration) {
        log.info("Generating presigned URL for file: {}", key);
        
        try {
            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            
            GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
                    .signatureDuration(duration)
                    .getObjectRequest(getObjectRequest)
                    .build();
            
            PresignedGetObjectRequest presignedRequest = s3Presigner.presignGetObject(presignRequest);
            
            return presignedRequest.url().toString();
        } catch (S3Exception e) {
            log.error("Failed to generate presigned URL: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate presigned URL: " + e.getMessage(), e);
        }
    }
    
    /**
     * Delete file from S3
     */
    public void deleteFile(String key) {
        log.info("Deleting file from S3: {}", key);
        
        try {
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            
            s3Client.deleteObject(deleteObjectRequest);
            log.info("Successfully deleted file: {}", key);
        } catch (S3Exception e) {
            log.error("Failed to delete file from S3: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to delete file from S3: " + e.getMessage(), e);
        }
    }
    
    /**
     * Check if file exists in S3
     */
    public boolean fileExists(String key) {
        try {
            HeadObjectRequest headObjectRequest = HeadObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            
            s3Client.headObject(headObjectRequest);
            return true;
        } catch (NoSuchKeyException e) {
            return false;
        } catch (S3Exception e) {
            log.error("Error checking file existence: {}", e.getMessage(), e);
            throw new RuntimeException("Error checking file existence: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get file metadata
     */
    public java.util.Map<String, String> getFileMetadata(String key) {
        try {
            HeadObjectRequest headObjectRequest = HeadObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            
            HeadObjectResponse response = s3Client.headObject(headObjectRequest);
            return response.metadata();
        } catch (S3Exception e) {
            log.error("Failed to get file metadata: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get file metadata: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get file size
     */
    public Long getFileSize(String key) {
        try {
            HeadObjectRequest headObjectRequest = HeadObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            
            HeadObjectResponse response = s3Client.headObject(headObjectRequest);
            return response.contentLength();
        } catch (S3Exception e) {
            log.error("Failed to get file size: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get file size: " + e.getMessage(), e);
        }
    }
    
    /**
     * Validate uploaded file
     */
    private void validateFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File is empty or null");
        }
        
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.trim().isEmpty()) {
            throw new IllegalArgumentException("File name is invalid");
        }
        
        // Check file extension
        String extension = getFileExtension(originalFilename);
        if (!isValidContractExtension(extension)) {
            throw new IllegalArgumentException("Invalid file type. Only .sol files are allowed");
        }
        
        // Check file size (max 10MB)
        long maxSize = 10 * 1024 * 1024; // 10MB
        if (file.getSize() > maxSize) {
            throw new IllegalArgumentException("File size exceeds maximum allowed size of 10MB");
        }
    }
    
    /**
     * Check if file extension is valid for contracts
     */
    private boolean isValidContractExtension(String extension) {
        return extension.equalsIgnoreCase("sol");
    }
    
    /**
     * Generate unique file name
     */
    private String generateFileName(String originalFilename, Long userId) {
        String extension = getFileExtension(originalFilename);
        String uuid = UUID.randomUUID().toString();
        return String.format("%d_%s_%d.%s", userId, uuid, System.currentTimeMillis(), extension);
    }
    
    /**
     * Generate report file name
     */
    private String generateReportFileName(String fileName, Long scanId) {
        if (fileName == null || fileName.trim().isEmpty()) {
            fileName = "report";
        }
        String uuid = UUID.randomUUID().toString();
        return String.format("%d_%s_%d.pdf", scanId, uuid, System.currentTimeMillis());
    }
    
    /**
     * Get file extension from filename
     */
    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return "";
        }
        return filename.substring(filename.lastIndexOf(".") + 1);
    }
}
