package com.security.auditor.repository;

import com.security.auditor.model.entity.Contract;
import com.security.auditor.model.entity.ContractType;
import com.security.auditor.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Contract Repository
 * Data access layer for Contract entity
 */
@Repository
public interface ContractRepository extends JpaRepository<Contract, Long> {

    /**
     * Find all contracts by user
     */
    List<Contract> findByUser(User user);

    /**
     * Find all contracts by user ID
     */
    List<Contract> findByUserId(Long userId);

    /**
     * Find contract by file path
     */
    Optional<Contract> findByFilePath(String filePath);

    /**
     * Find contract by file hash
     */
    Optional<Contract> findByFileHash(String fileHash);

    /**
     * Find contracts by type
     */
    List<Contract> findByContractType(ContractType contractType);

    /**
     * Find contracts by user and type
     */
    List<Contract> findByUserAndContractType(User user, ContractType contractType);

    /**
     * Find contracts by user ID and type
     */
    List<Contract> findByUserIdAndContractType(Long userId, ContractType contractType);

    /**
     * Find contracts by filename containing (case-insensitive)
     */
    List<Contract> findByFilenameContainingIgnoreCase(String filename);

    /**
     * Find contracts created within date range
     */
    List<Contract> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Find contracts by user created within date range
     */
    List<Contract> findByUserIdAndCreatedAtBetween(Long userId, LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Count contracts by user
     */
    long countByUserId(Long userId);

    /**
     * Count contracts by type
     */
    long countByContractType(ContractType contractType);

    /**
     * Find recent contracts by user (limit results)
     */
    @Query("SELECT c FROM Contract c WHERE c.user.id = :userId ORDER BY c.createdAt DESC")
    List<Contract> findRecentContractsByUserId(@Param("userId") Long userId);

    /**
     * Find contracts larger than specified size
     */
    @Query("SELECT c FROM Contract c WHERE c.fileSize > :size")
    List<Contract> findContractsLargerThan(@Param("size") Long size);

    /**
     * Check if user has uploaded a specific file (by hash)
     */
    @Query("SELECT CASE WHEN COUNT(c) > 0 THEN true ELSE false END FROM Contract c WHERE c.user.id = :userId AND c.fileHash = :fileHash")
    boolean hasUserUploadedFile(@Param("userId") Long userId, @Param("fileHash") String fileHash);

    /**
     * Delete contracts by user ID
     */
    void deleteByUserId(Long userId);
}
