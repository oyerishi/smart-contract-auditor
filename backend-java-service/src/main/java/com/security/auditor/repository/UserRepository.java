package com.security.auditor.repository;

import com.security.auditor.model.entity.User;
import com.security.auditor.model.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * User Repository
 * Data access layer for User entity
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by username
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email
     */
    Optional<User> findByEmail(String email);

    /**
     * Find user by username or email
     */
    Optional<User> findByUsernameOrEmail(String username, String email);

    /**
     * Check if username exists
     */
    boolean existsByUsername(String username);

    /**
     * Check if email exists
     */
    boolean existsByEmail(String email);

    /**
     * Find all active users
     */
    List<User> findByIsActive(Boolean isActive);

    /**
     * Find users by role
     */
    List<User> findByRole(UserRole role);

    /**
     * Find users who have exceeded their quota
     */
    @Query("SELECT u FROM User u WHERE u.apiQuotaUsed >= u.apiQuota")
    List<User> findUsersExceededQuota();

    /**
     * Find users with remaining quota
     */
    @Query("SELECT u FROM User u WHERE u.apiQuotaUsed < u.apiQuota")
    List<User> findUsersWithRemainingQuota();

    /**
     * Update last login timestamp
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :loginTime WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") Long userId, @Param("loginTime") LocalDateTime loginTime);

    /**
     * Update user quota usage
     */
    @Modifying
    @Query("UPDATE User u SET u.apiQuotaUsed = u.apiQuotaUsed + 1 WHERE u.id = :userId")
    void incrementQuotaUsed(@Param("userId") Long userId);

    /**
     * Reset quota for all users
     */
    @Modifying
    @Query("UPDATE User u SET u.apiQuotaUsed = 0")
    void resetAllQuotas();

    /**
     * Find users created within date range
     */
    List<User> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Count active users
     */
    long countByIsActive(Boolean isActive);

    /**
     * Find users by email verification status
     */
    List<User> findByIsEmailVerified(Boolean isEmailVerified);
}
