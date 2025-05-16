// src/main/java/com/expensepro/expensemanagement/repository/PasswordResetTokenRepository.java
package com.expensepro.expensemanagement.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.expensepro.expensemanagement.model.PasswordResetToken;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
}
