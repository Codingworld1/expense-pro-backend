package com.expensepro.expensemanagement.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.expensepro.expensemanagement.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {

    // Find user by email (used for login)
    Optional<User> findByEmail(String email);
}
