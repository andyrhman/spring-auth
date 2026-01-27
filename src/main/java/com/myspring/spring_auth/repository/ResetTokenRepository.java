package com.myspring.spring_auth.repository;

import com.myspring.spring_auth.entity.ResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ResetTokenRepository extends JpaRepository<ResetToken, UUID> {
    Optional<ResetToken> findByToken(String token);

    void deleteAllByEmail(String email);
}
