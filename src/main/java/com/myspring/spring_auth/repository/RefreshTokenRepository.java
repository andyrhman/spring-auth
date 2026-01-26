package com.myspring.spring_auth.repository;

import com.myspring.spring_auth.entity.RefreshToken;
import com.myspring.spring_auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;
import java.util.List;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findAllByUser(User user);

    void deleteAllByUser(User user);
}
