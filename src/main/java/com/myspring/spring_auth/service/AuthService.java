package com.myspring.spring_auth.service;

import com.myspring.spring_auth.entity.RefreshToken;
import com.myspring.spring_auth.entity.User;
import com.myspring.spring_auth.repository.RefreshTokenRepository;
import com.myspring.spring_auth.repository.UserRepository;
import com.myspring.spring_auth.security.JwtUtil;
import com.myspring.spring_auth.util.HashUtil;
import com.myspring.spring_auth.util.InvalidCredentialsException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final long refreshDays;

    public record AuthTokens(String accessToken, String refreshToken) {
    }

    public AuthService(UserRepository userRepo,
            RefreshTokenRepository refreshRepo,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            @Value("${app.jwt.refresh-token-expiration-days:30}") long refreshDays) {
        this.userRepo = userRepo;
        this.refreshRepo = refreshRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.refreshDays = refreshDays;
    }

    public User register(String username, String email, String firstName, String lastName, String rawPassword) {
        if (userRepo.existsByUsername(username))
            throw new IllegalArgumentException("username already exists");
        if (userRepo.findByEmail(email.toLowerCase(Locale.ROOT)).isPresent())
            throw new IllegalArgumentException("Email already exists");

        User u = new User();
        u.setUsername(username);
        u.setEmail(email.toLowerCase(Locale.ROOT));
        u.setFirstName(firstName);
        u.setLastName(lastName);
        u.setPassword(passwordEncoder.encode(rawPassword));
        return userRepo.save(u);
    }

    public AuthTokens login(String usernameOrEmail, String rawPassword) {
        // try username first, then email
        User user = userRepo.findByUsername(usernameOrEmail)
                .or(() -> userRepo.findByEmail(usernameOrEmail.toLowerCase(Locale.ROOT)))
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new InvalidCredentialsException();
        }

        String access = jwtUtil.generateAccessToken(user.getUsername(), List.of("ROLE_USER"));
        String plainRefresh = generateRefreshPlain();
        storeRefreshToken(plainRefresh, user);

        return new AuthTokens(access, plainRefresh);
    }

    private String generateRefreshPlain() {
        // high-entropy opaque token
        return UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString();
    }

    public void storeRefreshToken(String plainToken, User user) {
        String hash = HashUtil.sha256Hex(plainToken);
        RefreshToken rt = new RefreshToken();
        rt.setTokenHash(hash);
        rt.setUser(user);
        rt.setExpiresAt(Instant.now().plus(refreshDays, ChronoUnit.DAYS));
        rt.setRevoked(false);
        refreshRepo.save(rt);
    }

    public RefreshToken findByPlainToken(String plain) {
        String hash = HashUtil.sha256Hex(plain);
        return refreshRepo.findByTokenHash(hash).orElse(null);
    }

    public AuthTokens refresh(String plainToken) {
        RefreshToken rt = findByPlainToken(plainToken);
        if (rt == null)
            throw new IllegalArgumentException("Invalid refresh token");
        if (rt.isRevoked() || rt.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Expired or revoked refresh token");
        }

        // rotate: revoke old token and create new one
        rt.setRevoked(true);
        refreshRepo.save(rt);

        User user = rt.getUser();

        String newAccess = jwtUtil.generateAccessToken(user.getUsername(), List.of("ROLE_USER"));
        String newPlain = generateRefreshPlain();
        storeRefreshToken(newPlain, user);

        return new AuthTokens(newAccess, newPlain);
    }

    public void revokeByPlain(String plainToken) {
        var rt = findByPlainToken(plainToken);
        if (rt != null) {
            rt.setRevoked(true);
            refreshRepo.save(rt);
        }
    }
}
