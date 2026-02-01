package com.myspring.spring_auth.service;

import com.myspring.spring_auth.entity.ResetToken;
import com.myspring.spring_auth.exception.InvalidRequestException;
import com.myspring.spring_auth.repository.ResetTokenRepository;
import com.myspring.spring_auth.repository.UserRepository;
import com.myspring.spring_auth.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;

@Service
public class PasswordResetService {
    private final UserRepository userRepo;
    private final ResetTokenRepository resetRepo;
    private final MailService mailService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepo;
    private final long expirationMinutes;
    private final SecureRandom rnd = new SecureRandom();

    public PasswordResetService(UserRepository userRepo,
            ResetTokenRepository resetRepo,
            MailService mailService,
            PasswordEncoder passwordEncoder,
            RefreshTokenRepository refreshTokenRepo,
            @Value("${app.reset-token.expiration-minutes:30}") long expirationMinutes) {
        this.userRepo = userRepo;
        this.resetRepo = resetRepo;
        this.mailService = mailService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepo = refreshTokenRepo;
        this.expirationMinutes = expirationMinutes;
    }

    public void requestReset(String email) throws Exception {
        var userOpt = userRepo.findByEmail(email.toLowerCase(Locale.ROOT));
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("User not found"); // or return success to avoid email harvesting
        }
        // generate token
        byte[] b = new byte[16];
        rnd.nextBytes(b);
        String token = HexFormat.of().formatHex(b);

        ResetToken rt = new ResetToken();
        rt.setToken(token);
        rt.setEmail(email.toLowerCase(Locale.ROOT));
        rt.setExpiresAt(Instant.now().plusSeconds(expirationMinutes * 60));
        rt.setUsed(false);
        resetRepo.save(rt);

        // send email
        mailService.sendPasswordReset(email, token);
    }

    @Transactional
    public void performReset(String token, String password, String passwordConfirm) {
        if (!password.equals(passwordConfirm))
            throw new InvalidRequestException("Passwords do not match");
        ResetToken rt = resetRepo.findByToken(token).orElseThrow(() -> new InvalidRequestException("Invalid token"));

        if (rt.isUsed() || rt.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidRequestException("Token expired or already used");
        }

        var user = userRepo.findByEmail(rt.getEmail().toLowerCase(Locale.ROOT))
                .orElseThrow(() -> new InvalidRequestException("User not found"));

        // store hashed password (Argon2 PasswordEncoder bean)
        user.setPassword(passwordEncoder.encode(password));
        userRepo.save(user);

        // mark token used
        rt.setUsed(true);
        resetRepo.save(rt);

        // revoke all refresh tokens for user (force login)
        refreshTokenRepo.deleteAllByUser(user);
    }
}
