package com.myspring.spring_auth.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;

import com.myspring.spring_auth.entity.RefreshToken;
import com.myspring.spring_auth.entity.User;
import com.myspring.spring_auth.repository.RefreshTokenRepository;
import com.myspring.spring_auth.repository.UserRepository;
import com.myspring.spring_auth.security.JwtUtil;
import com.myspring.spring_auth.util.HashUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class AuthService {

    private final UserRepository userRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final long refreshDays;
    private final long rememberMeDays;

    private final SecureRandom rnd = new SecureRandom();
    private final Base32 base32 = new Base32();
    private final TimeBasedOneTimePasswordGenerator totpGenerator;

    public record AuthTokens(String accessToken, String refreshToken) {
    }

    public record LoginBeginResult(Map<String, Object> payload) {
    }

    public record TokensWithExpiry(String accessToken, String refreshToken, long refreshDays) {
    }

    public AuthService(UserRepository userRepo,
            RefreshTokenRepository refreshRepo,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            @Value("${app.jwt.refresh-token-expiration-days:30}") long refreshDays,
            @Value("${app.auth.remember-days:365}") long rememberMeDays) throws Exception {
        this.userRepo = userRepo;
        this.refreshRepo = refreshRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.refreshDays = refreshDays;
        this.rememberMeDays = rememberMeDays;
        this.totpGenerator = new TimeBasedOneTimePasswordGenerator(); // default 30s, 6 digits, HmacSHA1
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

    public void storeRefreshTokenWithExpiry(String plainToken, User user, long days) {
        String hash = HashUtil.sha256Hex(plainToken);
        RefreshToken rt = new RefreshToken();
        rt.setTokenHash(hash);
        rt.setUser(user);
        rt.setExpiresAt(Instant.now().plus(days, ChronoUnit.DAYS));
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
        if (rt.isRevoked() || rt.getExpiresAt().isBefore(Instant.now()))
            throw new IllegalArgumentException("Expired or revoked refresh token");

        // rotate
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

    public LoginBeginResult beginLogin(String usernameOrEmail, String rawPassword, boolean rememberMe) {
        User user = userRepo.findByUsername(usernameOrEmail)
                .or(() -> userRepo.findByEmail(usernameOrEmail.toLowerCase(Locale.ROOT)))
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        Map<String, Object> out = new HashMap<>();
        out.put("id", user.getId().toString());
        out.put("rememberMe", rememberMe);

        String tfaSecret = user.getTfaSecret();
        if (tfaSecret != null && !tfaSecret.isBlank()) {
            // user already enrolled -> require code step
            return new LoginBeginResult(out);
        } else {
            // generate a new secret (Base32) and otpauth URL for client to show QR
            byte[] secretBytes = new byte[20];
            rnd.nextBytes(secretBytes);
            String base32Secret = base32.encodeToString(secretBytes).replace("=", "");
            String otpAuthUrl = buildOtpAuthUrl("MyApp", user.getUsername(), base32Secret);
            out.put("secret", base32Secret);
            out.put("otpauth_url", otpAuthUrl);
            return new LoginBeginResult(out);
        }
    }

    public TokensWithExpiry completeTwoFactor(String idStr, String codeStr, String providedSecret, boolean rememberMe) {
        UUID id = UUID.fromString(idStr);
        User user = userRepo.findById(id).orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        // determine secret: stored or provided (during enrollment)
        String secret = (user.getTfaSecret() != null && !user.getTfaSecret().isBlank()) ? user.getTfaSecret()
                : providedSecret;
        if (secret == null || secret.isBlank())
            throw new IllegalArgumentException("Invalid credentials");

        boolean ok = verifyTotpCode(secret, codeStr, 1); // allow +/-1 step
        if (!ok)
            throw new IllegalArgumentException("Invalid credentials");

        // persist secret if new enrollment
        if (user.getTfaSecret() == null || user.getTfaSecret().isBlank()) {
            user.setTfaSecret(secret);
            userRepo.save(user);
        }

        // issue tokens
        String access = jwtUtil.generateAccessToken(user.getUsername(), List.of("ROLE_USER"));
        String plainRefresh = generateRefreshPlain();
        long days = rememberMe ? rememberMeDays : refreshDays;
        storeRefreshTokenWithExpiry(plainRefresh, user, days);

        return new TokensWithExpiry(access, plainRefresh, days);
    }

    private String buildOtpAuthUrl(String issuer, String accountName, String base32Secret) {
        // otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                urlEncode(issuer), urlEncode(accountName), base32Secret, urlEncode(issuer));
    }

    private static String urlEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private boolean verifyTotpCode(String base32Secret, String codeStr, int window) {
        try {
            byte[] secretBytes = base32.decode(base32Secret);
            Key key = new SecretKeySpec(secretBytes, "HmacSHA1");

            Instant now = Instant.now();
            Duration step = totpGenerator.getTimeStep(); // usually 30s
            long stepSeconds = step.getSeconds();

            int code = Integer.parseInt(codeStr);

            for (int i = -window; i <= window; i++) {
                Instant instant = now.plusSeconds(i * stepSeconds);
                int generated = totpGenerator.generateOneTimePassword(key, instant);
                if (generated == code)
                    return true;
            }
            return false;
        } catch (Exception ex) {
            return false;
        }
    }
}
