package com.myspring.spring_auth.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class JwtUtil {

    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final long accessTokenSeconds;

    public JwtUtil(@Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.access-token-expiration-minutes:10}") long accessMinutes) {
        if (secret == null || secret.isBlank() || secret.startsWith("replace")) {
            throw new IllegalStateException("JWT secret is not configured. Set APP_JWT_SECRET environment variable.");
        }
        this.algorithm = Algorithm.HMAC256(secret);
        this.verifier = JWT.require(algorithm).build();
        this.accessTokenSeconds = accessMinutes * 60;
    }

    public String generateAccessToken(String username, List<String> roles) {
        Instant now = Instant.now();
        return JWT.create()
                .withSubject(username)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(accessTokenSeconds)))
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("roles", roles)
                .sign(algorithm);
    }

    public DecodedJWT validateAndDecode(String token) {
        return verifier.verify(token);
    }
}
