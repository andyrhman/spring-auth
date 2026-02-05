package com.myspring.spring_auth.controller;

import com.myspring.spring_auth.entity.User;
import com.myspring.spring_auth.repository.UserRepository;
import com.myspring.spring_auth.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import com.myspring.spring_auth.dto.RegisterRequest;
import com.myspring.spring_auth.dto.TwoFactorRequest;
import com.myspring.spring_auth.dto.LoginRequest;

import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import java.util.Locale;
import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepo;

    @Value("${app.cookie.refresh-name:refreshToken}")
    private String cookieName;

    @Value("${app.jwt.refresh-token-expiration-days:30}")
    private long refreshDays;

    public AuthController(AuthService authService, UserRepository userRepo) {
        this.authService = authService;
        this.userRepo = userRepo;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequest req) {
        String username = req.username().trim();
        String email = req.email().trim().toLowerCase(Locale.ROOT);

        if (!req.password().equals(req.passwordConfirm())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", "Passwords do not match"));
        }

        if (userRepo.existsByUsername(username)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", "Username already exists"));
        }

        if (userRepo.findByEmail(email).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", "Email already exists"));
        }

        User u;
        try {
            u = authService.register(username, email, req.firstName(), req.lastName(), req.password());
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Could not create user"));
        }

        Map<String, Object> resp = new java.util.HashMap<>();
        resp.put("id", u.getId());
        resp.put("username", u.getUsername());
        resp.put("email", u.getEmail());
        if (u.getFirstName() != null)
            resp.put("first_name", u.getFirstName());
        if (u.getLastName() != null)
            resp.put("last_name", u.getLastName());
        resp.put("createdAt", u.getCreatedAt());

        return ResponseEntity.status(HttpStatus.CREATED).body(resp);
    }

    // Login: returns either 2FA info or immediate tokens depending on user's TFA
    // state
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Validated LoginRequest req) {
        try {
            var res = authService.beginLogin(req.usernameOrEmail(), req.password(), req.rememberMe());
            // res is a Map-like record; it can contain:
            // - { id, rememberMe } -> 2FA required
            // - { id, rememberMe, secret, otpauth_url } -> enrollment instructions
            return ResponseEntity.ok(res);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
        }
    }

    // Two-factor endpoint: verifies code, issues tokens and sets refresh cookie
    @PostMapping("/two-factor")
    public ResponseEntity<?> twoFactor(@RequestBody @Validated TwoFactorRequest req, HttpServletResponse response) {
        try {
            var tokensWithExpiry = authService.completeTwoFactor(req.id(), req.code(), req.secret(), req.rememberMe());

            // create cookie with refresh token expiry in days
            ResponseCookie cookie = ResponseCookie.from(cookieName, tokensWithExpiry.refreshToken())
                    .httpOnly(true)
                    .secure(true)
                    .path("/api/auth")
                    .maxAge(Duration.ofDays(tokensWithExpiry.refreshDays()))
                    .sameSite("Strict")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

            return ResponseEntity.ok(Map.of("accessToken", tokensWithExpiry.accessToken()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
        }
    }

    // Optional: endpoint to return otpauth URI only (if you want server to build QR
    // image)
    // @GetMapping("/qr/{userId}")
    // public ResponseEntity<?> qr(@PathVariable String userId) {
    // Optional<User> u = userRepo.findById(UUID.fromString(userId));
    // if (u.isEmpty())
    // return ResponseEntity.notFound().build();
    // String otpAuthUrl = authService.buildOtpAuthUrl(u.get());
    // return ResponseEntity.ok(Map.of("otpauth_url", otpAuthUrl));
    // }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        String plain = extractRefreshFromCookie(request);
        if (plain == null)
            return ResponseEntity.status(401).body(Map.of("error", "no refresh cookie"));

        try {
            var tokens = authService.refresh(plain);
            ResponseCookie cookie = ResponseCookie.from(cookieName, tokens.refreshToken())
                    .httpOnly(true)
                    .secure(true)
                    .path("/api/auth")
                    .maxAge(Duration.ofDays(refreshDays))
                    .sameSite("Strict")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
            return ResponseEntity.ok(Map.of("accessToken", tokens.accessToken()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String plain = extractRefreshFromCookie(request);
        if (plain != null)
            authService.revokeByPlain(plain);

        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .path("/api/auth")
                .httpOnly(true)
                .secure(true)
                .maxAge(0)
                .sameSite("Strict")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(Map.of("message", "logged out"));
    }

    // NEW: return authenticated user data (without password)
    @GetMapping("/user")
    public ResponseEntity<?> currentUser(Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "unauthenticated"));
        }
        return userRepo.findByUsername(authentication.getName())
                .map(u -> ResponseEntity.ok(Map.of(
                        "id", u.getId(),
                        "username", u.getUsername(),
                        "email", u.getEmail(),
                        "firstName", u.getFirstName(),
                        "lastName", u.getLastName(),
                        "createdAt", u.getCreatedAt())))
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error", "user not found")));
    }

    private String extractRefreshFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null)
            return null;
        for (Cookie c : request.getCookies()) {
            if (cookieName.equals(c.getName()))
                return c.getValue();
        }
        return null;
    }
}
