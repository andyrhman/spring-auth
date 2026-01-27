package com.myspring.spring_auth.controller;

import com.myspring.spring_auth.dto.ForgotRequest;
import com.myspring.spring_auth.dto.ResetRequest;
import com.myspring.spring_auth.service.PasswordResetService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class PasswordResetController {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetController.class);

    private final PasswordResetService passwordResetService;

    public PasswordResetController(PasswordResetService passwordResetService) {
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/forgot")
    public ResponseEntity<?> forgot(@RequestBody @Valid ForgotRequest req) {
        try {
            // Request reset: this will create token if user exists and attempt to send
            // email
            passwordResetService.requestReset(req.email());
        } catch (Exception ex) {
            // log the real error for operators but don't reveal details to the client
            log.error("Error during password reset request for email {}: {}", req.email(), ex.getMessage(), ex);
            // IMPORTANT: return same generic message to user to avoid email enumeration
        }

        // Always return 200 OK with generic message (avoid leaking existence of
        // address)
        return ResponseEntity
                .ok(Map.of("message", "If an account with that email exists, a reset link has been sent."));
    }

    @PostMapping("/reset")
    public ResponseEntity<?> reset(@RequestBody @Valid ResetRequest req) {
        try {
            passwordResetService.performReset(req.token(), req.password(), req.passwordConfirm());
            return ResponseEntity.ok(Map.of("message", "Password updated successfully"));
        } catch (Exception ex) {
            // return 400 for known invalid requests
            return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
        }
    }
}
