package com.myspring.spring_auth.controller;

import com.myspring.spring_auth.dto.ForgotRequest;
import com.myspring.spring_auth.dto.ResetRequest;
import com.myspring.spring_auth.service.PasswordResetService;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Locale;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    public PasswordResetController(PasswordResetService passwordResetService) {
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/forgot")
    public ResponseEntity<?> forgot(@RequestBody @Valid ForgotRequest req) {

        String email = req.email().trim().toLowerCase(Locale.ROOT);
        try {

            passwordResetService.requestReset(email);
            return ResponseEntity
                    .ok(Map.of("message", "If an account with that email exists, a reset link has been sent."));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
        }

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
