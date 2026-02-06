package com.myspring.spring_auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @JsonProperty("username") @NotBlank String usernameOrEmail,
        @JsonProperty("password") @NotBlank String password,
        @JsonProperty("rememberMe") Boolean rememberMe
) {
    public LoginRequest {
        if (rememberMe == null) {
            rememberMe = false;
        }
    }
}
