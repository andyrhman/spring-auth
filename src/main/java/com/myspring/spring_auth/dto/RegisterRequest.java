package com.myspring.spring_auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(
        @JsonProperty("username") @NotBlank String username,
        @JsonProperty("email") @Email @NotBlank String email,
        @JsonProperty("first_name") String firstName,
        @JsonProperty("last_name") String lastName,
        @JsonProperty("password") @NotBlank String password,
        @JsonProperty("password_confirm") @NotBlank String passwordConfirm) {
}
