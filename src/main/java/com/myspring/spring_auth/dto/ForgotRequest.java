package com.myspring.spring_auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotRequest(
        @JsonProperty("email") @Email @NotBlank String email) {
}
