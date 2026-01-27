package com.myspring.spring_auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetRequest(
        @JsonProperty("token") @NotBlank String token,
        @JsonProperty("password") @NotBlank @Size(min = 6) String password,
        @JsonProperty("password_confirm") @NotBlank @Size(min = 6) String passwordConfirm) {
}
