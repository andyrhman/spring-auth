package com.myspring.spring_auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record TwoFactorRequest(
    @JsonProperty("id") @NotBlank String id,          
    @JsonProperty("code") @NotBlank String code,      
    @JsonProperty("secret") String secret,            
    @JsonProperty("rememberMe") boolean rememberMe
) {}
