package com.pineone.auth.api.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;

public record TwoFactorAuthViewRequest(
    @NotBlank
    String tokenKey,

    @NotBlank
    String method,

    @NotBlank
    String target,

    int limitCount,

    @NotNull
    LocalDateTime createdAt,

    @NotNull
    LocalDateTime expireAt
) { }
