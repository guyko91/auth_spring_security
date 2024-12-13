package com.pineone.auth.api.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenRefreshRequest(
    @NotBlank
    String refreshToken
) { }
