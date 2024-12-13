package com.pineone.auth.api.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenLogoutRequest(
    @NotBlank
    String refreshToken
) { }
