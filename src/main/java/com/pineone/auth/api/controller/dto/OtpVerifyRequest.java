package com.pineone.auth.api.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record OtpVerifyRequest(
    @NotBlank
    String tokenKey,

    @NotBlank
    String code
) { }
