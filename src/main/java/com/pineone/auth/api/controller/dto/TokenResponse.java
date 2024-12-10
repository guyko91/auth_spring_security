package com.pineone.auth.api.controller.dto;

public record TokenResponse(
    String accessToken,
    String refreshToken
) { }
