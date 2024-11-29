package com.pineone.auth.api.controller.dto;

public record LoginResponse(
    String accessToken,
    String refreshToken
) { }
