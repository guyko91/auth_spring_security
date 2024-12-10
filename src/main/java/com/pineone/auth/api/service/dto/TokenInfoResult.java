package com.pineone.auth.api.service.dto;

public record TokenInfoResult(
    String accessToken,
    String refreshToken
) { }
