package com.pineone.auth.security.token;

public record TokenPairDto(
    String tokenKey,
    TokenDto accessToken,
    TokenDto refreshToken
) { }
