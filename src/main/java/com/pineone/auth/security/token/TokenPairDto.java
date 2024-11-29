package com.pineone.auth.security.token;

public record TokenPairDto(
    TokenDto accessToken,
    TokenDto refreshToken
) { }
