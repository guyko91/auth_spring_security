package com.pineone.auth.api.service.dto;

import com.pineone.auth.security.token.TokenPairDto;
import java.time.LocalDateTime;

public record AuthTokenCreateCommand(
    long userSeq,
    String accessToken,
    LocalDateTime accessTokenExpireDateTime,
    String refreshToken,
    LocalDateTime refreshTokenExpireDateTime
) {
    public static AuthTokenCreateCommand of(long userSeq, TokenPairDto tokenPair) {
        return new AuthTokenCreateCommand(
            userSeq,
            tokenPair.accessToken().token(),
            tokenPair.accessToken().expireDateTime(),
            tokenPair.refreshToken().token(),
            tokenPair.refreshToken().expireDateTime()
        );
    }
}
