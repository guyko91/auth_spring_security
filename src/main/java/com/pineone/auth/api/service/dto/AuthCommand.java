package com.pineone.auth.api.service.dto;

import com.pineone.auth.security.token.TokenPairDto;
import java.time.LocalDateTime;

public record AuthCommand(
    long userSeq,
    String tokenKey,
    String accessToken,
    LocalDateTime accessTokenExpireDateTime,
    String refreshToken,
    LocalDateTime refreshTokenExpireDateTime
) {
    public static AuthCommand of(long userSeq, TokenPairDto tokenPair) {
        return new AuthCommand(
            userSeq,
            tokenPair.tokenKey(),
            tokenPair.accessToken().token(),
            tokenPair.accessToken().expireDateTime(),
            tokenPair.refreshToken().token(),
            tokenPair.refreshToken().expireDateTime()
        );
    }
}
