package com.pineone.auth.security.token;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenProvider {

    private final JwtProvider jwtProvider;

    private static final int ACCESS_TOKEN_EX_BUFFER_SEC = 30;

    public TokenPairDto createTokenPair(UserPrincipal userPrincipal) {
        TokenDto accessToken = jwtProvider.createToken(userPrincipal, TokenType.ACCESS_TOKEN);
        TokenDto refreshToken = jwtProvider.createToken(userPrincipal, TokenType.REFRESH_TOKEN);
        return new TokenPairDto(accessToken, refreshToken);
    }

    public TokenDto createNewAccessToken(UserPrincipal userPrincipal) {
        return jwtProvider.createToken(userPrincipal, TokenType.ACCESS_TOKEN);
    }

    public void validateRefreshAccessToken(String tokenString) {
        Claims claims = jwtProvider.validateToken(tokenString);

        // ACCESS_TOKEN 만료시간 (버퍼시간 포함)
        Date expiryDate = new Date(new Date().getTime() - ACCESS_TOKEN_EX_BUFFER_SEC * 1000);

        // ACCESS_TOKEN 만료 전 토큰 갱신 요청 시
        boolean isExpired = claims.getExpiration().before(expiryDate);
        if (!isExpired) {
            // ACCESS_TOKEN 만료 전 토큰 갱신 요청 시, 예외 처리
            throw new BusinessException(ErrorCode.UNAUTHORIZED_ACCESS_TOKEN_BEFORE_EXPIRED);
        }
    }

    public void validateRefreshToken(String tokenString) {
        Claims claims = jwtProvider.validateToken(tokenString);
        boolean isExpired = claims.getExpiration().before(new Date());
        if (isExpired) {
            // 만료된 REFRESH_TOKEN으로 요청 시, 예외 처리 (재로그인 플로우)
            throw new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_EXPIRED);
        }
    }

    public UserPrincipal validateAndGetUserPrincipalFrom(String accessToken) {
        Claims claims = jwtProvider.validateToken(accessToken);

        long seq = Long.parseLong(claims.getSubject());
        String id = claims.get(JwtProvider.JWT_CLAIM_KEY_ID, String.class);
        String name = claims.get(JwtProvider.JWT_CLAIM_KEY_NAME, String.class);

        return UserPrincipal.of(seq, id, name);
    }

}
