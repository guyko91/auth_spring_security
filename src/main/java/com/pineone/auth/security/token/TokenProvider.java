package com.pineone.auth.security.token;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.config.AuthProperties;
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
    private final AuthProperties authProperties;

    private static final int ACCESS_TOKEN_EX_BUFFER_SEC = 30;

    public TokenPairDto createTokenPair(UserPrincipal userPrincipal) {
        TokenDto accessToken = createNewAccessToken(userPrincipal);
        TokenDto refreshToken = createNewRefreshToken(userPrincipal);
        return new TokenPairDto(accessToken, refreshToken);
    }

    public TokenDto createNewAccessToken(UserPrincipal userPrincipal) {
        Date expiryDate = getExpiryDateBy(TokenType.ACCESS_TOKEN);
        return jwtProvider.createToken(userPrincipal, TokenType.ACCESS_TOKEN, expiryDate);
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

    public UserPrincipal validateAndGetUserPrincipalFrom(String tokenString) {
        Claims claims = jwtProvider.validateToken(tokenString);

        long seq = Long.parseLong(claims.getSubject());
        String id = claims.get(JwtProvider.JWT_CLAIM_KEY_ID, String.class);
        String name = claims.get(JwtProvider.JWT_CLAIM_KEY_NAME, String.class);

        return UserPrincipal.of(seq, id, name);
    }

    private TokenDto createNewRefreshToken(UserPrincipal userPrincipal) {
        Date expiryDate = getExpiryDateBy(TokenType.REFRESH_TOKEN);
        return jwtProvider.createToken(userPrincipal, TokenType.REFRESH_TOKEN, expiryDate);
    }

    private Date getExpiryDateBy(TokenType tokenType) {
        if (TokenType.TEMPORARY.equals(tokenType)) {
            return getExpiryDateFromNowWithMilli(authProperties.getAuth().getTemporaryTokenExpMilli());
        } else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return getExpiryDateFromNowWithMilli(authProperties.getAuth().getAccessTokenExpMilli());
        }
        return getExpiryDateFromNowWithMilli(authProperties.getAuth().getRefreshTokenExpMilli());
    }

    private Date getExpiryDateFromNowWithMilli(long milli) {
        return new Date(new Date().getTime() + milli);
    }

}
