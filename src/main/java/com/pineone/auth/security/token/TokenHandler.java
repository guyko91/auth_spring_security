package com.pineone.auth.security.token;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.exception.TokenValidateException;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenHandler {

    private final TokenProvidable tokenProvider;
    private final AuthProperties authProperties;

    private static final int ACCESS_TOKEN_EX_BUFFER_SEC = 30;

    public TokenPairDto createTokenPair(UserPrincipal userPrincipal) {
        TokenDto accessToken = createNewAccessToken(userPrincipal);
        TokenDto refreshToken = createNewRefreshToken(userPrincipal);
        return new TokenPairDto(accessToken, refreshToken);
    }

    public void validateTokenRefreshRequest(String accessToken, String refreshToken) throws TokenValidateException {
        TokenClaims accessTokenClaims = tokenProvider.validateToken(accessToken);
        TokenClaims refreshTokenClaims = tokenProvider.validateToken(refreshToken);

        checkTokenSubjectEquals(accessTokenClaims, refreshTokenClaims);
        validateRefreshReqAccessToken(accessTokenClaims);
        validateRefreshReqRefreshToken(refreshTokenClaims);
    }

    public UserPrincipal validateAndGetUserPrincipalFrom(String accessToken) throws TokenValidateException {
        TokenClaims claims = tokenProvider.validateToken(accessToken);
        return claims.toUserPrincipal();
    }

    private TokenDto createNewAccessToken(UserPrincipal userPrincipal) {
        Date expiryDate = getExpiryDateBy(TokenType.ACCESS_TOKEN);
        return tokenProvider.createToken(userPrincipal, TokenType.ACCESS_TOKEN, expiryDate);
    }

    private TokenDto createNewRefreshToken(UserPrincipal userPrincipal) {
        Date expiryDate = getExpiryDateBy(TokenType.REFRESH_TOKEN);
        return tokenProvider.createToken(userPrincipal, TokenType.REFRESH_TOKEN, expiryDate);
    }

    private void checkTokenSubjectEquals(TokenClaims accessTokenClaims, TokenClaims refreshTokenClaims) {
        long accessTokenSubject = accessTokenClaims.getTokenSubject();
        long refreshTokenSubject = refreshTokenClaims.getTokenSubject();

        if (accessTokenSubject != refreshTokenSubject) { throw new BusinessException(ErrorCode.UNAUTHORIZED_TOKEN_ERROR, "토큰 subject 불일치"); }
    }

    private void validateRefreshReqAccessToken(TokenClaims accessTokenClaims) {
        Date expiryDate = getExpiryDateBy(TokenType.ACCESS_TOKEN);
        boolean isExpired = accessTokenClaims.isTokenExpired(expiryDate);
        if (!isExpired) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED_ACCESS_TOKEN_BEFORE_EXPIRED);
        }
    }

    private void validateRefreshReqRefreshToken(TokenClaims refreshTokenClaims) {
        Date expiryDate = getExpiryDateBy(TokenType.REFRESH_TOKEN);
        boolean isExpired = refreshTokenClaims.isTokenExpired(expiryDate);
        if (isExpired) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_EXPIRED);
        }
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
