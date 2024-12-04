package com.pineone.auth.security.token.jwt;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.RSAKeyUtil;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import java.security.PrivateKey;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.TimeZone;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final AuthProperties authProperties;

    public TokenPairDto createTokenPair(UserPrincipal userPrincipal) {
        TokenDto accessToken = createToken(userPrincipal, TokenType.ACCESS_TOKEN);
        TokenDto refreshToken = createToken(userPrincipal, TokenType.REFRESH_TOKEN);
        return new TokenPairDto(accessToken, refreshToken);
    }

    public TokenDto createNewAccessToken(UserPrincipal userPrincipal) {
        return createToken(userPrincipal, TokenType.ACCESS_TOKEN);
    }

    public long validateAccessToken(String tokenString) {
        Claims claims = validateTokenString(tokenString);
        boolean isExpired = claims.getExpiration().before(new Date());
        if (!isExpired) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED_ACCESS_TOKEN_BEFORE_EXPIRED);
        }
        return Long.parseLong(claims.getSubject());
    }

    public long validateRefreshToken(String tokenString) {
        Claims claims = validateTokenString(tokenString);
        boolean isExpired = claims.getExpiration().before(new Date());
        if (isExpired) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_EXPIRED);
        }
        return Long.parseLong(claims.getSubject());
    }

    public UserPrincipal getUserPrincipalFrom(String accessToken) {
        long userSeq = validateAccessToken(accessToken);
        return  UserPrincipal.fromToken(userSeq);
    }

    private TokenDto createToken(UserPrincipal userPrincipal, TokenType tokenType) {
        String subject = Long.toString(userPrincipal.getSeq());
        Date expiryDate = getExpiryDateBy(tokenType);

        PrivateKey key;
        try {
            key = RSAKeyUtil.getPrivateKey();
        }catch (Exception e) {
            e.printStackTrace();
            throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, "RSA Key Error");
        }

        String token = Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(new Date())
            .setExpiration(expiryDate)
            .signWith(key)
            .compact();
        LocalDateTime expireDateTime = expiryDate.toInstant()
            .atZone(TimeZone.getDefault().toZoneId())
            .toLocalDateTime();

        return new TokenDto(token, expireDateTime);
    }

    private Date getExpiryDateBy(TokenType tokenType) {
        if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return new Date(new Date().getTime() + authProperties.getAuth().getAccessTokenExpMilli());
        }
        return new Date(new Date().getTime() + authProperties.getAuth().getRefreshTokenExpMilli());
    }

    private Claims validateTokenString(String tokenString) {
        try {
            PrivateKey key = RSAKeyUtil.getPrivateKey();
            return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(tokenString)
                .getBody();
        } catch (SignatureException e) {
            // 서명이 유효하지 않으면
            throw new BusinessException(ErrorCode.UNAUTHORIZED_TOKEN_SIGNATURE);
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED_TOKEN_ERROR);
        }
    }

}
