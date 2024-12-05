package com.pineone.auth.security.token.jwt;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.RSAKeyUtil;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final AuthProperties authProperties;

    public static final String JWT_CLAIM_KEY_ID = "id";
    public static final String JWT_CLAIM_KEY_NAME = "name";

    public TokenDto createToken(UserPrincipal userPrincipal, TokenType tokenType) {
        PrivateKey key = getPrivateKey();

        String subject = Long.toString(userPrincipal.getSeq());
        Date expiryDate = getExpiryDateBy(tokenType);

        Map<String, Object> customClaims = Map.of(
            JWT_CLAIM_KEY_ID, userPrincipal.getId(),
            JWT_CLAIM_KEY_NAME, userPrincipal.getName()
        );

        String token = Jwts.builder()
            .setSubject(subject)
            .addClaims(customClaims)
            .setIssuedAt(new Date())
            .setExpiration(expiryDate)
            .signWith(key)
            .compact();

        LocalDateTime expireDateTime = expiryDate.toInstant()
            .atZone(TimeZone.getDefault().toZoneId())
            .toLocalDateTime();

        return new TokenDto(tokenType, token, expireDateTime);
    }

    public Claims validateToken(String tokenString) throws JwtException {
        PublicKey publicKey = getPublicKey();

        return Jwts.parserBuilder()
            .setSigningKey(publicKey)
            .build()
            .parseClaimsJws(tokenString)
            .getBody();
    }

    private Date getExpiryDateBy(TokenType tokenType) {
        if (TokenType.TEMPORARY.equals(tokenType)) {
            return getExpiryDateFromNowWithMilli(authProperties.getAuth().getTemporaryTokenExpMilli());
        } else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return getExpiryDateFromNowWithMilli(authProperties.getAuth().getAccessTokenExpMilli());
        }
        return getExpiryDateFromNowWithMilli(authProperties.getAuth().getRefreshTokenExpMilli());
    }

    private PrivateKey getPrivateKey() {
        PrivateKey key;
        try {
            key = RSAKeyUtil.getPrivateKey();
        }catch (Exception e) {
            e.printStackTrace();
            throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, "RSA Key Error");
        }
        return key;
    }

    private PublicKey getPublicKey() {
        PublicKey key;
        try {
            key = RSAKeyUtil.getPublicKey();
        }catch (Exception e) {
            e.printStackTrace();
            throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, "RSA Key Error");
        }
        return key;
    }

    private Date getExpiryDateFromNowWithMilli(long milli) {
        return new Date(new Date().getTime() + milli);
    }

}
