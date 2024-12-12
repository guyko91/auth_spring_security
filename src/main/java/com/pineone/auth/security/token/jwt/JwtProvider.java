package com.pineone.auth.security.token.jwt;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenClaims;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenProvidable;
import com.pineone.auth.security.token.TokenType;
import com.pineone.auth.security.token.exception.TokenValidateException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import org.springframework.stereotype.Component;

@Component
public class JwtProvider implements TokenProvidable {

    public static final String JWT_CLAIM_KEY_ID = "id";
    public static final String JWT_CLAIM_KEY_NAME = "name";

    @Override
    public TokenDto createToken(UserPrincipal userPrincipal, TokenType tokenType, Date expiryDate) {
        PrivateKey key = getPrivateKey();

        String subject = Long.toString(userPrincipal.getSeq());

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

    @Override
    public TokenClaims validateToken(String tokenString) throws TokenValidateException {
        try {
           Claims jwtClaims = parseTokenString(tokenString);
            return TokenClaims.of(jwtClaims);
        }catch (JwtException e) {
            throw new TokenValidateException();
        }
    }

    private PrivateKey getPrivateKey() {
        PrivateKey key;
        try {
            key = RSAKeyUtil.getPrivateKey();
        }catch (Exception e) {
            throw new BusinessException(
                ErrorCode.INTERNAL_SERVER_ERROR,
                String.format("RSA Key Error (%s)", e.getMessage())
            );
        }
        return key;
    }

    private PublicKey getPublicKey() {
        PublicKey key;
        try {
            key = RSAKeyUtil.getPublicKey();
        }catch (Exception e) {
            throw new BusinessException(
                ErrorCode.INTERNAL_SERVER_ERROR,
                String.format("RSA Key Error (%s)", e.getMessage())
            );
        }
        return key;
    }

    private Claims parseTokenString(String tokenString) {
        PublicKey publicKey = getPublicKey();
        return Jwts.parserBuilder()
            .setSigningKey(publicKey)
            .build()
            .parseClaimsJws(tokenString)
            .getBody();
    }

}
