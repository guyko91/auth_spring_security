package com.pineone.auth.security.token.jwt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.RSAKeyUtil;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    @InjectMocks
    private JwtProvider jwtTokenProvider;

    @Mock
    private AuthProperties authProperties;

    @Mock
    private RSAKeyUtil rsaKeyUtil;

    private UserPrincipal userPrincipal;

    @BeforeEach
    void setUp() {
        userPrincipal = UserPrincipal.of(1L, "testUser", "Test User");

        AuthProperties.Auth auth = new AuthProperties.Auth();
        auth.setAccessTokenExpMilli(900000L); // 15 minutes
        auth.setRefreshTokenExpMilli(604800000L); // 7 days
        auth.setTemporaryTokenExpMilli(300000L); // 5 minutes

        when(authProperties.getAuth()).thenReturn(auth);
    }

    @Test
    void testCreateToken() throws Exception {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        PrivateKey privateKey = keyPair.getPrivate();

        when(rsaKeyUtil.getPrivateKey()).thenReturn(privateKey);

        TokenDto tokenDto = jwtTokenProvider.createToken(userPrincipal, TokenType.ACCESS_TOKEN);

        assertNotNull(tokenDto);
        assertEquals(TokenType.ACCESS_TOKEN, tokenDto.token());
        assertNotNull(tokenDto.token());
        assertNotNull(tokenDto.expireDateTime());
    }

    @Test
    void testValidateToken() throws Exception {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        PublicKey publicKey = keyPair.getPublic();

        when(rsaKeyUtil.getPublicKey()).thenReturn(publicKey);

        String token = Jwts.builder()
            .setSubject("1")
            .claim(JwtProvider.JWT_CLAIM_KEY_ID, "testUser")
            .claim(JwtProvider.JWT_CLAIM_KEY_NAME, "Test User")
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 900000L)) // 15 minutes
            .signWith(publicKey)
            .compact();

        Claims claims = jwtTokenProvider.validateToken(token);

        assertNotNull(claims);
        assertEquals("1", claims.getSubject());
        assertEquals("testUser", claims.get(JwtProvider.JWT_CLAIM_KEY_ID, String.class));
        assertEquals("Test User", claims.get(JwtProvider.JWT_CLAIM_KEY_NAME, String.class));
    }
}