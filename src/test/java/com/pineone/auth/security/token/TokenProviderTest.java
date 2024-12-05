package com.pineone.auth.security.token;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import java.time.LocalDateTime;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TokenProviderTest {

    @InjectMocks
    private TokenProvider tokenProvider;

    @Mock
    private JwtProvider jwtTokenProvider;

    private UserPrincipal userPrincipal;

    @BeforeEach
    void setUp() {
        userPrincipal = UserPrincipal.of(1L, "testUser", "Test User");
    }

    @Test
    void testCreateTokenPair() {
        TokenDto accessToken = new TokenDto(TokenType.ACCESS_TOKEN, "accessToken", LocalDateTime.now().plusMinutes(15));
        TokenDto refreshToken = new TokenDto(TokenType.REFRESH_TOKEN, "refreshToken", LocalDateTime.now().plusDays(7));

        when(jwtTokenProvider.createToken(userPrincipal, TokenType.ACCESS_TOKEN)).thenReturn(accessToken);
        when(jwtTokenProvider.createToken(userPrincipal, TokenType.REFRESH_TOKEN)).thenReturn(refreshToken);

        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);

        assertNotNull(tokenPair);
        assertEquals("accessToken", tokenPair.accessToken().token());
        assertEquals("refreshToken", tokenPair.accessToken().token());
    }

    @Test
    void testCreateNewAccessToken() {
        TokenDto accessToken = new TokenDto(TokenType.ACCESS_TOKEN, "accessToken", LocalDateTime.now().plusMinutes(15));
        when(jwtTokenProvider.createToken(userPrincipal, TokenType.ACCESS_TOKEN)).thenReturn(accessToken);

        TokenDto newAccessToken = tokenProvider.createNewAccessToken(userPrincipal);

        assertNotNull(newAccessToken);
        assertEquals("accessToken", newAccessToken.token());
    }

    @Test
    void testValidateRefreshAccessToken() {
        Claims claims = mock(Claims.class);
        when(claims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() - 1000));
        when(jwtTokenProvider.validateToken(anyString())).thenReturn(claims);

        tokenProvider.validateRefreshAccessToken("tokenString");

        verify(jwtTokenProvider).validateToken("tokenString");
    }

    @Test
    void testValidateRefreshToken() {
        Claims claims = mock(Claims.class);
        when(claims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(jwtTokenProvider.validateToken(anyString())).thenReturn(claims);

        tokenProvider.validateRefreshToken("tokenString");

        verify(jwtTokenProvider).validateToken("tokenString");
    }

    @Test
    void testValidateAndGetUserPrincipalFrom() {
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("1");
        when(claims.get(JwtProvider.JWT_CLAIM_KEY_ID, String.class)).thenReturn("testUser");
        when(claims.get(JwtProvider.JWT_CLAIM_KEY_NAME, String.class)).thenReturn("Test User");

        when(jwtTokenProvider.validateToken(anyString())).thenReturn(claims);

        UserPrincipal userPrincipal = tokenProvider.validateAndGetUserPrincipalFrom("accessToken");

        assertNotNull(userPrincipal);
        assertEquals(1L, userPrincipal.getSeq());
        assertEquals("testUser", userPrincipal.getId());
        assertEquals("Test User", userPrincipal.getName());
    }
}