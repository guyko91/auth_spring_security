package com.pineone.auth.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
public class ServletAuthHandler {

    private final AuthProperties authProperties;
    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper;

    private final String AUTHORIZATION_HEADER_KEY = "Authorization";
    private final String TOKEN_PREFIX = "Bearer ";
    private final String AUTH_REFRESH_TOKEN_COOKIE_KEY = "refreshToken";

    public void processTokenResponse(HttpServletRequest request, HttpServletResponse response, TokenPairDto tokenPair) {
        String accessToken = tokenPair.accessToken().token();
        String refreshToken = tokenPair.refreshToken().token();
        setAccessTokenResponse(response, accessToken);
        processRefreshTokenResponse(request, response, refreshToken);
    }

    public void processTokenRedirectResponse(HttpServletRequest request, HttpServletResponse response, TokenPairDto tokenPair)
        throws IOException {
        setAccessTokenResponse(response, tokenPair.accessToken().token());
        processRefreshTokenResponse(request, response, tokenPair.refreshToken().token());
        setRedirectResponse(response);
    }

    public void writeErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(errorCode.getHttpStatus().value());

        String responseBody = objectMapper.writeValueAsString(ApiResult.response(errorCode));
        response.getWriter().write(responseBody);
    }

    public String validateTokenRefreshRequest(HttpServletRequest servletRequest) {
        String accessToken = getAccessTokenStringFrom(servletRequest)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED, "AccessToken 이 존재 하지 않습니다."));
        String refreshToken = getRefreshTokenStringFrom(servletRequest)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED, "RefreshToken 이 존재 하지 않습니다."));

        tokenProvider.validateRefreshAccessToken(accessToken);
        tokenProvider.validateRefreshToken(refreshToken);

        return refreshToken;
    }

    public void processTokenRefreshResponse(HttpServletResponse response, TokenDto newAccessToken) {
        setAccessTokenResponse(response, newAccessToken.token());
    }

    public void validateLogoutRequest(HttpServletRequest request) {

        String refreshTokenString = getRefreshTokenStringFrom(request)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED, "RefreshToken 이 존재 하지 않습니다."));

        tokenProvider.validateRefreshToken(refreshTokenString);
    }

    public void processLogout(HttpServletRequest request, HttpServletResponse response) {
        getRefreshTokenStringFrom(request)
            .ifPresent(refreshToken -> deleteCookie(request, response));
    }

    public Optional<String> getAccessTokenStringFrom(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER_KEY);
        if (StringUtils.hasText(authHeader) && authHeader.startsWith(TOKEN_PREFIX)) {
            return Optional.of(parseAuthorizationToken(authHeader));
        }
        return Optional.empty();
    }

    private void setAccessTokenResponse(HttpServletResponse response, String accessTokenString) {
        response.setHeader(AUTHORIZATION_HEADER_KEY, TOKEN_PREFIX + accessTokenString);
    }

    private void processRefreshTokenResponse(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        deleteCookie(request, response);
        addCookie(response, refreshToken);
    }

    private Optional<String> getRefreshTokenStringFrom(HttpServletRequest request) {
        return getCookie(request).map(Cookie::getValue);
    }

    private String parseAuthorizationToken(String authorizationHeader) {
        return authorizationHeader.substring(TOKEN_PREFIX.length()).trim();
    }

    private void setRedirectResponse(HttpServletResponse response) throws IOException {
        String redirectUri = UriComponentsBuilder.fromUriString(authProperties.getOauth2().getLoginSuccessRedirectUri())
            .build().toUriString();

        response.sendRedirect(redirectUri);
    }

    private Optional<Cookie> getCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(AUTH_REFRESH_TOKEN_COOKIE_KEY)) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    private void addCookie(HttpServletResponse response, String refreshTokenString) {
        Cookie cookie = new Cookie(AUTH_REFRESH_TOKEN_COOKIE_KEY, refreshTokenString);
        int maxAge = authProperties.getAuth().getCookieMaxSeconds();

        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);

        response.addCookie(cookie);
    }

    private void deleteCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            Arrays.stream(cookies)
                .filter(cookie -> AUTH_REFRESH_TOKEN_COOKIE_KEY.equals(cookie.getName()))
                .findFirst()
                .ifPresent(cookie -> {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                });
        }
    }

}
