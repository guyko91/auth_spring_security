package com.pineone.auth.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

    public void processOAuthTokenResponse(HttpServletResponse response, TokenPairDto tokenPair)
        throws IOException {
        setRedirectResponse(response, tokenPair.tokenKey());
    }

    public void writeErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(errorCode.getHttpStatus().value());

        String responseBody = objectMapper.writeValueAsString(ApiResult.response(errorCode));
        response.getWriter().write(responseBody);
    }

    public Optional<String> getAccessTokenStringFrom(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER_KEY);
        if (StringUtils.hasText(authHeader) && authHeader.startsWith(TOKEN_PREFIX)) {
            return Optional.of(parseAuthorizationToken(authHeader));
        }
        return Optional.empty();
    }

    private String parseAuthorizationToken(String authorizationHeader) {
        return authorizationHeader.substring(TOKEN_PREFIX.length()).trim();
    }

    private void setRedirectResponse(HttpServletResponse response, String tokenKey) throws IOException {
        String successRedirectUri = authProperties.getOauth2().getLoginSuccessRedirectUri();
        String tokenKeyQueryParamName = authProperties.getOauth2().getLoginSuccessTokenQueryParam();

        response.sendRedirect(
            UriComponentsBuilder
                .fromUriString(successRedirectUri)
                .queryParam(tokenKeyQueryParamName, tokenKey)
                .build().toUriString()
        );
    }

}
