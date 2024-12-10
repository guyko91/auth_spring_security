package com.pineone.auth.security;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.service.ServletAuthHandler;
import com.pineone.auth.security.token.TokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    public static final String TOKEN_EXCEPTION_ATTRIBUTE_KEY = "TOKEN_EXCEPTION";

    private final ServletAuthHandler servletAuthHandler;
    private final SecurityProvider securityProvider;
    private final TokenProvider tokenProvider;
    private final String[] AUTH_WHITELIST;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String requestPath = request.getRequestURI();
        for (String pattern : AUTH_WHITELIST) {
            if (pathMatcher.match(pattern, requestPath)) {
                return true;
            }
        }
        return PathRequest.toStaticResources().atCommonLocations().matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        try {
            authenticateRequest(request);
        } catch (ExpiredJwtException e) {
            setTokenExceptionAttribute(request, ErrorCode.UNAUTHORIZED_TOKEN_EXPIRED);
        } catch (JwtException e) {
            setTokenExceptionAttribute(request, ErrorCode.UNAUTHORIZED_TOKEN_ERROR);
        } catch (AuthenticationException e) {
            setTokenExceptionAttribute(request, ErrorCode.UNAUTHORIZED);
        } catch (Exception e) {
            setTokenExceptionAttribute(request, ErrorCode.INTERNAL_SERVER_ERROR);
        } finally {
            filterChain.doFilter(request, response);
        }

    }

    private void authenticateRequest(HttpServletRequest request) {
        String accessToken = servletAuthHandler.getAccessTokenStringFrom(request)
            .orElseThrow(() -> new CustomAuthenticationException(ErrorCode.UNAUTHORIZED, "인증 토큰이 없습니다."));

        UserPrincipal userPrincipal = tokenProvider.validateAndGetUserPrincipalFrom(accessToken);

        securityProvider.authenticateTokenUserPrincipal(userPrincipal);
    }

    private void setTokenExceptionAttribute(HttpServletRequest request, ErrorCode errorCode) {
        request.setAttribute(TOKEN_EXCEPTION_ATTRIBUTE_KEY, errorCode);
    }
}