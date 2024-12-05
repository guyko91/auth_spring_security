package com.pineone.auth.security.token.jwt;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.service.ServletAuthHandler;
import com.pineone.auth.security.CustomAuthenticationException;
import com.pineone.auth.security.SecurityProvider;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * 필터는 빈으로 설정 시 서블릿에도 중복 등록되어 동작하므로, 필터를 빈으로 등록하지 않는다.
     */
    private final ServletAuthHandler servletAuthHandler;
    private final TokenProvider tokenProvider;
    private final SecurityProvider securityProvider;
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
        FilterChain filterChain) throws AuthenticationException {

        try {
            authenticateRequest(request);
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            throw new CustomAuthenticationException(ErrorCode.UNAUTHORIZED_TOKEN_EXPIRED, "JWT 토큰이 만료되었습니다.");
        } catch (JwtException e) {
            throw new CustomAuthenticationException(ErrorCode.UNAUTHORIZED_TOKEN_ERROR, "유효하지 않은 JWT 토큰입니다.");
        } catch (AuthenticationException e) {
            throw new CustomAuthenticationException(ErrorCode.UNAUTHORIZED, "인증에 실패했습니다.");
        } catch (Exception e) {
            log.error("Unexpected error during JWT authentication", e);
            throw new CustomAuthenticationException(ErrorCode.INTERNAL_SERVER_ERROR, "인증 처리 중 예상치 못한 오류가 발생했습니다.");
        }
    }

    private void authenticateRequest(HttpServletRequest request) {
        String accessToken = servletAuthHandler.getAccessTokenStringFrom(request)
            .orElseThrow(() -> new CustomAuthenticationException(ErrorCode.UNAUTHORIZED, "인증 토큰이 없습니다."));

        UserPrincipal userPrincipal = tokenProvider.validateAndGetUserPrincipalFrom(accessToken);

        securityProvider.authenticateTokenUserPrincipal(userPrincipal);
    }

}
