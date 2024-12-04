package com.pineone.auth.security.token.jwt;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.security.CustomAuthenticationException;
import com.pineone.auth.api.controller.utils.HeaderUtil;
import com.pineone.auth.security.UserPrincipal;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_KEY = "exception";

    private final JwtTokenProvider jwtProvider;
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
        String accessToken = extractAccessToken(request);
        Authentication authentication = createAuthentication(accessToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("SecurityContext에 '{}' 인증 정보를 저장했습니다. uri: {}",
            authentication.getName(), request.getRequestURI());
    }

    private String extractAccessToken(HttpServletRequest request) {
        String accessToken = HeaderUtil.getAccessToken(request);

        if (!StringUtils.hasText(accessToken)) {
            throw new CustomAuthenticationException(ErrorCode.UNAUTHORIZED, "인증 토큰이 없습니다.");
        }

        return accessToken;
    }

    private Authentication createAuthentication(String accessToken) {
        UserPrincipal userPrincipal = jwtProvider.getUserPrincipalFrom(accessToken);

        return new UsernamePasswordAuthenticationToken(
            userPrincipal,
            null,
            userPrincipal.getAuthorities()
        );
    }

}
