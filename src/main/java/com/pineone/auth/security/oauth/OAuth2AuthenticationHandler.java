package com.pineone.auth.security.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.utils.CookieUtil;
import com.pineone.auth.api.service.UserTokenService;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.jwt.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    private final AuthProperties authProperties;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserTokenService userTokenService;
    private final ObjectMapper objectMapper;

    /**
     * OAuth 인증 성공 핸들러
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        TokenPairDto tokenPairDto = jwtTokenProvider.createTokenPair(userPrincipal);
        userTokenService.saveOrUpdateRefreshToken(userPrincipal.getSeq(), tokenPairDto);

        processCookie(response, tokenPairDto.refreshToken().token());
        processRedirectResponse(response, tokenPairDto.accessToken().token());
    }

    /**
     * OAuth 인증 실패 핸들러
     * @param request
     * @param response
     * @param exception
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException exception) throws IOException, ServletException {
        ErrorCode errorCode = ErrorCode.INTERNAL_SERVER_ERROR_EXTERNAL;
        writeErrorResponse(response, errorCode);
    }


    private void processCookie(HttpServletResponse response, String refreshToken) {
        int refreshTokenCookieMaxAgeSeconds = authProperties.getAuth().getCookieMaxSeconds();
        CookieUtil.addCookie(response, refreshToken, refreshTokenCookieMaxAgeSeconds);
    }

    private void processRedirectResponse(HttpServletResponse response, String accessToken) throws IOException {
        String redirectUri = buildRedirectUri(accessToken);
        response.sendRedirect(redirectUri);
    }

    private String buildRedirectUri(String accessToken) {
        return UriComponentsBuilder.fromUriString(authProperties.getOauth2().getLoginSuccessRedirectUri())
            .queryParam(authProperties.getOauth2().getLoginSuccessTokenQueryParam(), accessToken)
            .build().toUriString();
    }

    private void writeErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(errorCode.getHttpStatus().value());

        String responseBody = objectMapper.writeValueAsString(ApiResult.response(errorCode));
        response.getWriter().write(responseBody);
    }

}
