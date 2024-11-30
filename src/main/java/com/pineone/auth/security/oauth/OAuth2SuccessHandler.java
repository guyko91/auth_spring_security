package com.pineone.auth.security.oauth;

import com.pineone.auth.api.controller.utils.CookieUtil;
import com.pineone.auth.api.service.UserTokenService;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthProperties authProperties;
    private final TokenProvider tokenProvider;
    private final UserTokenService userTokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        TokenPairDto tokenPairDto = tokenProvider.createTokenPair(userPrincipal);
        userTokenService.saveOrUpdateRefreshToken(userPrincipal, tokenPairDto);

        processCookie(response, tokenPairDto.refreshToken().token());
        processRedirectResponse(response, tokenPairDto.accessToken().token());
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

}
