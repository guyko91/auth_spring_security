package com.pineone.auth.security.oauth;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.service.UserOtpService;
import com.pineone.auth.api.service.UserTokenService;
import com.pineone.auth.api.service.dto.AuthTokenCreateCommand;
import com.pineone.auth.api.service.dto.OtpRequiredResult;
import com.pineone.auth.security.ServletAuthHandler;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenHandler;
import com.pineone.auth.security.token.TokenPairDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    private final TokenHandler tokenHandler;
    private final ServletAuthHandler servletAuthHandler;
    private final UserTokenService userTokenService;
    private final UserOtpService userOtpService;

    /**
     * OAuth 인증 성공 핸들러
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        TokenPairDto tokenPairDto = tokenHandler.createTokenPair(userPrincipal);

        AuthTokenCreateCommand authTokenCreateCommand = AuthTokenCreateCommand.of(userPrincipal.getSeq(), tokenPairDto);
        String tokenUuid = userTokenService.saveAuthToken(authTokenCreateCommand);
        OtpRequiredResult otpResult = userOtpService.checkUserOtpVerifyRequired(userPrincipal.getSeq());

        servletAuthHandler.processOAuthTokenResponse(response, tokenUuid, otpResult);
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
        ErrorCode errorCode = ErrorCode.INTERNAL_SERVER_ERROR;
        servletAuthHandler.writeErrorResponse(response, errorCode);
    }

}
