package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.dto.LoginRequest;
import com.pineone.auth.api.controller.dto.LoginResponse;
import com.pineone.auth.api.controller.dto.RefreshResponse;
import com.pineone.auth.api.controller.dto.SignUpRequest;
import com.pineone.auth.api.controller.dto.SignupResponse;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.controller.utils.CookieUtil;
import com.pineone.auth.api.controller.utils.HeaderUtil;
import com.pineone.auth.api.service.AuthFacade;
import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.service.dto.LoginResult;
import com.pineone.auth.api.service.dto.RefreshResult;
import com.pineone.auth.api.service.dto.SignUpResult;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthFacade authFacade;
    private final TokenProvider tokenProvider;
    private final AuthProperties authProperties;

    @PostMapping("login")
    public ResponseEntity<ApiResult<LoginResponse>> login(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        @RequestBody @Valid LoginRequest loginRequest) {

        LoginResult result = authFacade.login(loginRequest.id(), loginRequest.password());

        TokenDto accessToken = result.tokenPair().accessToken();
        TokenDto refreshToken = result.tokenPair().refreshToken();

        processCookie(servletRequest, servletResponse, refreshToken);

        LoginResponse response = new LoginResponse(accessToken.token());

        return ResponseEntity.ok(ApiResult.ok(response));
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResult<SignupResponse>> join(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        @RequestBody @Valid SignUpRequest signUpRequest) {

        SignUpResult result = authFacade.signUp(signUpRequest.id(), signUpRequest.password(),
            signUpRequest.name());

        TokenDto accessToken = result.tokenPair().accessToken();
        TokenDto refreshToken = result.tokenPair().refreshToken();

        processCookie(servletRequest, servletResponse, refreshToken);

        SignupResponse response = SignupResponse.of(accessToken, result.user());

        return ResponseEntity.ok(ApiResult.ok(response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResult<RefreshResponse>> refresh(HttpServletRequest servletRequest) {

        String accessToken = HeaderUtil.getAccessToken(servletRequest);
        String refreshToken = CookieUtil.getCookie(servletRequest)
            .map(Cookie::getValue)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_INVALID));

        long userSeq = tokenProvider.validateAccessToken(accessToken);
        tokenProvider.validateRefreshToken(refreshToken);

        RefreshResult refreshResult = authFacade.refresh(userSeq, refreshToken);

        return ResponseEntity.ok(
            ApiResult.ok(new RefreshResponse(refreshResult.newAccessToken().token())));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResult<Void>> logout(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) {

        CookieUtil.getCookie(servletRequest)
            .map(Cookie::getValue)
            .ifPresent(token -> {
                long userSeq = tokenProvider.validateRefreshToken(token);
                authFacade.logout(userSeq);
                CookieUtil.deleteCookie(servletRequest, servletResponse);
            });

        return ResponseEntity.ok(ApiResult.ok());
    }

    private void processCookie(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        TokenDto refreshToken) {

        int refreshTokenCookieMaxAgeSeconds = authProperties.getAuth().getCookieMaxSeconds();

        CookieUtil.deleteCookie(servletRequest, servletResponse);
        CookieUtil.addCookie(servletResponse, refreshToken.token(), refreshTokenCookieMaxAgeSeconds);
    }
}
