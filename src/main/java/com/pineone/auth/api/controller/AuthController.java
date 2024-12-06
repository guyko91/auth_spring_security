package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.dto.LoginRequest;
import com.pineone.auth.api.controller.dto.LoginResponse;
import com.pineone.auth.api.controller.dto.RefreshResponse;
import com.pineone.auth.api.controller.dto.SignUpRequest;
import com.pineone.auth.api.controller.dto.SignupResponse;
import com.pineone.auth.api.service.ServletAuthHandler;
import com.pineone.auth.api.service.AuthFacade;
import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.service.dto.LoginResult;
import com.pineone.auth.api.service.dto.RefreshResult;
import com.pineone.auth.api.service.dto.SignUpResult;
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
    private final ServletAuthHandler servletAuthHandler;

    @PostMapping("login")
    public ResponseEntity<ApiResult<LoginResponse>> login(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        @RequestBody @Valid LoginRequest loginRequest) {

        LoginResult loginResult = authFacade.login(loginRequest.id(), loginRequest.password());

        servletAuthHandler.processTokenResponse(servletRequest, servletResponse, loginResult.tokenPair());

        LoginResponse response = new LoginResponse(loginResult.user());

        return ResponseEntity.ok(ApiResult.ok(response));
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResult<SignupResponse>> join(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse,
        @RequestBody @Valid SignUpRequest signUpRequest) {

        SignUpResult signupResult = authFacade.signUp(
            signUpRequest.id(), signUpRequest.password(), signUpRequest.name());

        servletAuthHandler.processTokenResponse(
            servletRequest, servletResponse, signupResult.tokenPair());

        SignupResponse response = new SignupResponse(signupResult.user());

        return ResponseEntity.ok(ApiResult.ok(response));
    }


    @PostMapping("/refresh")
    public ResponseEntity<ApiResult<RefreshResponse>> refresh(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) {

        String refreshTokenString = servletAuthHandler.validateTokenRefreshRequest(servletRequest);

        RefreshResult refreshResult = authFacade.refresh(refreshTokenString);

        servletAuthHandler.processTokenRefreshResponse(servletResponse, refreshResult.newAccessToken());

        return ResponseEntity.ok(ApiResult.ok(new RefreshResponse(refreshResult.user())));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResult<Void>> logout(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) {

        String refreshToken = servletAuthHandler.validateLogoutRequest(servletRequest);

        authFacade.logout(refreshToken);

        servletAuthHandler.processLogout(servletRequest, servletResponse);

        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResult<Void>> verifyOtp(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) {

        // TODO: Implement OTP verification logic

        return ResponseEntity.ok(ApiResult.ok());
    }

}
