package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.SuccessCode;
import com.pineone.auth.api.controller.dto.AuthResponse;
import com.pineone.auth.api.controller.dto.LoginRequest;
import com.pineone.auth.api.controller.dto.TwoFactorVerifyRequest;
import com.pineone.auth.api.controller.dto.SignUpRequest;
import com.pineone.auth.api.controller.dto.TokenResponse;
import com.pineone.auth.api.service.AuthFacade;
import com.pineone.auth.api.service.dto.LoginResult;
import com.pineone.auth.api.service.dto.SignUpResult;
import com.pineone.auth.api.service.dto.SignupCommand;
import com.pineone.auth.api.service.dto.TokenInfoResult;
import jakarta.validation.Valid;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("public/api")
@RequiredArgsConstructor
public class PublicApiController {

    private final AuthFacade authFacade;

    @PostMapping("login")
    public ResponseEntity<ApiResult<AuthResponse>> login(@RequestBody @Valid LoginRequest loginRequest) {

        LoginResult loginResult = authFacade.login(loginRequest.id(), loginRequest.password());

        if (loginResult.isOtpRequired()) {
            AuthResponse result = AuthResponse.otpRequired(loginResult.tokenUuid(), loginResult.otpRequire());
            return ResponseEntity.accepted()
                .body(ApiResult.response(SuccessCode.ACCEPTED_OTP_REQUIRED, result));
        }

        return ResponseEntity.ok(
            ApiResult.ok(
                AuthResponse.otpNotRequired(loginResult.tokenUuid()))
        );
    }

    @PostMapping("signup")
    public ResponseEntity<ApiResult<AuthResponse>> join(@RequestBody @Valid SignUpRequest signUpRequest) {

        SignupCommand signupCommand = signUpRequest.toSignupCommand();
        SignUpResult signupResult = authFacade.signUp(signupCommand);

        AuthResponse result = AuthResponse.otpRequired(signupResult.tokenUuid(), signupResult.otpRequire());
        return ResponseEntity.accepted()
            .body(ApiResult.response(SuccessCode.ACCEPTED_OTP_REQUIRED, result));
    }

    @PostMapping("2fa-verify")
    public ResponseEntity<ApiResult<AuthResponse>> twoFactorAuthVerify(@RequestBody @Valid TwoFactorVerifyRequest twoFactorVerifyRequest) {

        String tokenKey = twoFactorVerifyRequest.tokenKey();
        String code = twoFactorVerifyRequest.code();
        LocalDateTime verifyDateTime = LocalDateTime.now();

        authFacade.verifyUser2FA(tokenKey, code, verifyDateTime);

        return ResponseEntity.ok(ApiResult.ok());
    }

    @GetMapping("token")
    public ResponseEntity<ApiResult<TokenResponse>> tokenInfo(@RequestParam("tokenKey") String tokenKey) {

        TokenInfoResult tokenInfoResult = authFacade.getTokenPair(tokenKey);

        TokenResponse result = new TokenResponse(tokenInfoResult.accessToken(), tokenInfoResult.refreshToken());

        ApiResult<TokenResponse> response = ApiResult.ok(result);
        return ResponseEntity.ok(response);
    }

}
