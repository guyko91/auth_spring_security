package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.dto.AuthResponse;
import com.pineone.auth.api.controller.dto.TokenLogoutRequest;
import com.pineone.auth.api.controller.dto.TokenRefreshRequest;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.service.AuthFacade;
import com.pineone.auth.api.service.dto.TokenRefreshResult;
import com.pineone.auth.security.ServletAuthHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class SecureApiController {

    private final AuthFacade authFacade;
    private final ServletAuthHandler servletAuthHandler;

    @PostMapping("/refresh")
    public ResponseEntity<ApiResult<AuthResponse>> refresh(
        HttpServletRequest request,
        @RequestBody @Valid TokenRefreshRequest tokenRefreshRequest
    ) {

        String accessToken = parseAccessTokenFrom(request);
        String refreshToken = tokenRefreshRequest.refreshToken();

        TokenRefreshResult tokenRefreshResult = authFacade.refresh(accessToken, refreshToken);

        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResult<Void>> logout(
        HttpServletRequest request,
        @RequestBody @Valid TokenLogoutRequest tokenLogoutRequest
    ) {
        String refreshToken = tokenLogoutRequest.refreshToken();

        authFacade.logout(refreshToken);
        return ResponseEntity.ok(ApiResult.ok());
    }

    private String parseAccessTokenFrom(HttpServletRequest request) {
        return servletAuthHandler.getAccessTokenStringFrom(request)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED));
    }

}
