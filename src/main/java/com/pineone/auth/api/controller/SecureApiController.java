package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.dto.RefreshResponse;
import com.pineone.auth.api.service.AuthFacade;
import com.pineone.auth.api.service.UserOtpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class SecureApiController {

    private final AuthFacade authFacade;
    private final UserOtpService userOtpService;

    @PostMapping("/refresh")
    public ResponseEntity<ApiResult<RefreshResponse>> refresh() {

//        RefreshResult refreshResult = authFacade.refresh(refreshTokenString);

        return ResponseEntity.ok(ApiResult.ok());
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResult<Void>> logout(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) {

        return ResponseEntity.ok(ApiResult.ok());
    }

}
