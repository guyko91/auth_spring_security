package com.pineone.auth.security.token.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.service.ServletAuthHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /**
     * 인증 필터에서 SecurityContext에 Authentication 이 세팅되지 않았을때 호출되는 컴포넌트.
     */
    private final ObjectMapper objectMapper;
    private final ServletAuthHandler servletAuthHandler;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException) throws IOException {
        ErrorCode errorCode = determineErrorCode(request);

        servletAuthHandler.writeErrorResponse(response, errorCode);
    }

    private ErrorCode determineErrorCode(HttpServletRequest request) {
        ErrorCode tokenErrorCode = (ErrorCode) request.getAttribute(JwtAuthenticationFilter.TOKEN_EXCEPTION_ATTRIBUTE_KEY);
        return tokenErrorCode != null ? tokenErrorCode : ErrorCode.UNAUTHORIZED;
    }

}
