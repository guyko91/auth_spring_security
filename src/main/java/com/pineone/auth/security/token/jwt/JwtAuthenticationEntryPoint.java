package com.pineone.auth.security.token.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.security.CustomAuthenticationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    /**
     * 앞의 필터에서 AuthenticationException 이 발생 시 호출되는 컴포넌트.
     * 인증되지 않은 사용자가 보호된 리소스에 액세스하려고 할 때 호출된다.
     */

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException) throws IOException {

        log.debug("JwtAuthenticationEntryPoint.commence");

        ErrorCode errorCode = determineErrorCode(authException, request);
        writeErrorResponse(response, errorCode);
    }

    private ErrorCode determineErrorCode(AuthenticationException authException, HttpServletRequest request) {
        if (authException instanceof CustomAuthenticationException) {
            return ((CustomAuthenticationException)  authException).getErrorCode();
        }
        return ErrorCode.UNAUTHORIZED;
    }

    private void writeErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(errorCode.getHttpStatus().value());

        String responseBody = objectMapper.writeValueAsString(ApiResult.response(errorCode));
        response.getWriter().write(responseBody);
    }
}
