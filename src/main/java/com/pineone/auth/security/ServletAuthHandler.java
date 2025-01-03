package com.pineone.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineone.auth.api.controller.constant.ApiResult;
import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.service.dto.TwoFactorAuthRequiredResult;
import com.pineone.auth.api.service.model.TwoFactorAuthInfoProvidable;
import com.pineone.auth.config.AuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
public class ServletAuthHandler {

    private final AuthProperties authProperties;
    private final ObjectMapper objectMapper;

    public  final String AUTHORIZATION_HEADER_KEY = "Authorization";

    public void processOAuthTokenResponse(HttpServletResponse response, String tokenUuid,
        TwoFactorAuthRequiredResult otpResult) throws IOException {

        if (otpResult.twoFactorAuthRequired()) {
            toOtpPageRedirectResponse(response, tokenUuid, otpResult.twoFactorAuthInfoProvidable());
        }else {
            toSuccessRedirectResponse(response, tokenUuid);
        }
    }

    public void writeErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(errorCode.getHttpStatus().value());

        String responseBody = objectMapper.writeValueAsString(ApiResult.response(errorCode));
        response.getWriter().write(responseBody);
    }

    public Optional<String> getAccessTokenStringFrom(HttpServletRequest request) {
        String accessTokenHeader = request.getHeader(AUTHORIZATION_HEADER_KEY);
        if (StringUtils.hasText(accessTokenHeader)) {
            return Optional.of(accessTokenHeader);
        }
        return Optional.empty();
    }

    private void toSuccessRedirectResponse(HttpServletResponse response, String tokenUuid) throws IOException {
        String successRedirectUri = authProperties.getOauth2().getLoginSuccessRedirectUri();
        String tokenKeyQueryParamName = authProperties.getOauth2().getLoginSuccessTokenQueryParam();

        response.sendRedirect(
            UriComponentsBuilder
                .fromUriString(successRedirectUri)
                .queryParam(tokenKeyQueryParamName, tokenUuid)
                .build().toUriString()
        );
    }

    private void toOtpPageRedirectResponse(HttpServletResponse response, String tokenUuid, TwoFactorAuthInfoProvidable authInfo) throws IOException {
        String redirectUri = authProperties.getOauth2().getOtpRequireRedirectUri();
        String target = authInfo.getTarget();

        response.setContentType("text/html;charset=UTF-8");

        String htmlContent = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
            </head>
            <body>
                <form id='postForm' action='%s' method='post'>
                    <input type='hidden' name='%s' value='%s'>
                    <input type='hidden' name='%s' value='%s'>
                    <input type='hidden' name='%s' value='%s'>
                    <input type='hidden' name='%s' value='%s'>
                    <input type='hidden' name='%s' value='%s'>
                    <input type='hidden' name='%s' value='%s'>
                </form>
                <script>
                    document.getElementById('postForm').submit();
                </script>
            </body>
            </html>
        """.formatted(
                redirectUri,
                "tokenKey", tokenUuid,
                "target", target,
                "method", authInfo.getMethod(),
                "limitCount", authInfo.getLimitCount(),
                "createdAt", authInfo.getCreatedDateTime(),
                "expireAt", authInfo.getExpireDateTime()
            );

        response.getWriter().write(htmlContent);
    }

}
