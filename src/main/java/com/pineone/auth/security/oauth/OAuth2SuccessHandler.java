package com.pineone.auth.security.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        TokenPairDto tokenPairDto = tokenProvider.createTokenPair(userPrincipal);

        // 응답 헤더에 상태 코드와 함께 토큰을 JSON 형식으로 응답 본문에 추가
        response.setStatus(HttpServletResponse.SC_OK); // 200 OK 상태 코드
        response.setContentType("application/json");  // 응답 내용 타입 설정
        response.getWriter().write(objectMapper.writeValueAsString(tokenPairDto));

        response.sendRedirect("/home");

        // 이후 성공 핸들러 호출 (여기서는 기본 핸들러 호출)
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
