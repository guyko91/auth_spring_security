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




    }

    private void loginSuccess(HttpServletResponse response, UserPrincipal userPrincipal) {

    }
}
