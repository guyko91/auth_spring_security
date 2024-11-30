package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User;
import com.pineone.auth.api.service.dto.LoginResult;
import com.pineone.auth.api.service.dto.RefreshResult;
import com.pineone.auth.api.service.dto.SignUpResult;
import com.pineone.auth.security.SecurityProvider;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthFacade {

    private final UserService userService;
    private final UserTokenService userTokenService;

    private final SecurityProvider securityProvider;
    private final TokenProvider tokenProvider;

    @Transactional
    public LoginResult login(String id, String password) {
        UserPrincipal userPrincipal = securityProvider.createAuthentication(id, password);
        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);

        userTokenService.saveOrUpdateRefreshToken(userPrincipal, tokenPair);

        return new LoginResult(tokenPair);
    }

    @Transactional
    public SignUpResult signUp(String id, String password, String name) {
        userService.checkUserIdDuplication(id);

        User user = userService.createUserWith(id, password, name);
        UserPrincipal userPrincipal = securityProvider.createAuthentication(id, password);
        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);

        userTokenService.saveOrUpdateRefreshToken(userPrincipal, tokenPair);

        return new SignUpResult(user, tokenPair);
    }

    @Transactional
    public RefreshResult refresh(long userSeq, String refreshToken) {
        User user = userService.getUserBy(userSeq)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_USER_NOT_FOUND));

        userTokenService.findUserTokenBy(refreshToken)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_INVALID));

        UserPrincipal userPrincipal = securityProvider.createAuthentication(user.getId(), user.getPassword());
        TokenDto newAccessToken = tokenProvider.createNewAccessToken(userPrincipal);

        return new RefreshResult(newAccessToken);
    }

    @Transactional
    public void logout(long userSeq) {
        userTokenService.logoutUserToken(userSeq);
    }

}
