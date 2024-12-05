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
@Transactional
@RequiredArgsConstructor
public class AuthFacade {

    private final UserService userService;
    private final UserTokenService userTokenService;

    private final SecurityProvider securityProvider;
    private final TokenProvider tokenProvider;

    public LoginResult login(String id, String password) {
        UserPrincipal userPrincipal = securityProvider.authenticateIdPwd(id, password);
        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);

        User user = userService.getUserBy(userPrincipal.getSeq())
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_USER_NOT_FOUND));

        userTokenService.saveOrUpdateRefreshToken(userPrincipal.getSeq(), tokenPair.refreshToken());

        return LoginResult.of(tokenPair, user);
    }

    public SignUpResult signUp(String id, String password, String name) {
        userService.checkUserIdDuplication(id);

        User user = userService.createUserWith(id, password, name);
        UserPrincipal userPrincipal = securityProvider.authenticateIdPwd(id, password);
        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);

        userTokenService.saveOrUpdateRefreshToken(user.getSeq(), tokenPair.refreshToken());

        return SignUpResult.of(tokenPair, user);
    }

    public RefreshResult refresh(String refreshToken) {

        UserPrincipal userPrincipal = securityProvider.getCurrentUserPrincipal();

        User user = userService.getUserBy(userPrincipal.getSeq())
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_USER_NOT_FOUND));

        userTokenService.findUserTokenBy(refreshToken)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_INVALID));

        TokenDto newAccessToken = tokenProvider.createNewAccessToken(userPrincipal);

        return RefreshResult.of(newAccessToken, user);
    }

    public void logout() {
        UserPrincipal userPrincipal = securityProvider.getCurrentUserPrincipal();

        userTokenService.logoutUserToken(userPrincipal.getSeq());
    }

}
