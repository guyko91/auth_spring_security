package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User;
import com.pineone.auth.api.model.UserAuthToken;
import com.pineone.auth.api.service.dto.AuthTokenCreateCommand;
import com.pineone.auth.api.service.dto.LoginResult;
import com.pineone.auth.api.service.dto.TwoFactorAuthRequiredResult;
import com.pineone.auth.api.service.dto.TokenRefreshResult;
import com.pineone.auth.api.service.dto.SignUpResult;
import com.pineone.auth.api.service.dto.SignupCommand;
import com.pineone.auth.api.service.dto.TokenInfoResult;
import com.pineone.auth.security.SecurityHandler;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenHandler;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthFacade {

    private final UserService userService;
    private final UserTokenService userTokenService;
    private final User2FAService user2FAService;

    private final SecurityHandler securityHandler;
    private final TokenHandler tokenHandler;

    public LoginResult login(String id, String password) {
        UserPrincipal userPrincipal = securityHandler.authenticateIdPwd(id, password);
        User user = findUserWith(userPrincipal.getSeq());

        TokenPairDto tokenPair = tokenHandler.createTokenPair(userPrincipal);
        String tokenUuid = createAndGetAuthTokenUuid(userPrincipal.getSeq(), tokenPair);
        TwoFactorAuthRequiredResult twoFactorCheckResult = user2FAService.checkUser2FARequired(userPrincipal.getSeq());

        return LoginResult.of(tokenUuid, user, twoFactorCheckResult);
    }

    public SignUpResult signUp(SignupCommand command) {
        checkUserIdDuplication(command.id());

        User user = userService.createUserWith(command.id(), command.password(), command.name());
        UserPrincipal userPrincipal = securityHandler.authenticateIdPwd(command.id(), command.password());

        TokenPairDto tokenPair = tokenHandler.createTokenPair(userPrincipal);
        String tokenUuid = createAndGetAuthTokenUuid(userPrincipal.getSeq(), tokenPair);
        TwoFactorAuthRequiredResult twoFactorCheckResult = user2FAService.create2FARequireInfo(userPrincipal.getSeq());

        return SignUpResult.of(user, tokenUuid, twoFactorCheckResult);
    }

    public TokenInfoResult getTokenPair(String tokenUuid) {
        UserAuthToken userAuthToken = findUserAuthTokenBy(tokenUuid);
        return new TokenInfoResult(userAuthToken.getAccessToken(), userAuthToken.getRefreshToken());
    }

    public void verifyUser2FA(String tokenKey, String inputCode, LocalDateTime verifyDateTime) {
        UserAuthToken userAuthToken = findUserAuthTokenBy(tokenKey);
        long userSeq = userAuthToken.getUserSeq();

        boolean otpCodeMatched = user2FAService.verifyUser2FACode(userSeq, inputCode, verifyDateTime);
        if (!otpCodeMatched) { throw new BusinessException(ErrorCode.BAD_REQUEST_INVALID_PARAMETER_2FA_CODE_MISMATCH); }
    }

    public TokenRefreshResult refresh(String accessToken, String refreshToken) {
        checkUserRefreshTokenExists(refreshToken);
        tokenHandler.validateTokenRefreshRequest(accessToken, refreshToken);
        UserPrincipal userPrincipal = tokenHandler.validateAndGetUserPrincipalFrom(accessToken);

        userTokenService.logoutUserToken(refreshToken);

        TokenPairDto tokenPair = tokenHandler.createTokenPair(userPrincipal);
        String tokenUuid = createAndGetAuthTokenUuid(userPrincipal.getSeq(), tokenPair);
        User user = findUserWith(userPrincipal.getSeq());

        return TokenRefreshResult.of(user, tokenUuid);
    }

    public void logout(String refreshToken) {
        userTokenService.logoutUserToken(refreshToken);
    }

    private void checkUserIdDuplication(String id) {
        userService.getUserBy(id)
            .ifPresent(user -> { throw new BusinessException(ErrorCode.CONFLICT, "ID is duplicated"); });
    }

    private void checkUserRefreshTokenExists(String refreshToken) {
        userTokenService.findUserTokenBy(refreshToken)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_INVALID));
    }

    private String createAndGetAuthTokenUuid(long userSeq, TokenPairDto tokenPair) {
        AuthTokenCreateCommand command = AuthTokenCreateCommand.of(userSeq, tokenPair);
        return userTokenService.saveAuthToken(command);
    }

    private User findUserWith(long userSeq) {
        return userService.getUserBy(userSeq)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_USER_NOT_FOUND));
    }

    private UserAuthToken findUserAuthTokenBy(String tokenUuid) {
        return userTokenService.findAuthTokenWith(tokenUuid)
            .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));
    }

}
