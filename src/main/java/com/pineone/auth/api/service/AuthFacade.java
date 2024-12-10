package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User;
import com.pineone.auth.api.model.UserAuthToken;
import com.pineone.auth.api.service.dto.AuthTokenCreateCommand;
import com.pineone.auth.api.service.dto.LoginResult;
import com.pineone.auth.api.service.dto.OtpRequiredResult;
import com.pineone.auth.api.service.dto.RefreshResult;
import com.pineone.auth.api.service.dto.SignUpResult;
import com.pineone.auth.api.service.dto.SignupCommand;
import com.pineone.auth.api.service.dto.TokenInfoResult;
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
    private final UserOtpService userOtpService;

    private final SecurityProvider securityProvider;
    private final TokenProvider tokenProvider;

    public LoginResult login(String id, String password) {
        UserPrincipal userPrincipal = securityProvider.authenticateIdPwd(id, password);
        User user = findUserWith(userPrincipal.getSeq());

        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);
        String tokenUuid = createAndGetAuthTokenUuid(userPrincipal.getSeq(), tokenPair);
        OtpRequiredResult otpResult = userOtpService.isUserOtpVerifyRequired(userPrincipal.getSeq());

        return LoginResult.of(tokenUuid, user, otpResult);
    }

    public SignUpResult signUp(SignupCommand command) {
        userService.checkUserIdDuplication(command.id());

        User user = userService.createUserWith(command.id(), command.password(), command.name());
        UserPrincipal userPrincipal = securityProvider.authenticateIdPwd(command.id(), command.password());

        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);
        String tokenUuid = createAndGetAuthTokenUuid(userPrincipal.getSeq(), tokenPair);
        OtpRequiredResult otpResult = userOtpService.createEncodedOtpSecret(userPrincipal.getSeq());

        return SignUpResult.of(user, tokenUuid, otpResult);
    }

    public TokenInfoResult getTokenPair(String tokenUuid) {
        UserAuthToken userAuthToken = findUserAuthTokenBy(tokenUuid);
        return new TokenInfoResult(userAuthToken.getAccessToken(), userAuthToken.getRefreshToken());
    }

    public void verifyUserOtp(String tokenKey, String code) {
        UserAuthToken userAuthToken = findUserAuthTokenBy(tokenKey);
        long userSeq = userAuthToken.getUserSeq();

        boolean otpCodeMatched = userOtpService.isUserOtpCodeMatched(userSeq, code);
        if (!otpCodeMatched) {
            throw new BusinessException(ErrorCode.BAD_REQUEST_INVALID_PARAMETER_OTP_CODE);
        }
    }

    public RefreshResult refresh(String refreshToken) {

        UserPrincipal userPrincipal = securityProvider.getCurrentUserPrincipal()
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED));

        User user = findUserWith(userPrincipal.getSeq());

        userTokenService.findUserTokenBy(refreshToken)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_INVALID));

        TokenDto newAccessToken = tokenProvider.createNewAccessToken(userPrincipal);

        return RefreshResult.of(newAccessToken, user);
    }

    public void logout(String refreshToken) {
        userTokenService.logoutUserToken(refreshToken);
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
