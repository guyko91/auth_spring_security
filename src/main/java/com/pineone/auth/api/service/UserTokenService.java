package com.pineone.auth.api.service;

import com.pineone.auth.api.model.UserAuthToken;
import com.pineone.auth.api.model.UserToken;
import com.pineone.auth.api.repository.AuthTokenRepository;
import com.pineone.auth.api.repository.UserTokenRepository;
import com.pineone.auth.api.service.dto.AuthCommand;
import java.time.LocalDateTime;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserTokenService {

    private final UserTokenRepository userTokenRepository;
    private final AuthTokenRepository authTokenRepository;

    @Transactional
    public void saveAuthToken(AuthCommand authCommand) {
        saveAuthTokenPair(authCommand.userSeq(), authCommand.tokenKey(), authCommand.accessToken(), authCommand.refreshToken());
        saveUserRefreshToken(authCommand.userSeq(), authCommand.refreshToken(), authCommand.refreshTokenExpireDateTime());
    }

    public Optional<UserAuthToken> findAuthTokenWith(String tokenKey) {
        return authTokenRepository.findByUuid(tokenKey);
    }

    @Transactional
    public void logoutUserToken(long userSeq) {
        userTokenRepository.findByUserSeq(userSeq)
            .ifPresent(userTokenRepository::delete);
    }

    @Transactional
    public void logoutUserToken(String refreshToken) {
        userTokenRepository.findByRefreshToken(refreshToken)
            .ifPresent(userTokenRepository::delete);
    }

    public Optional<UserToken> findUserTokenBy(String refreshToken) {
        return userTokenRepository.findByRefreshToken(refreshToken);
    }

    private void saveAuthTokenPair(long userSeq, String tokenKey, String accessToken, String refreshToken) {
        UserAuthToken userAuthToken = UserAuthToken.create(userSeq, tokenKey, accessToken, refreshToken);
        authTokenRepository.save(userAuthToken);
    }

    private void saveUserRefreshToken(long userSeq, String refreshToken, LocalDateTime expireDateTime) {
        UserToken userToken = UserToken.create(userSeq, refreshToken, expireDateTime);
        userTokenRepository.save(userToken);
    }

}
