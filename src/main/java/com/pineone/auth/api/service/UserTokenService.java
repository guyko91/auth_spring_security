package com.pineone.auth.api.service;

import com.pineone.auth.api.model.UserAuthToken;
import com.pineone.auth.api.model.UserToken;
import com.pineone.auth.api.repository.AuthTokenRepository;
import com.pineone.auth.api.repository.UserTokenRepository;
import com.pineone.auth.api.service.dto.AuthTokenCreateCommand;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
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
    public String saveAuthToken(AuthTokenCreateCommand command) {
        String tokenUuid = saveAuthTokenPair(command.userSeq(), command.accessToken(), command.refreshToken());
        saveUserRefreshToken(command.userSeq(), command.refreshToken(), command.refreshTokenExpireDateTime());
        return tokenUuid;
    }

    public Optional<UserAuthToken> findAuthTokenWith(String tokenUuid) {
        return authTokenRepository.findById(tokenUuid);
    }

    @Transactional
    public void logoutUserToken(String refreshToken) {
        userTokenRepository.findByRefreshToken(refreshToken)
            .ifPresent(userTokenRepository::delete);
    }

    public Optional<UserToken> findUserTokenBy(String refreshToken) {
        return userTokenRepository.findByRefreshToken(refreshToken);
    }

    private String saveAuthTokenPair(long userSeq, String accessToken, String refreshToken) {
        String tokenUuid = UUID.randomUUID().toString();
        UserAuthToken userAuthToken = UserAuthToken.create(tokenUuid, userSeq, accessToken, refreshToken);
        authTokenRepository.save(userAuthToken);
        return tokenUuid;
    }

    private void saveUserRefreshToken(long userSeq, String refreshToken, LocalDateTime expireDateTime) {
        UserToken userToken = UserToken.create(userSeq, refreshToken, expireDateTime);
        userTokenRepository.save(userToken);
    }

}
