package com.pineone.auth.api.service;

import com.pineone.auth.api.model.UserToken;
import com.pineone.auth.api.repository.UserTokenRepository;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenPairDto;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserTokenService {

    private final UserTokenRepository userTokenRepository;

    @Transactional
    public void logoutUserToken(long userSeq) {
        userTokenRepository.findByUserSeq(userSeq)
            .ifPresent(userTokenRepository::delete);
    }

    public Optional<UserToken> findUserTokenBy(String refreshToken) {
        return userTokenRepository.findByRefreshToken(refreshToken);
    }

    @Transactional
    public void saveOrUpdateRefreshToken(long userSeq, TokenDto refreshToken) {
        Optional<UserToken> userToken = userTokenRepository.findByUserSeq(userSeq);

        if(userToken.isPresent()) {
            userToken.get().updateRefreshToken(refreshToken.token(), refreshToken.expireDateTime());
        }else {
            UserToken newToken = UserToken.create(userSeq, refreshToken.token(), refreshToken.expireDateTime());
            userTokenRepository.save(newToken);
        }
    }

}
