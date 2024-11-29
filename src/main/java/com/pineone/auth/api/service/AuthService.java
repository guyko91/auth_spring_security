package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User;
import com.pineone.auth.api.model.UserToken;
import com.pineone.auth.api.repository.UserRepository;
import com.pineone.auth.api.repository.UserTokenRepository;
import com.pineone.auth.api.service.dto.LoginResult;
import com.pineone.auth.api.service.dto.RefreshResult;
import com.pineone.auth.api.service.dto.SignUpResult;
import com.pineone.auth.security.SecurityProvider;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.token.TokenDto;
import com.pineone.auth.security.token.TokenPairDto;
import com.pineone.auth.security.token.TokenProvider;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final SecurityProvider securityProvider;
    private final TokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;
    private final UserTokenRepository userTokenRepository;

    public LoginResult login(String id, String password) {
        UserPrincipal userPrincipal = securityProvider.createAuthentication(id, password);
        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);

        processRefreshToken(userPrincipal, tokenPair);

        return new LoginResult(tokenPair);
    }

    public SignUpResult signUp(String id, String password, String name) {
        checkIdDuplication(id);

        User user = createUserWith(id, password, name);
        UserPrincipal userPrincipal = securityProvider.createAuthentication(id, password);
        TokenPairDto tokenPair = tokenProvider.createTokenPair(userPrincipal);

        processRefreshToken(userPrincipal, tokenPair);

        return new SignUpResult(user, tokenPair);
    }

    public RefreshResult refresh(long userSeq, String refreshToken) {
        User user = userRepository.findById(userSeq)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_USER_NOT_FOUND));

        userTokenRepository.findByRefreshToken(refreshToken)
            .orElseThrow(() -> new BusinessException(ErrorCode.UNAUTHORIZED_REFRESH_TOKEN_INVALID));

        UserPrincipal userPrincipal = securityProvider.createAuthentication(user.getId(), user.getPassword());
        TokenDto newAccessToken = tokenProvider.createNewAccessToken(userPrincipal);

        return new RefreshResult(newAccessToken);
    }

    public void logout(long userSeq) {
        userTokenRepository.findByUserSeq(userSeq)
            .ifPresent(userTokenRepository::delete);
    }

    private void processRefreshToken(UserPrincipal userPrincipal, TokenPairDto tokenPair) {
        long userSeq = userPrincipal.getSeq();
        TokenDto refreshToken = tokenPair.refreshToken();

        Optional<UserToken> userToken = userTokenRepository.findByUserSeq(userSeq);

        if(userToken.isPresent()) {
            userToken.get().updateRefreshToken(refreshToken.token(), refreshToken.expireDateTime());
        }else {
            UserToken newToken = UserToken.create(userSeq, refreshToken.token(), refreshToken.expireDateTime());
            userTokenRepository.save(newToken);
        }
    }

    private void checkIdDuplication(String id) {
        if (userRepository.existsById(id)) {
            throw new BusinessException(ErrorCode.CONFLICT, "ID is duplicated");
        }
    }

    private User createUserWith(String id, String password, String name) {
        String encodedPassword = passwordEncoder.encode(password);
        User user = User.createNormal(id, encodedPassword, name);
        return userRepository.saveAndFlush(user);
    }
}
