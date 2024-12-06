package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User;
import com.pineone.auth.api.repository.UserRepository;
import com.pineone.auth.security.oauth.user.OAuth2UserInfo;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Optional<User> getUserBy(long userSeq) {
        return userRepository.findById(userSeq);
    }

    public Optional<User> getUserBy(String id) {
        return userRepository.findById(id);
    }

    public void checkUserIdDuplication(String id) {
        if (userRepository.existsById(id)) {
            throw new BusinessException(ErrorCode.CONFLICT, "ID is duplicated");
        }
    }

    @Transactional
    public User createUserWith(String id, String password, String name) {
        String encodedPassword = passwordEncoder.encode(password);
        User user = User.createNormal(id, encodedPassword, name);
        return userRepository.saveAndFlush(user);
    }

    @Transactional
    public User createUserWith(OAuth2UserInfo oAuth2UserInfo) {
        User oauth2User = User.createOAuth2(
            oAuth2UserInfo.getId(),
            oAuth2UserInfo.getName(),
            oAuth2UserInfo.getEmail(),
            oAuth2UserInfo.getProvider().toAuthProvider()
        );
        return userRepository.saveAndFlush(oauth2User);
    }

}
