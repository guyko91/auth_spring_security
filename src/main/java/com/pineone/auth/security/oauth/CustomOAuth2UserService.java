package com.pineone.auth.security.oauth;

import com.pineone.auth.api.model.User;
import com.pineone.auth.api.repository.UserRepository;
import com.pineone.auth.security.UserPrincipal;
import com.pineone.auth.security.oauth.user.OAuth2UserInfo;
import com.pineone.auth.security.oauth.user.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        try {
            return process(userRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User process(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2Provider provider = extractProviderFrom(oAuth2UserRequest);
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(provider, oAuth2User.getAttributes());

        return getOrCreateUser(oAuth2UserInfo);
    }

    private OAuth2Provider extractProviderFrom(OAuth2UserRequest oAuth2UserRequest) {
        String providerId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        return OAuth2Provider.valueOf(providerId.toUpperCase());
    }

    private UserPrincipal getOrCreateUser(OAuth2UserInfo oauth2UserInfo) {
        User savedUser = userRepository.findById(oauth2UserInfo.getId())
            .map(this::updateUser)
            .orElseGet(() -> createOAuthUser(oauth2UserInfo));

        return UserPrincipal.create(savedUser, oauth2UserInfo.getAttributes());
    }

    private User updateUser(User user) {
        // TODO : 변경된 OAuth 사용자 정보로 업데이트 필요한 경우, 업데이트 로직 추가
        return user;
    }

    private User createOAuthUser(OAuth2UserInfo oAuth2UserInfo) {
        return userRepository.saveAndFlush(
            User.createOAuth2(
                oAuth2UserInfo.getId(),
                oAuth2UserInfo.getName(),
                oAuth2UserInfo.getEmail(),
                oAuth2UserInfo.getProvider().toAuthProvider()
            )
        );
    }

}
