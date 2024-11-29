package com.pineone.auth.security.oauth.user;

import com.pineone.auth.security.oauth.OAuth2Provider;
import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(OAuth2Provider provider , Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> new GoogleOAuth2User(attributes);
            case FACEBOOK -> new FacebookOAuth2User(attributes);
            case KAKAO -> new KakaoOAuth2User(attributes);
            case NAVER -> new NaverOAuth2User(attributes);
            default -> throw new IllegalArgumentException("Unsupported provider: " + provider);
        };
    }

}
