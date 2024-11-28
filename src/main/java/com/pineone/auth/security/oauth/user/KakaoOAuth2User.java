package com.pineone.auth.security.oauth.user;

import java.util.Map;

public class KakaoOAuth2User extends OAuth2UserAttribute implements OAuth2UserInfo {

    public KakaoOAuth2User(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getProviderId() {
        return "";
    }

    @Override
    public String getProvider() {
        return "";
    }

    @Override
    public String getName() {
        return "";
    }

    @Override
    public String getEmail() {
        return "";
    }
}
