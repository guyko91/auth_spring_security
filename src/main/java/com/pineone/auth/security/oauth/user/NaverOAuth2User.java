package com.pineone.auth.security.oauth.user;

import java.util.Map;

public class NaverOAuth2User extends OAuth2UserAttribute implements OAuth2UserInfo {

    public NaverOAuth2User(Map<String, Object> attributes) {
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
