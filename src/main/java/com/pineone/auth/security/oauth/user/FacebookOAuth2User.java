package com.pineone.auth.security.oauth.user;

import java.util.Map;

public class FacebookOAuth2User extends OAuth2UserAttribute implements OAuth2UserInfo {

    public FacebookOAuth2User(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getEmail() {
        return "";
    }

    @Override
    public String getName() {
        return "";
    }

    @Override
    public String getProvider() {
        return "";
    }

    @Override
    public String getProviderId() {
        return "";
    }
}
