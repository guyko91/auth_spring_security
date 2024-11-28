package com.pineone.auth.security.oauth.user;

import java.util.Map;

public class GithubOAuth2User extends OAuth2UserInfo {

    public GithubOAuth2User(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getUserIdentifier() {
        return (String) attributes.get("id");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

}
