package com.pineone.auth.security.oauth.user;

import java.util.Map;

public abstract class OAuth2UserAttribute {
    private final Map<String, Object> attributes;
    public OAuth2UserAttribute(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
}
