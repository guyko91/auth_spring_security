package com.pineone.auth.security.oauth.user;

import java.util.Map;

public abstract class AbstractOAuth2User {
    private final Map<String, Object> attributes;
    protected AbstractOAuth2User(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    protected String getAttribute(String key) {
        return attributes.get(key) == null ? "" : String.valueOf(attributes.get(key));
    }
    public Map<String, Object> getAttributes() { return attributes; }
}
