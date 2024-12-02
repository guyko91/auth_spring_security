package com.pineone.auth.security.oauth.user;

import com.pineone.auth.security.oauth.OAuth2Provider;
import java.util.Map;

public class NaverOAuth2User extends AbstractOAuth2User implements OAuth2UserInfo {

    public NaverOAuth2User(Map<String, Object> attributes) { super(attributes); }

    @Override
    public String getId() {
        String[] parentKeys = {OAuth2Provider.NAVER.getAttributeKey()};
        return getAttribute(parentKeys, OAuth2Provider.NAVER.getIdentifierKey());
    }

    @Override
    public OAuth2Provider getProvider() { return OAuth2Provider.NAVER; }

    @Override
    public String getName() {
        String[] parentKeys = {OAuth2Provider.NAVER.getAttributeKey()};
        return getAttribute(parentKeys, "name");
    }

    @Override
    public String getEmail() {
        String[] parentKeys = {OAuth2Provider.NAVER.getAttributeKey()};
        return getAttribute(parentKeys, "email");
    }
}
