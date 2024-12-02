package com.pineone.auth.security.oauth.user;

import com.pineone.auth.security.oauth.OAuth2Provider;
import java.util.Map;

public class NaverOAuth2User extends AbstractOAuth2User implements OAuth2UserInfo {

    public NaverOAuth2User(Map<String, Object> attributes) { super(attributes); }

    @Override
    public String getId() { return getAttribute(OAuth2Provider.NAVER.getIdentifierKey()); }

    @Override
    public OAuth2Provider getProvider() { return OAuth2Provider.NAVER; }

    @Override
    public String getName() {
        return getAttribute("name");
    }

    @Override
    public String getEmail() {
        return getAttribute("email");
    }
}
