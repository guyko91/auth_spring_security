package com.pineone.auth.security.oauth.user;

import com.pineone.auth.security.oauth.OAuth2Provider;
import java.util.Map;

public class FacebookOAuth2User extends AbstractOAuth2User implements OAuth2UserInfo {

    public FacebookOAuth2User(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() { return getAttribute("id"); }

    @Override
    public OAuth2Provider getProvider() { return OAuth2Provider.FACEBOOK; }

    @Override
    public String getEmail() { return getAttribute("email"); }

    @Override
    public String getName() { return getAttribute("name"); }

}
