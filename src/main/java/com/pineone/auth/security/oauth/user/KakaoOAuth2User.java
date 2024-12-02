package com.pineone.auth.security.oauth.user;

import com.pineone.auth.security.oauth.OAuth2Provider;
import java.util.Map;

public class KakaoOAuth2User extends AbstractOAuth2User implements OAuth2UserInfo {

    public KakaoOAuth2User(Map<String, Object> attributes) { super(attributes); }

    @Override
    public String getId() { return getAttribute(OAuth2Provider.KAKAO.getIdentifierKey()); }

    @Override
    public OAuth2Provider getProvider() { return OAuth2Provider.KAKAO; }

    @Override
    public String getName() { return getAttribute("profile_nickname"); }

    @Override
    public String getEmail() { return getAttribute("email"); }
}
