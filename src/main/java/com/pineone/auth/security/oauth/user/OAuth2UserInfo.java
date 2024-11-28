package com.pineone.auth.security.oauth.user;

public interface OAuth2UserInfo {

    String getProviderId();
    String getProvider();
    String getName();
    String getEmail();

}
