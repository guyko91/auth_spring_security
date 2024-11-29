package com.pineone.auth.security.oauth.user;

import com.pineone.auth.security.oauth.OAuth2Provider;
import java.util.Map;

public interface OAuth2UserInfo {

    OAuth2Provider getProvider();
    Map<String, Object> getAttributes();
    String getId();
    String getName();
    String getEmail();

}
