package com.pineone.auth.api.controller;

import com.pineone.auth.api.controller.dto.OAuthProviderViewResponse;
import java.util.List;

public interface OAuthInfoProvidable {

    List<OAuthProviderViewResponse> getOAuthProviderList();

}
