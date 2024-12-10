package com.pineone.auth.security.oauth;

import com.pineone.auth.api.controller.OAuthInfoProvidable;
import com.pineone.auth.api.controller.dto.OAuthProviderViewResponse;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuthProvider implements OAuthInfoProvidable {

    private final ClientRegistrationRepository clientRegistrationRepository;

    private static final String START_WITH_OAUTH_DESC_FORMAT = "%s 시작하기";
    private static final String OAUTH_REDIRECT_URI_FORMAT = "/oauth2/authorization/%s";

    @Override
    public List<OAuthProviderViewResponse> getOAuthProviderList() {

        Iterable<ClientRegistration> clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;

        List<OAuthProviderViewResponse> resultList = new ArrayList<>();
        clientRegistrations.forEach(registration -> {
            String registrationId = registration.getRegistrationId();
            OAuth2Provider provider = OAuth2Provider.ofRegistrationId(registrationId);

            String koreanName = provider.getKoreanName();
            String loginUri = String.format(OAUTH_REDIRECT_URI_FORMAT, registrationId);
            String description = String.format(START_WITH_OAUTH_DESC_FORMAT, koreanName);

            resultList.add(
                new OAuthProviderViewResponse(registrationId, koreanName, loginUri, description)
            );
        });

        return resultList;
    }
}
