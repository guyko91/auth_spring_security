package com.pineone.auth.config;

import java.util.ArrayList;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "prop")
public class AuthProperties {

    @NestedConfigurationProperty
    private final Auth auth = new Auth();

    @NestedConfigurationProperty
    private final OAuth2 oauth2 = new OAuth2();

    @Data
    public static class Auth {
        private long accessTokenExpMilli;
        private long refreshTokenExpMilli;

        public int getCookieMaxSeconds() { return (int) refreshTokenExpMilli / 1000; }
    }

    @Data
    public static class OAuth2 {
        private String loginSuccessRedirectUri;
        private String loginSuccessTokenQueryParam;
        private List<String> authorizedRedirectUris = new ArrayList<>();
    }

}
