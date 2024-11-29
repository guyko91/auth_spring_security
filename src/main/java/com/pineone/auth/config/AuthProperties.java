package com.pineone.auth.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AuthProperties {

    private final Auth auth = new Auth();
    private final OAuth2 oauth2 = new OAuth2();

    @Data
    public static final class Auth {
        private String tokenSecret;
        private long accessTokenExpMilli;
        private long refreshTokenExpMilli;
    }

    @Data
    public static final class OAuth2 {
        private List<String> authorizedRedirectUris = new ArrayList<>();
    }

}
