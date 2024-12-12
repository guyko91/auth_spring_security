package com.pineone.auth.config;

import lombok.Data;
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

    @NestedConfigurationProperty
    private final Otp otp = new Otp();

    @Data
    public static class Auth {
        private long temporaryTokenExpMilli;
        private long accessTokenExpMilli;
        private long refreshTokenExpMilli;

        public int getCookieMaxSeconds() { return (int) refreshTokenExpMilli / 1000; }
    }

    @Data
    public static class OAuth2 {
        private String loginSuccessRedirectUri;
        private String otpRequireRedirectUri;
        private String loginSuccessTokenQueryParam;
        private String otpQrCodeQueryParam;
    }

    @Data
    public static class Otp {
        private String issuerName;
        private int verifyExpDays;
        private int qrCodeWidth;
        private int qrCodeHeight;
    }

}
