package com.pineone.auth.config;

import com.pineone.auth.api.model.TwoFactorAuthMethod;
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
    private final TwoFactorAuth twoFactorAuth = new TwoFactorAuth();

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
    }

    @Data
    public static class TwoFactorAuth {
        private boolean enabled;
        private TwoFactorAuthMethod method;
        private int verifyExpDays;
        private int verifyLimitSeconds;
        private int verifyLimitCount;
        private int dailyLimitCount;

        private TOtp totp;
        private Email email;
        private Sms sms;

        @Data
        public static class TOtp {
            private String issuerName;
            private int qrCodeWidth;
            private int qrCodeHeight;
        }

        @Data
        public static class Email {
            private String protocol;
            private String host;
            private int port;
            private String userName;
            private String password;
            private String senderEmail;
        }

        @Data
        public static class Sms {
            private String senderNumber;
        }
    }

}
