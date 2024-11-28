package com.pineone.auth.security.oauth;

import java.util.Arrays;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OAuth2Provider {

    GOOGLE("google", null, "email"),
    FACEBOOK("facebook", null, "email"),
    KAKAO("kakao", "kakao_account", "id"),
    NAVER("naver", "response", "email")

    private final String registrationId;
    // OAuth 서버로 부터 받은 JSON 데이터를 파싱하기 위한 키값
    private final String attributeKey;
    // 사용자 정보를 불러올 때 필요한 키값
    private final String identifier;

    public static OAuth2Provider from(String paramRegistrationId) {
        return Arrays.stream(values())
            .filter(oAuth2Provider -> oAuth2Provider.getRegistrationId().equalsIgnoreCase(paramRegistrationId))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown OAuth2 provider: " + paramRegistrationId));
    }
}
