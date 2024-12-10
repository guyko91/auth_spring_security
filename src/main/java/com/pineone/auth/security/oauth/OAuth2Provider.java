package com.pineone.auth.security.oauth;

import com.pineone.auth.api.model.AuthProvider;
import java.util.Arrays;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OAuth2Provider {

    GOOGLE("구글", null, "sub"),
    FACEBOOK("페이스북", null, "id"),
    KAKAO("카카오", "kakao_account", "id"),
    NAVER("네이버", "response", "id")
    ;

    private final String koreanName;
    // OAuth 서버로 부터 받은 JSON 데이터 중 사용자 정보를 파싱하기 위한 키값 (null 인 경우 1depth)
    private final String attributeKey;
    // 사용자 정보를 불러올 때 필요한 키값
    private final String identifierKey;

    public AuthProvider toAuthProvider() {
        return AuthProvider.valueOf(this.name());
    }

    public static OAuth2Provider ofRegistrationId(String registrationId) {
        return Arrays.stream(values())
            .filter(provider -> provider.name().equalsIgnoreCase(registrationId))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("등록되지 않은 OAuth2Provider 입니다."));
    }

}
