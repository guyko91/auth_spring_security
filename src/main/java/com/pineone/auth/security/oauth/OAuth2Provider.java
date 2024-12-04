package com.pineone.auth.security.oauth;

import com.pineone.auth.api.model.AuthProvider;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OAuth2Provider {

    GOOGLE(null, "sub"),
    FACEBOOK(null, "id"),
    KAKAO("kakao_account", "id"),
//    NAVER("response", "id")
    ;

    // OAuth 서버로 부터 받은 JSON 데이터 중 사용자 정보를 파싱하기 위한 키값 (null 인 경우 1depth)
    private final String attributeKey;
    // 사용자 정보를 불러올 때 필요한 키값
    private final String identifierKey;

    public AuthProvider toAuthProvider() {
        return AuthProvider.valueOf(this.name());
    }
}
