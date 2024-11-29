package com.pineone.auth.api.controller.dto;

import com.pineone.auth.api.model.User;
import com.pineone.auth.security.token.TokenDto;

public record SignupResponse(
    String accessToken,
    SignupUserResponse user
) {
    public record SignupUserResponse(Long key, String id, String name) { }

    public static SignupResponse of(TokenDto accessToken, User user) {
        return new SignupResponse(
            accessToken.token(),
            new SignupUserResponse(user.getSeq(), user.getId(), user.getName())
        );
    }

}
