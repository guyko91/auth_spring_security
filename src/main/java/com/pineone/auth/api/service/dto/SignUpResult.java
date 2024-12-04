package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;
import com.pineone.auth.security.token.TokenPairDto;

public record SignUpResult(
    TokenPairDto tokenPair,
    UserResponse user
) {
    public static SignUpResult of(TokenPairDto tokenPair, User user) {
        return new SignUpResult(tokenPair, UserResponse.from(user));
    }
}
