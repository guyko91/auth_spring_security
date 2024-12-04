package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;
import com.pineone.auth.security.token.TokenPairDto;

public record LoginResult(
    TokenPairDto tokenPair,
    UserResponse user
) {
    public static LoginResult of(TokenPairDto tokenPair, User user) {
        return new LoginResult(tokenPair, UserResponse.from(user));
    }
}
