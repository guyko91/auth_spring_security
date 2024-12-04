package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;
import com.pineone.auth.security.token.TokenDto;

public record RefreshResult(
    TokenDto newAccessToken,
    UserResponse user
) {
    public static RefreshResult of(TokenDto newAccessToken, User user) {
        return new RefreshResult(newAccessToken, UserResponse.from(user));
    }
}
