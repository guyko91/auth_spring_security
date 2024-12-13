package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;
import com.pineone.auth.security.UserPrincipal;

public record TokenRefreshResult(
    UserResponse user,
    String tokenUuid
) {
    public static TokenRefreshResult of(User user, String tokenUuid) {
        return new TokenRefreshResult(UserResponse.from(user), tokenUuid);
    }
}
