package com.pineone.auth.api.controller.dto;

import com.pineone.auth.api.model.User;

public record UserResponse(
    String id,
    String name,
    String email,
    String authType
) {
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getName(), user.getEmail(), user.getProvider().name());
    }
}
