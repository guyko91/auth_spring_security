package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.OtpRequireResponse;
import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;

public record LoginResult(
    UserResponse user,
    String tokenUuid,
    OtpRequireResponse otpRequire
) {
    public static LoginResult of(String tokenUuid, User user, OtpRequiredResult otpResult) {
        return new LoginResult(UserResponse.from(user), tokenUuid, OtpRequireResponse.from(otpResult));
    }

    public boolean isOtpRequired() {
        return otpRequire != null && otpRequire.otpRequired();
    }
}
