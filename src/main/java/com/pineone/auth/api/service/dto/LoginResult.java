package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.TwoFactorAuthRequireResponse;
import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;

public record LoginResult(
    UserResponse user,
    String tokenUuid,
    TwoFactorAuthRequireResponse otpRequire
) {
    public static LoginResult of(String tokenUuid, User user, TwoFactorAuthRequiredResult otpResult) {
        return new LoginResult(UserResponse.from(user), tokenUuid, TwoFactorAuthRequireResponse.from(otpResult));
    }

    public boolean isOtpRequired() {
        return otpRequire != null && otpRequire.authRequired();
    }
}
