package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.TwoFactorAuthRequireResponse;
import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;

public record SignUpResult(
    UserResponse user,
    String tokenUuid,
    TwoFactorAuthRequireResponse otpRequire
) {
    public static SignUpResult of(User user, String tokenUuid, TwoFactorAuthRequiredResult twoFactorAuthRequiredResult) {
        return new SignUpResult(UserResponse.from(user), tokenUuid, TwoFactorAuthRequireResponse.from(
            twoFactorAuthRequiredResult));
    }
}
