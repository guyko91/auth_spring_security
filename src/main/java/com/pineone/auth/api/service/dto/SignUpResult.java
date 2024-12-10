package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.OtpRequireResponse;
import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;

public record SignUpResult(
    UserResponse user,
    String tokenUuid,
    OtpRequireResponse otpRequire
) {
    public static SignUpResult of(User user, String tokenUuid, OtpRequiredResult otpRequiredResult) {
        return new SignUpResult(UserResponse.from(user), tokenUuid, OtpRequireResponse.from(otpRequiredResult));
    }
}
