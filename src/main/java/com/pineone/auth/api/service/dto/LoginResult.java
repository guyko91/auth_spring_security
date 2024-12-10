package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.OtpRequireResponse;
import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;
import com.pineone.auth.security.token.TokenPairDto;

public record LoginResult(
    UserResponse user,
    TokenPairDto tokenPair,
    OtpRequireResponse otpRequire
) {
    public static LoginResult of(TokenPairDto tokenPair, User user, OtpRequiredResult otpResult) {
        return new LoginResult(UserResponse.from(user), tokenPair, OtpRequireResponse.from(otpResult));
    }

    public boolean isOtpRequired() {
        return otpRequire != null && otpRequire.otpRequired();
    }
}
