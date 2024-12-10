package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.controller.dto.OtpRequireResponse;
import com.pineone.auth.api.controller.dto.UserResponse;
import com.pineone.auth.api.model.User;
import com.pineone.auth.security.token.TokenPairDto;

public record SignUpResult(
    TokenPairDto tokenPair,
    UserResponse user,
    OtpRequireResponse otpRequire
) {
    public static SignUpResult of(TokenPairDto tokenPair, User user, OtpRequiredResult otpRequiredResult) {
        return new SignUpResult(tokenPair, UserResponse.from(user), OtpRequireResponse.from(otpRequiredResult));
    }
}
