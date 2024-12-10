package com.pineone.auth.api.controller.dto;

public record AuthResponse(
    String tokenKey,
    OtpRequireResponse otpRequire
) {
    public static AuthResponse otpNotRequired(String tokenKey) {
        return new AuthResponse(tokenKey, null);
    }

    public static AuthResponse otpRequired(String tokenKey, OtpRequireResponse otpRequire) {
        return new AuthResponse(tokenKey, otpRequire);
    }
}
