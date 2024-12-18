package com.pineone.auth.api.controller.dto;

public record AuthResponse(
    String tokenKey,
    TwoFactorAuthRequireResponse authRequire
) {
    public static AuthResponse otpNotRequired(String tokenKey) {
        return new AuthResponse(tokenKey, TwoFactorAuthRequireResponse.otpNotRequired());
    }

    public static AuthResponse otpRequired(String tokenKey, TwoFactorAuthRequireResponse otpRequire) {
        return new AuthResponse(tokenKey, otpRequire);
    }
}
