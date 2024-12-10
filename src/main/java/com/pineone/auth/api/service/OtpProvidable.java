package com.pineone.auth.api.service;

public interface OtpProvidable {
    String createSecret();
    String createOtpAuthUrl(String secretKey, String account);
    String getQRImageBase64(String googleOTPAuthURL, int height, int width);
    boolean verifyOtp(String secret, String code);
}
