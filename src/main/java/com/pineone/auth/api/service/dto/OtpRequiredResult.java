package com.pineone.auth.api.service.dto;

public record OtpRequiredResult(
    boolean otpRequired,
    String otpQrCode
) {

    public static OtpRequiredResult otpNotRequired() {
        return new OtpRequiredResult(false, null);
    }

    public static OtpRequiredResult otpRequired(String otpQrCode) {
        return new OtpRequiredResult(true, otpQrCode);
    }

}
