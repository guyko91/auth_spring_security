package com.pineone.auth.api.controller.dto;

import com.pineone.auth.api.service.dto.OtpRequiredResult;

public record OtpRequireResponse(
    boolean otpRequired,
    String otpQrCode
) {

    public static OtpRequireResponse from(OtpRequiredResult result) {
        return new OtpRequireResponse(result.otpRequired(), result.otpQrCode());
    }

    public static OtpRequireResponse otpNotRequired() {
        return new OtpRequireResponse(false, null);
    }

}
