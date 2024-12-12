package com.pineone.auth.api.service.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OTPCipherOperation {
    ENCRYPT("암호화", "OTP Secret 암호화에 실패했습니다."),
    DECRYPT("복호화", "OTP Secret 복호화에 실패했습니다.");

    private final String description;
    private final String errorMessage;
}
