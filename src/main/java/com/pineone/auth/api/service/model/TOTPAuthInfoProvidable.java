package com.pineone.auth.api.service.model;

import com.pineone.auth.api.model.TwoFactorAuthMethod;
import com.pineone.auth.api.model.User2FA;
import java.time.LocalDateTime;

public class TOTPAuthInfoProvidable implements TwoFactorAuthInfoProvidable {

    private String otpQrCode;
    private LocalDateTime createdAt;
    private int attemptCount;

    private TOTPAuthInfoProvidable() { }

    private TOTPAuthInfoProvidable(String otpQrCode, LocalDateTime createdAt, int attemptCount) {
        this.otpQrCode = otpQrCode;
        this.createdAt = createdAt;
        this.attemptCount = attemptCount;
    }

    @Override
    public String getMethod() { return TwoFactorAuthMethod.TOTP.name(); }

    @Override
    public long getAttemptCount() { return attemptCount; }

    @Override
    public String getTarget() { return otpQrCode; }

    @Override
    public int getLimitCount() { return Integer.MAX_VALUE; }

    @Override
    public LocalDateTime getCreatedDateTime() { return createdAt; }

    @Override
    public LocalDateTime getExpireDateTime() {
        return LocalDateTime.of(9999, 12, 31, 23, 59, 59);
    }

    public static TOTPAuthInfoProvidable createFrom(User2FA user2FA) {
        String otpQrCode = user2FA.getAuthTarget();
        LocalDateTime createdAt = user2FA.getRegDate();
        return new TOTPAuthInfoProvidable(otpQrCode, createdAt, 0);
    }

}
