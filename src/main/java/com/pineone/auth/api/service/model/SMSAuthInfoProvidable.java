package com.pineone.auth.api.service.model;

import com.pineone.auth.api.model.TwoFactorAuthMethod;
import com.pineone.auth.api.model.User2FA;
import java.time.LocalDateTime;

public class SMSAuthInfoProvidable implements TwoFactorAuthInfoProvidable {

    private String authNumber;
    private int limitCount;
    private int attemptCount;
    private LocalDateTime createdAt;
    private LocalDateTime expiredAt;

    private SMSAuthInfoProvidable() { }

    private SMSAuthInfoProvidable(String authNumber, int limitCount, int attemptCount,
        LocalDateTime createdAt, LocalDateTime expiredAt) {
        this.authNumber = authNumber;
        this.limitCount = limitCount;
        this.attemptCount = attemptCount;
        this.createdAt = createdAt;
        this.expiredAt = expiredAt;
    }

    @Override
    public String getMethod() { return TwoFactorAuthMethod.SMS.name(); }

    @Override
    public String getTarget() { return authNumber; }

    @Override
    public int getLimitCount() { return limitCount;}

    @Override
    public long getAttemptCount() { return attemptCount; }

    @Override
    public LocalDateTime getCreatedDateTime() { return createdAt; }

    @Override
    public LocalDateTime getExpireDateTime() { return expiredAt; }

    public static SMSAuthInfoProvidable createFrom(User2FA user2FA, int verifyLimitCount,
        LocalDateTime createdAt, LocalDateTime expiredAt) {
        String authNumber = user2FA.getAuthTarget();
        return new SMSAuthInfoProvidable(authNumber, verifyLimitCount, 0, createdAt, expiredAt);
    }
}
