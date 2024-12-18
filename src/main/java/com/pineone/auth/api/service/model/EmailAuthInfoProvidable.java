package com.pineone.auth.api.service.model;

import com.pineone.auth.api.model.TwoFactorAuthMethod;
import com.pineone.auth.api.model.User2FA;
import java.time.LocalDateTime;

public class EmailAuthInfoProvidable implements TwoFactorAuthInfoProvidable {

    private String email;
    private int limitCount;
    private int attemptCount;
    private LocalDateTime createdAt;
    private LocalDateTime expiredAt;

    private EmailAuthInfoProvidable() { }

    private EmailAuthInfoProvidable(String email, int limitCount, int attemptCount,
        LocalDateTime createdAt, LocalDateTime expiredAt) {
        this.email = email;
        this.limitCount = limitCount;
        this.attemptCount = attemptCount;
        this.createdAt = createdAt;
        this.expiredAt = expiredAt;
    }

    @Override
    public String getMethod() { return TwoFactorAuthMethod.EMAIL.name(); }

    @Override
    public String getTarget() {
        return email;
    }

    @Override
    public int getLimitCount() {
        return limitCount;
    }

    @Override
    public long getAttemptCount() { return attemptCount; }

    @Override
    public LocalDateTime getCreatedDateTime() { return createdAt; }

    @Override
    public LocalDateTime getExpireDateTime() { return expiredAt; }

    public static EmailAuthInfoProvidable createFrom(User2FA user2FA,
        int verifyLimitCount, LocalDateTime createdAt, LocalDateTime expiredAt) {
        String email = user2FA.getAuthTarget();
        return new EmailAuthInfoProvidable(email, verifyLimitCount, 0, createdAt, expiredAt);
    }
}
