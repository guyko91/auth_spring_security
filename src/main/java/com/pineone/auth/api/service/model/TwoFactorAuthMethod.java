package com.pineone.auth.api.service.model;

import java.time.LocalDateTime;

public abstract class TwoFactorAuthMethod {

    protected final int limitCount;
    protected final LocalDateTime createdAt;
    protected final LocalDateTime expiredAt;

    protected TwoFactorAuthMethod(int limitCount, LocalDateTime createdAt, LocalDateTime expiredAt) {
        this.limitCount = limitCount;
        this.createdAt = createdAt;
        this.expiredAt = expiredAt;
    }
}
