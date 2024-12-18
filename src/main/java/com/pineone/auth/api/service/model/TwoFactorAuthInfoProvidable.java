package com.pineone.auth.api.service.model;

import java.time.LocalDateTime;

public interface TwoFactorAuthInfoProvidable {

    String getMethod();
    String getTarget();
    int getLimitCount();
    long getAttemptCount();
    LocalDateTime getCreatedDateTime();
    LocalDateTime getExpireDateTime();
}
