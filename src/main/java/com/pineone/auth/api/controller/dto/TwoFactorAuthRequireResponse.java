package com.pineone.auth.api.controller.dto;

import com.pineone.auth.api.service.dto.TwoFactorAuthRequiredResult;
import com.pineone.auth.api.service.model.TwoFactorAuthInfoProvidable;
import java.time.LocalDateTime;

public record TwoFactorAuthRequireResponse(
    boolean authRequired,
    TwoFactorAuthInfo authInfo
) {

    public static TwoFactorAuthRequireResponse from(TwoFactorAuthRequiredResult result) {
        if (!result.twoFactorAuthRequired()) { return otpNotRequired(); }
        return otpRequired(result.twoFactorAuthInfoProvidable());
    }

    public static TwoFactorAuthRequireResponse otpRequired(TwoFactorAuthInfoProvidable authInfo) {
        return new TwoFactorAuthRequireResponse(true, TwoFactorAuthInfo.from(authInfo));
    }

    public static TwoFactorAuthRequireResponse otpNotRequired() {
        return new TwoFactorAuthRequireResponse(false, null);
    }

    public record TwoFactorAuthInfo(
        String method,
        String target,
        int limitCount,
        long attemptCount,
        LocalDateTime createdDateTime,
        LocalDateTime expireDateTime
    ) {
        public static TwoFactorAuthInfo from(TwoFactorAuthInfoProvidable authInfo) {
            return new TwoFactorAuthInfo(
                authInfo.getMethod(),
                authInfo.getTarget(),
                authInfo.getLimitCount(),
                authInfo.getAttemptCount(),
                authInfo.getCreatedDateTime(),
                authInfo.getExpireDateTime()
            );
        }
    }
}
