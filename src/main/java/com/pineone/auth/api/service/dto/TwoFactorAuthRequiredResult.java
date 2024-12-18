package com.pineone.auth.api.service.dto;

import com.pineone.auth.api.service.model.TwoFactorAuthInfoProvidable;

public record TwoFactorAuthRequiredResult(
    boolean twoFactorAuthRequired,
    TwoFactorAuthInfoProvidable twoFactorAuthInfoProvidable
) {

    public static TwoFactorAuthRequiredResult notRequired() {
        return new TwoFactorAuthRequiredResult(false, null);
    }

    public static TwoFactorAuthRequiredResult required(TwoFactorAuthInfoProvidable authInfo) {
        return new TwoFactorAuthRequiredResult(true, authInfo);
    }

}
