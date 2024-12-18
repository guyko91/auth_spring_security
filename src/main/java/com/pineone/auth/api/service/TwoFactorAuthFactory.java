package com.pineone.auth.api.service;

import com.pineone.auth.api.model.TwoFactorAuthMethod;
import com.pineone.auth.api.model.User2FA;
import com.pineone.auth.api.service.model.EmailAuthInfoProvidable;
import com.pineone.auth.api.service.model.SMSAuthInfoProvidable;
import com.pineone.auth.api.service.model.TOTPAuthInfoProvidable;
import com.pineone.auth.api.service.model.TwoFactorAuthInfoProvidable;
import com.pineone.auth.config.AuthProperties;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TwoFactorAuthFactory {

    private final AuthProperties authProperties;

    private final BidirectionalCipher cipher;
    private final OtpProvidable otpProvider;

    public User2FA createUser2FA(long userSeq) {
        TwoFactorAuthMethod method = authProperties.getTwoFactorAuth().getMethod();

        return switch (method) {

            case TOTP -> {
                String otpSecret = otpProvider.createSecret();
                String otpEncKey = cipher.generateSecretKey();

                String encodedOtpSecret = cipher.encrypt(otpSecret, otpEncKey);
                String otpQrCode = createUserOtpQRCode(userSeq, otpSecret);

                yield User2FA.createTOTP(userSeq, encodedOtpSecret, otpEncKey, otpQrCode);
            }

            case EMAIL -> {
                // TODO
                throw new IllegalArgumentException("Implement EMAIL 2FA method");
            }

            case SMS -> {
                // TODO
                throw new IllegalArgumentException("Implement SMS 2FA method");
            }

            default -> throw new IllegalArgumentException("Unsupported 2FA method: " + method);
        };
    }

    public TwoFactorAuthInfoProvidable create2FAInfo(User2FA user2FA) {
        int verifyLimitCount = authProperties.getTwoFactorAuth().getVerifyLimitCount();
        int verifyLimitSeconds = authProperties.getTwoFactorAuth().getVerifyLimitSeconds();

        LocalDateTime createdAt = LocalDateTime.now();
        LocalDateTime expireAt = createdAt.plusSeconds(verifyLimitSeconds);

        TwoFactorAuthMethod method = user2FA.getAuthMethod();
        return switch (method) {
            case TOTP -> TOTPAuthInfoProvidable.createFrom(user2FA);
            case EMAIL -> EmailAuthInfoProvidable.createFrom(user2FA, verifyLimitCount, createdAt, expireAt);
            case SMS -> SMSAuthInfoProvidable.createFrom(user2FA, verifyLimitCount, createdAt, expireAt);
            default -> throw new IllegalArgumentException("Unsupported 2FA method: " + method);
        };
    }

    private String createUserOtpQRCode(long userSeq, String decodedUserOtpSecret) {
        String account = String.valueOf(userSeq);
        int qrHeight = authProperties.getTwoFactorAuth().getTotp().getQrCodeHeight();
        int qrWidth = authProperties.getTwoFactorAuth().getTotp().getQrCodeWidth();
        String otpAuthUrl = otpProvider.createOtpAuthUrl(decodedUserOtpSecret, account);

        return otpProvider.getQRImageBase64(otpAuthUrl, qrHeight, qrWidth);
    }

}
