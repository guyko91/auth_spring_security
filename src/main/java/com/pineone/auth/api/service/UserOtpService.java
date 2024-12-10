package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.UserOtp;
import com.pineone.auth.api.repository.UserOtpRepository;
import com.pineone.auth.api.service.dto.OtpRequiredResult;
import com.pineone.auth.config.AuthProperties;
import com.pineone.auth.security.otp.OtpProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
@RequiredArgsConstructor
public class UserOtpService {

    private final UserOtpRepository repository;
    private final BidirectionalCipher cipher;

    private final OtpProvider otpProvider;
    private final AuthProperties authProperties;

    public OtpRequiredResult createEncodedOtpSecret(long userSeq) {
        String otpSecret = otpProvider.createSecret();
        String otpEncKey = cipher.generateSecretKey();

        String encodedOtpSecret = encodeOtpSecret(otpEncKey, otpSecret);
        UserOtp userOtp = UserOtp.create(userSeq, encodedOtpSecret, otpEncKey);
        repository.saveAndFlush(userOtp);

        String otpQrCode = createUserOtpQRCode(userSeq, userOtp);

        return OtpRequiredResult.otpRequired(otpQrCode);
    }

    public OtpRequiredResult isUserOtpVerifyRequired(long userSeq) {
        UserOtp userOtp = findUserOtpBy(userSeq);

        int otpVerifyExpDays = authProperties.getOtp().getVerifyExpDays();
        boolean expired = userOtp.isExpired(otpVerifyExpDays);

        if (expired) {
            String otpQrCode = createUserOtpQRCode(userSeq, userOtp);
            return OtpRequiredResult.otpRequired(otpQrCode);
        }

        return OtpRequiredResult.otpNotRequired();
    }

    public boolean isUserOtpCodeMatched(long userSeq, String code) {
        UserOtp userOtp = findUserOtpBy(userSeq);
        String decodedSecret = decodeUserOtpSecret(userOtp);
        return otpProvider.verifyOtp(decodedSecret, code);
    }

    private String decodeUserOtpSecret(UserOtp userOtp) {
        try {
            return userOtp.getDecodedSecret(cipher);
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, "OTP Secret 복호화에 실패했습니다.");
        }
    }

    private String encodeOtpSecret(String key, String otpSecret) {
        try {
            return cipher.encrypt(key, otpSecret);
        }catch (Exception e) {
            throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, "OTP Secret 암호화에 실패했습니다.");
        }
    }

    private UserOtp findUserOtpBy(long userSeq) {
        return repository.findByUserSeq(userSeq)
            .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));
    }

    private String createUserOtpQRCode(long userSeq, UserOtp userOtp) {
        String account = String.valueOf(userSeq);
        String otpAuthUrl = otpProvider.createOtpAuthUrl(decodeUserOtpSecret(userOtp), account);
        return otpProvider.getQRImageBase64(otpAuthUrl, 200, 200);
    }
}
