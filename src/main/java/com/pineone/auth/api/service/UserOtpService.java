package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.UserOtp;
import com.pineone.auth.api.repository.UserOtpRepository;
import com.pineone.auth.api.service.dto.OtpRequiredResult;
import com.pineone.auth.api.service.model.OTPCipherOperation;
import com.pineone.auth.config.AuthProperties;
import java.time.LocalDateTime;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
@RequiredArgsConstructor
public class UserOtpService {

    private final UserOtpRepository repository;
    private final BidirectionalCipher cipher;
    private final OtpProvidable otpProvider;

    private final AuthProperties authProperties;

    public OtpRequiredResult createEncodedOtpSecret(long userSeq) {
        UserOtp newUserOtp = createNewUserOtp(userSeq);
        String otpSecret = getUserOtpDecodedSecret(newUserOtp);
        String otpQrCode = createUserOtpQRCode(userSeq, otpSecret);

        return OtpRequiredResult.otpRequired(otpQrCode);
    }

    public OtpRequiredResult checkUserOtpVerifyRequired(long userSeq) {
        UserOtp userOtp = findOrCreateUserOtp(userSeq);
        return checkUserOtpExpiration(userSeq, userOtp);
    }

    private OtpRequiredResult checkUserOtpExpiration(long userSeq, UserOtp userOtp) {
        int otpVerifyExpDays = authProperties.getOtp().getVerifyExpDays();
        return userOtp.isExpired(otpVerifyExpDays)
            ? OtpRequiredResult.otpRequired(createUserOtpQRCode(userSeq, getUserOtpDecodedSecret(userOtp)))
            : OtpRequiredResult.otpNotRequired();
    }

    private UserOtp createNewUserOtp(long userSeq) {
        String otpSecret = otpProvider.createSecret();
        String otpEncKey = cipher.generateSecretKey();
        String encodedOtpSecret = handleCipherOperation(OTPCipherOperation.ENCRYPT, otpSecret, otpEncKey);

        return createNewUserOtp(userSeq, encodedOtpSecret, otpEncKey);
    }

    private String getUserOtpDecodedSecret(UserOtp userOtp) {
        String encodedSecret = userOtp.getEncodedSecret();
        String otpEncKey = userOtp.getEncKey();
        return handleCipherOperation(OTPCipherOperation.DECRYPT, encodedSecret, otpEncKey);
    }

    private String createUserOtpQRCode(long userSeq, String decodedUserOtpSecret) {
        String account = String.valueOf(userSeq);
        int qrHeight = authProperties.getOtp().getQrCodeHeight();
        int qrWidth = authProperties.getOtp().getQrCodeWidth();
        String otpAuthUrl = otpProvider.createOtpAuthUrl(decodedUserOtpSecret, account);

        return otpProvider.getQRImageBase64(otpAuthUrl, qrHeight, qrWidth);
    }

    private UserOtp findOrCreateUserOtp(long userSeq) {
        return findOptionalUserOtpBy(userSeq)
            .orElseGet(() -> createNewUserOtp(userSeq));
    }

    public boolean verifyUserOtpCode(long userSeq, String code, LocalDateTime verifyDateTime) {
        UserOtp userOtp = findUserOtpBy(userSeq);
        String decodedSecret = getUserOtpDecodedSecret(userOtp);

        boolean verified = otpProvider.verifyOtp(decodedSecret, code);

        if (verified) { userOtp.refreshDate(verifyDateTime); }

        return verified;
    }

    private String handleCipherOperation(OTPCipherOperation operation, String target, String secret) {
        try {
            return operation == OTPCipherOperation.ENCRYPT
                ? cipher.encrypt(secret, target)
                : cipher.decrypt(secret, target);
        } catch (Exception e) {
            throw new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR, operation.getErrorMessage());
        }
    }

    private UserOtp createNewUserOtp(long userSeq, String encodedSecret, String otpEncKey) {
        UserOtp newUserOtp = UserOtp.create(userSeq, encodedSecret, otpEncKey);
        return repository.saveAndFlush(newUserOtp);
    }

    private UserOtp findUserOtpBy(long userSeq) {
        return repository.findByUserSeq(userSeq)
            .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));
    }

    private Optional<UserOtp> findOptionalUserOtpBy(long userSeq) {
        return repository.findByUserSeq(userSeq);
    }
}
