package com.pineone.auth.api.service;

import com.pineone.auth.api.controller.constant.ErrorCode;
import com.pineone.auth.api.controller.exception.BusinessException;
import com.pineone.auth.api.model.User2FA;
import com.pineone.auth.api.repository.User2FARepository;
import com.pineone.auth.api.repository.VerificationCodeRepository;
import com.pineone.auth.api.service.dto.TwoFactorAuthRequiredResult;
import com.pineone.auth.api.service.model.TwoFactorAuthInfoProvidable;
import com.pineone.auth.config.AuthProperties;
import java.time.LocalDateTime;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
@RequiredArgsConstructor
public class User2FAService {

    private final AuthProperties authProperties;

    private final User2FARepository repository;
    private final VerificationCodeRepository verificationCodeRepository;

    private final TwoFactorAuthFactory twoFactorAuthFactory;
    private final BidirectionalCipher cipher;
    private final OtpProvidable otpProvider;

    public TwoFactorAuthRequiredResult create2FARequireInfo(long userSeq) {
        boolean enabled = checkSystem2FAEnabled();
        if (!enabled) { return TwoFactorAuthRequiredResult.notRequired(); }

        User2FA newUser2FA = createNewUser2FA(userSeq);
        TwoFactorAuthInfoProvidable twoFactorAuthInfo = create2FAInfo(newUser2FA);

        return TwoFactorAuthRequiredResult.required(twoFactorAuthInfo);
    }

    public TwoFactorAuthRequiredResult checkUser2FARequired(long userSeq) {
        boolean enabled = checkSystem2FAEnabled();
        if (!enabled) { return TwoFactorAuthRequiredResult.notRequired(); }

        User2FA user2FA = findOrCreateUserOtp(userSeq);
        boolean user2FARequired = checkUser2FactorAuthExpired(user2FA);

        if (!user2FARequired) { return TwoFactorAuthRequiredResult.notRequired(); }

        TwoFactorAuthInfoProvidable twoFactorAuthInfo = create2FAInfo(user2FA);

        return TwoFactorAuthRequiredResult.required(twoFactorAuthInfo);
    }

    public boolean verifyUser2FACode(long userSeq, String userInputCode, LocalDateTime verifyDateTime) {
        User2FA user2FA = findUser2FABy(userSeq);

        if (user2FA.isTOTPMethod()) {
            return user2FA.checkTOTPAuthCodeMatched(userInputCode, verifyDateTime, cipher, otpProvider);
        }

        return verificationCodeRepository.verifyCode(user2FA, verifyDateTime, userInputCode);
    }

    private TwoFactorAuthInfoProvidable create2FAInfo(User2FA user2FA) {
        if (user2FA.isNotTOTPMethod()) {
            verificationCodeRepository.createVerificationCode(user2FA);
        }
        return twoFactorAuthFactory.create2FAInfo(user2FA);
    }

    private User2FA createNewUser2FA(long userSeq) {
        User2FA user2FA = twoFactorAuthFactory.createUser2FA(userSeq);
        return repository.saveAndFlush(user2FA);
    }

    private boolean checkSystem2FAEnabled() {
        return authProperties.getTwoFactorAuth().isEnabled();
    }

    private boolean checkUser2FactorAuthExpired(User2FA user2FA) {
        LocalDateTime verifyDateTime = LocalDateTime.now();
        int verifyExpDays = authProperties.getTwoFactorAuth().getVerifyExpDays();

        return user2FA.isExpired(verifyDateTime, verifyExpDays);
    }

    private User2FA findOrCreateUserOtp(long userSeq) {
        return findOptionalUserOtpBy(userSeq)
            .orElseGet(() -> createNewUser2FA(userSeq));
    }

    private User2FA findUser2FABy(long userSeq) {
        return repository.findByUserSeq(userSeq)
            .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));
    }

    private Optional<User2FA> findOptionalUserOtpBy(long userSeq) {
        return repository.findByUserSeq(userSeq);
    }
}
