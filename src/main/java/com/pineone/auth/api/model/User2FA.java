package com.pineone.auth.api.model;

import com.pineone.auth.api.service.BidirectionalCipher;
import com.pineone.auth.api.service.OtpProvidable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.security.SecureRandom;
import java.time.LocalDateTime;

@Entity
@Table(name = "tb_user_2fa")
public class User2FA extends BaseTimeEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "seq")
    private Long seq;

    @Column(name = "user_seq", nullable = false)
    private long userSeq;

    @Enumerated(EnumType.STRING)
    @Column(name = "method", nullable = false)
    private TwoFactorAuthMethod method;

    @Column(name = "target", length = 1024)
    private String target;

    @Column(name = "secret")
    private String secret;

    @Column(name = "enc_key")
    private String encryptionKey;

    @Column(name = "last_verified_date_time")
    private LocalDateTime lastVerifiedAt;

    protected User2FA() { }

    private User2FA(Long seq, long userSeq, TwoFactorAuthMethod method, String target, String secret,
        String encryptionKey, LocalDateTime lastVerifiedAt) {
        this.seq = seq;
        this.userSeq = userSeq;
        this.method = method;
        this.target = target;
        this.secret = secret;
        this.encryptionKey = encryptionKey;
        this.lastVerifiedAt = lastVerifiedAt;
    }

    public static User2FA createTOTP(long userSeq, String secret, String encryptionKey, String otpQrCode) {
        return new User2FA(
            null,
            userSeq,
            TwoFactorAuthMethod.TOTP,
            otpQrCode,
            secret,
            encryptionKey,
            null
        );
    }

    public boolean isExpired(LocalDateTime compareDate, int maxExpDays) {
        return lastVerifiedAt == null || lastVerifiedAt.plusDays(maxExpDays).isBefore(compareDate);
    }

    public boolean isTOTPMethod() {
        return TwoFactorAuthMethod.TOTP.equals(this.method);
    }

    public boolean isNotTOTPMethod() {
        return !isTOTPMethod();
    }

    public boolean checkTOTPAuthCodeMatched(String userInput, LocalDateTime verifyDateTime,
        BidirectionalCipher cipher, OtpProvidable otpProvidable) {

        String decodedSecret = cipher.decrypt(secret, encryptionKey);
        boolean verified = otpProvidable.verifyOtp(decodedSecret, userInput);

        return processVerifyResult(verifyDateTime, verified);
    }

    public boolean processVerifyResult(LocalDateTime verifyDateTime, boolean verified) {
        if (verified) this.lastVerifiedAt = verifyDateTime;
        return verified;
    }

    public long getUserSeq() { return userSeq; }

    public TwoFactorAuthMethod getAuthMethod() { return method; }

    public String getAuthTarget() { return target; }

    public String generateRandomSixDigitCode() {
        SecureRandom random = new SecureRandom();
        int code = random.nextInt(900000) + 100000; // 100000 ~ 999999 사이
        return String.valueOf(code);
    }

}
