package com.pineone.auth.api.model;

import com.pineone.auth.api.service.BidirectionalCipher;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

@Entity
@Table(name = "tb_user_otp")
public class UserOtp extends BaseTimeEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "seq")
    private Long seq;

    @Column(name = "user_seq", nullable = false)
    private long userSeq;

    @Column(name = "secret", nullable = false)
    private String secret;

    @Column(name = "last_verified_at")
    private LocalDateTime lastVerifiedAt;

    @Column(name = "enc_key", nullable = false)
    private String encryptionKey;

    protected UserOtp() { }

    private UserOtp(long userSeq, String secret, LocalDateTime lastVerifiedAt, String encryptionKey) {
        this.userSeq = userSeq;
        this.secret = secret;
        this.lastVerifiedAt = lastVerifiedAt;
        this.encryptionKey = encryptionKey;
    }

    public static UserOtp create(long userSeq, String secret, String encryptionKey) {
        return new UserOtp(userSeq, secret, null, encryptionKey);
    }

    public boolean isExpired(int maxExpDays) {
        return lastVerifiedAt == null || lastVerifiedAt.plusDays(maxExpDays).isBefore(LocalDateTime.now());
    }

    public String getDecodedSecret(BidirectionalCipher cipher) throws Exception {
        return cipher.decrypt(encryptionKey, secret);
    }

    public void refreshDate(LocalDateTime dateTime) {
        lastVerifiedAt = dateTime;
    }

}
