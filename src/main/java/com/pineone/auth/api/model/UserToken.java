package com.pineone.auth.api.model;

import jakarta.persistence.Id;
import java.time.LocalDateTime;
import org.springframework.data.redis.core.RedisHash;

@RedisHash("user_tokens")
public class UserToken {

    @Id
    private Long id;
    private Long userSeq;
    private String refreshToken;
    private LocalDateTime expiration;

    protected UserToken() {}

    private UserToken(Long id, Long userSeq, String refreshToken,
        LocalDateTime expiration) {
        this.id = id;
        this.userSeq = userSeq;
        this.refreshToken = refreshToken;
        this.expiration = expiration;
    }

    public static UserToken create(Long userSeq, String refreshToken, LocalDateTime expiration) {
        return new UserToken(null, userSeq, refreshToken, expiration);
    }

    public void updateRefreshToken(String token, LocalDateTime localDateTime) {
        this.refreshToken = token;
        this.expiration = localDateTime;
    }
}
